"""
Flask application and REST API server for Bank ATM Dispute, Fraud & e-KYC Customer Vault.
Compliant with Indonesian UU PDP No. 27/2022 and POJK No. 22/2023.

Enforces zero-plaintext-at-rest:
- Unwrapped DEK bundles exist exclusively in ephemeral RAM (ACTIVE_KEY_SESSIONS).
- All personal (Tier 1) and financial (Tier 2) fields are encrypted with AES, DES, and RC4.
- All binary evidence files (ID scans, bank statements, CCTV videos) are encrypted and stored in vault/.
- Cryptographic integrity (HMAC-SHA256) is verified before every decryption.
"""

from __future__ import annotations

import functools
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    session,
)

# Root project directory
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.database import (
    create_user,
    get_user_by_email,
    get_user_by_username,
    init_db,
)
from app.crypto_engine import (
    generate_dek_bundle,
    hash_password,
    unwrap_dek_bundle,
    verify_password,
    wrap_dek_bundle,
)


# =====================================================================
# In-Memory Active Key Session Store (Zero Plaintext Keys at Rest)
# =====================================================================
# Map: session_token -> {"user_id": str, "username": str, "email": str, "dek_bundle": dict}
ACTIVE_KEY_SESSIONS: Dict[str, Dict[str, Any]] = {}


def get_current_session() -> Optional[Dict[str, Any]]:
    """Retrieve the active authenticated session from Flask session or Authorization header."""
    token = session.get("token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()

    if token and token in ACTIVE_KEY_SESSIONS:
        return ACTIVE_KEY_SESSIONS[token]
    return None


def login_required(view_fn):
    """Decorator requiring an active authenticated customer session."""
    @functools.wraps(view_fn)
    def wrapped(*args, **kwargs):
        sess = get_current_session()
        if not sess:
            return jsonify({"error": "Authentication required. Please sign in."}), 401
        return view_fn(*args, **kwargs)
    return wrapped


# =====================================================================
# Flask Application Factory
# =====================================================================

def create_app() -> Flask:
    """Creates and configures the Flask application."""
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "app" / "templates"),
        static_folder=str(BASE_DIR / "app" / "static")
    )
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "bank_vault_dev_secret_key_oct2026_unwrapped_in_ram")
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB maximum upload

    # Ensure DB tables & directories exist
    init_db()

    # -----------------------------------------------------------------
    # Web View Routes
    # -----------------------------------------------------------------
    @app.route("/")
    def index():
        """Render the main banking dispute and vault web portal."""
        return render_template("index.html")

    # -----------------------------------------------------------------
    # Authentication API Routes
    # -----------------------------------------------------------------
    @app.route("/api/auth/register", methods=["POST"])
    @app.route("/api/register", methods=["POST"])
    def api_register():
        """
        Registers a new bank customer.
        Generates individual DEK bundle, wraps it with password-derived KEK,
        stores the wrapped bundle in SQLite, and logs in the customer.
        """
        data = request.get_json(silent=True) or request.form.to_dict()
        username = (data.get("username") or "").strip()
        email = (data.get("email") or "").strip()
        password = data.get("password") or ""
        full_name = (data.get("full_name") or username).strip()

        if not username:
            return jsonify({"error": "Username is required"}), 400
        if not password or len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400
        if not email:
            email = f"{username.lower()}@banknusantara.co.id"

        # Check existing user
        if get_user_by_username(username):
            return jsonify({"error": "Username already registered"}), 400
        if get_user_by_email(email):
            return jsonify({"error": "Email address already registered"}), 400

        # Cryptographic key generation & wrapping
        dek_bundle = generate_dek_bundle()
        wrapped = wrap_dek_bundle(dek_bundle, password)
        pwd_hash_info = hash_password(password)

        user_id = str(uuid.uuid4())
        created_user = create_user(
            username=username,
            email=email,
            auth_salt=pwd_hash_info["salt_hex"],
            password_hash=pwd_hash_info["hash_hex"],
            kdf_salt=wrapped["kdf_salt_hex"],
            wrapped_dek_bundle=wrapped["wrapped_bundle_json"],
            user_id=user_id
        )

        # Establish RAM-only key session
        session_token = str(uuid.uuid4())
        ACTIVE_KEY_SESSIONS[session_token] = {
            "user_id": created_user["id"],
            "username": created_user["username"],
            "email": created_user["email"],
            "full_name": full_name,
            "dek_bundle": dek_bundle
        }
        session["token"] = session_token

        return jsonify({
            "message": "Customer registered successfully",
            "user": {
                "id": created_user["id"],
                "username": created_user["username"],
                "email": created_user["email"],
                "full_name": full_name
            },
            "token": session_token
        }), 201

    @app.route("/api/auth/login", methods=["POST"])
    @app.route("/api/login", methods=["POST"])
    def api_login():
        """
        Authenticates bank customer, verifies password hash,
        unwraps DEK bundle in ephemeral RAM, and sets session.
        """
        data = request.get_json(silent=True) or request.form.to_dict()
        login_id = (data.get("username") or data.get("email") or "").strip()
        password = data.get("password") or ""

        if not login_id or not password:
            return jsonify({"error": "Username and password required"}), 400

        user = get_user_by_username(login_id) or get_user_by_email(login_id)
        if not user:
            return jsonify({"error": "Invalid username or password"}), 401

        if not verify_password(password, user["auth_salt"], user["password_hash"]):
            return jsonify({"error": "Invalid username or password"}), 401

        # Unwrap customer DEKs into memory
        try:
            dek_bundle = unwrap_dek_bundle(user["wrapped_dek_bundle"], password, user["kdf_salt"])
        except ValueError:
            return jsonify({"error": "Key unwrapping failed. Corrupted key bundle."}), 500

        session_token = str(uuid.uuid4())
        ACTIVE_KEY_SESSIONS[session_token] = {
            "user_id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["username"],
            "dek_bundle": dek_bundle
        }
        session["token"] = session_token

        return jsonify({
            "message": "Authenticated successfully",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"]
            },
            "token": session_token
        }), 200

    @app.route("/api/auth/logout", methods=["POST"])
    @app.route("/api/logout", methods=["POST"])
    def api_logout():
        """Clears active customer session and purges unwrapped DEKs from RAM."""
        token = session.get("token")
        if token and token in ACTIVE_KEY_SESSIONS:
            del ACTIVE_KEY_SESSIONS[token]
        session.clear()
        return jsonify({"message": "Logged out successfully"}), 200

    @app.route("/api/auth/me", methods=["GET"])
    @app.route("/api/me", methods=["GET"])
    def api_me():
        """Returns the current customer's authentication status."""
        sess = get_current_session()
        if not sess:
            return jsonify({"authenticated": False}), 200
        return jsonify({
            "authenticated": True,
            "user": {
                "id": sess["user_id"],
                "username": sess["username"],
                "email": sess["email"],
                "full_name": sess.get("full_name", sess["username"])
            }
        }), 200
    return app


# Create default application instance
app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
