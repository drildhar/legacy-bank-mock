"""
Database module for the Bank ATM Dispute, Fraud & e-KYC Customer Vault.
Manages SQLite storage at <project_root>/storage/bank_vault.db and flat-file
vault directories for raw ciphertext media blobs at:
    <project_root>/storage/vault/{aes, des, rc4}
"""

import os
import sqlite3
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Any

# Root project directories
BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = BASE_DIR / "storage"
DB_PATH = STORAGE_DIR / "bank_vault.db"
VAULT_DIR = STORAGE_DIR / "vault"
VAULT_AES = VAULT_DIR / "aes"
VAULT_DES = VAULT_DIR / "des"
VAULT_RC4 = VAULT_DIR / "rc4"


def ensure_storage_dirs() -> None:
    """Ensure that the SQLite storage and cipher-partitioned vault directories exist."""
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    VAULT_AES.mkdir(parents=True, exist_ok=True)
    VAULT_DES.mkdir(parents=True, exist_ok=True)
    VAULT_RC4.mkdir(parents=True, exist_ok=True)


def get_db_connection() -> sqlite3.Connection:
    """
    Open and return a configured connection to the SQLite database.
    Configures Row factory, WAL mode, and foreign keys.
    """
    ensure_storage_dirs()
    conn = sqlite3.connect(str(DB_PATH), timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def init_db() -> None:
    """
    Initialize SQLite database schema according to ADR-002 Data Classification
    (Tier 0 Unencrypted Routing, Tier 1 General Personal Data, Tier 2 Specific Financial Data).
    """
    ensure_storage_dirs()
    conn = get_db_connection()
    try:
        with conn:
            # 1. Users Table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                auth_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                kdf_salt TEXT NOT NULL,
                wrapped_dek_bundle TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """)

            # 2. Dispute Cases Table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS dispute_cases (
                -- Tier 0 (Unencrypted Routing Metadata - Non-identifying)
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                case_reference TEXT NOT NULL,
                atm_terminal_id TEXT NOT NULL,
                created_at TEXT NOT NULL,

                -- Tier 1 (General Personal Data - UU PDP Art. 4(3) / GDPR Art. 4(1), Encrypted JSON with AES, DES, RC4)
                enc_full_name TEXT NOT NULL,
                enc_nik TEXT NOT NULL,
                enc_phone TEXT NOT NULL,
                enc_mothers_maiden_name TEXT NOT NULL,

                -- Tier 2 (Specific Personal Financial Data - UU PDP Art. 4(2)(f) / GDPR Art. 9, Encrypted JSON with AES, DES, RC4)
                enc_card_pan TEXT NOT NULL,
                enc_account_number TEXT NOT NULL,
                enc_atm_stan TEXT NOT NULL,
                enc_dispute_amount TEXT NOT NULL,
                enc_incident_narrative TEXT NOT NULL,
                field_telemetry_json TEXT NOT NULL,

                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """)

            conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_dispute_cases_user_id ON dispute_cases(user_id);
            """)
            conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_dispute_cases_created ON dispute_cases(created_at);
            """)

            # 3. Case Attachments Table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS case_attachments (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                category TEXT NOT NULL, -- 'id_scan', 'office_doc', 'video_evidence'
                enc_original_filename TEXT NOT NULL,
                enc_mime_type TEXT NOT NULL,
                plaintext_size INTEGER NOT NULL,
                plaintext_sha256 TEXT NOT NULL,
                aes_meta_json TEXT NOT NULL,
                des_meta_json TEXT NOT NULL,
                rc4_meta_json TEXT NOT NULL,
                created_at TEXT NOT NULL,

                FOREIGN KEY (case_id) REFERENCES dispute_cases(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """)

            conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_attachments_case_id ON case_attachments(case_id);
            """)
            conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_attachments_user_id ON case_attachments(user_id);
            """)

            # 4. Benchmark Runs Table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS benchmark_runs (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                results_json TEXT NOT NULL
            );
            """)
    finally:
        conn.close()


# ---------------------------------------------------------
# Vault Media Path Resolvers
# ---------------------------------------------------------
def get_vault_path(cipher: str, attachment_id: str) -> Path:
    """Return the absolute file path for a ciphertext attachment in the vault."""
    cipher_lower = cipher.lower()
    if cipher_lower in ("aes", "aes-256", "aes-256-cbc"):
        return VAULT_AES / f"{attachment_id}.enc"
    elif cipher_lower in ("des", "des-cbc"):
        return VAULT_DES / f"{attachment_id}.enc"
    elif cipher_lower in ("rc4", "rc4-stream"):
        return VAULT_RC4 / f"{attachment_id}.enc"
    else:
        raise ValueError(f"Unknown vault cipher: {cipher}")


# ---------------------------------------------------------
# User Operations
# ---------------------------------------------------------
def create_user(
    username: str,
    email: str,
    auth_salt: str,
    password_hash: str,
    kdf_salt: str,
    wrapped_dek_bundle: str,
    user_id: Optional[str] = None
) -> Dict[str, Any]:
    """Insert a new user record."""
    uid = user_id or str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO users (id, username, email, auth_salt, password_hash, kdf_salt, wrapped_dek_bundle, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (uid, username, email, auth_salt, password_hash, kdf_salt, wrapped_dek_bundle, now_iso)
            )
        return {
            "id": uid,
            "username": username,
            "email": email,
            "auth_salt": auth_salt,
            "password_hash": password_hash,
            "kdf_salt": kdf_salt,
            "wrapped_dek_bundle": wrapped_dek_bundle,
            "created_at": now_iso
        }
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Fetch user by username."""
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Fetch user by email."""
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Fetch user by user ID."""
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# ---------------------------------------------------------
# Dispute Case Operations
# ---------------------------------------------------------
def create_dispute_case(case_data: Dict[str, Any]) -> Dict[str, Any]:
    """Insert a complete dispute case record into SQLite."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO dispute_cases (
                    id, user_id, case_reference, atm_terminal_id, created_at,
                    enc_full_name, enc_nik, enc_phone, enc_mothers_maiden_name,
                    enc_card_pan, enc_account_number, enc_atm_stan, enc_dispute_amount,
                    enc_incident_narrative, field_telemetry_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_data["id"],
                    case_data["user_id"],
                    case_data["case_reference"],
                    case_data["atm_terminal_id"],
                    case_data["created_at"],
                    case_data["enc_full_name"],
                    case_data["enc_nik"],
                    case_data["enc_phone"],
                    case_data["enc_mothers_maiden_name"],
                    case_data["enc_card_pan"],
                    case_data["enc_account_number"],
                    case_data["enc_atm_stan"],
                    case_data["enc_dispute_amount"],
                    case_data["enc_incident_narrative"],
                    case_data["field_telemetry_json"]
                )
            )
        return case_data
    finally:
        conn.close()


def get_cases_by_user(user_id: str) -> List[Dict[str, Any]]:
    """Fetch all dispute cases belonging to a specific user (Tier 0 index lookup)."""
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "SELECT * FROM dispute_cases WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,)
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_case_by_id(case_id: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetch a dispute case by ID, optionally verifying ownership."""
    conn = get_db_connection()
    try:
        if user_id:
            cur = conn.execute(
                "SELECT * FROM dispute_cases WHERE id = ? AND user_id = ?",
                (case_id, user_id)
            )
        else:
            cur = conn.execute("SELECT * FROM dispute_cases WHERE id = ?", (case_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# ---------------------------------------------------------
# Case Attachment Operations
# ---------------------------------------------------------
def create_attachment(attachment_data: Dict[str, Any]) -> Dict[str, Any]:
    """Insert an attachment record into SQLite."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO case_attachments (
                    id, case_id, user_id, category, enc_original_filename, enc_mime_type,
                    plaintext_size, plaintext_sha256, aes_meta_json, des_meta_json, rc4_meta_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attachment_data["id"],
                    attachment_data["case_id"],
                    attachment_data["user_id"],
                    attachment_data["category"],
                    attachment_data["enc_original_filename"],
                    attachment_data["enc_mime_type"],
                    attachment_data["plaintext_size"],
                    attachment_data["plaintext_sha256"],
                    attachment_data["aes_meta_json"],
                    attachment_data["des_meta_json"],
                    attachment_data["rc4_meta_json"],
                    attachment_data["created_at"]
                )
            )
        return attachment_data
    finally:
        conn.close()


def get_attachments_by_case(case_id: str, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch all attachments for a dispute case, optionally verifying user ownership."""
    conn = get_db_connection()
    try:
        if user_id:
            cur = conn.execute(
                "SELECT * FROM case_attachments WHERE case_id = ? AND user_id = ? ORDER BY created_at ASC",
                (case_id, user_id)
            )
        else:
            cur = conn.execute(
                "SELECT * FROM case_attachments WHERE case_id = ? ORDER BY created_at ASC",
                (case_id,)
            )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_attachment_by_id(attachment_id: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetch an attachment by ID, optionally verifying ownership."""
    conn = get_db_connection()
    try:
        if user_id:
            cur = conn.execute(
                "SELECT * FROM case_attachments WHERE id = ? AND user_id = ?",
                (attachment_id, user_id)
            )
        else:
            cur = conn.execute("SELECT * FROM case_attachments WHERE id = ?", (attachment_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# ---------------------------------------------------------
# Benchmark Runs Operations
# ---------------------------------------------------------
def save_benchmark_run(results_dict: Dict[str, Any], run_id: Optional[str] = None) -> Dict[str, Any]:
    """Store benchmark execution results into benchmark_runs."""
    rid = run_id or str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    results_json = json.dumps(results_dict)
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO benchmark_runs (id, created_at, results_json) VALUES (?, ?, ?)",
                (rid, now_iso, results_json)
            )
        return {"id": rid, "created_at": now_iso, "results": results_dict}
    finally:
        conn.close()


def get_latest_benchmark_run() -> Optional[Dict[str, Any]]:
    """Retrieve the most recent benchmark run from the database."""
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT * FROM benchmark_runs ORDER BY created_at DESC LIMIT 1")
        row = cur.fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "results": json.loads(row["results_json"])
        }
    finally:
        conn.close()


def get_all_benchmark_runs() -> List[Dict[str, Any]]:
    """Retrieve all historic benchmark runs."""
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT id, created_at, results_json FROM benchmark_runs ORDER BY created_at DESC")
        rows = cur.fetchall()
        return [
            {
                "id": r["id"],
                "created_at": r["created_at"],
                "results": json.loads(r["results_json"])
            }
            for r in rows
        ]
    finally:
        conn.close()
