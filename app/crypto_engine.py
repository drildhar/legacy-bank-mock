"""
Bank ATM Dispute, Fraud & e-KYC Customer Vault - Cryptographic Engine
Compliant with Indonesian UU PDP No. 27/2022 and POJK No. 22/2023.

This module implements:
1. PBKDF2-HMAC-SHA256 Customer Password Hashing & Verification.
2. User-Bound Envelope Encryption (KEK & DEK Bundle via AES-256-GCM).
3. Tri-Cipher Authenticated Encryption Pipeline:
   - Modern Core Banking: AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
   - Legacy ATM ISO 8583 / ANSI X9.8: DES-CBC (64-bit block) + HMAC-SHA256
   - Legacy PDF/Web Stream: RC4 Stream (Salted Frame Key, 768-drop) + HMAC-SHA256
   - Optional Reference: AES-256-GCM AEAD
4. Tri-Cipher Field & Binary Vault File Helpers.
5. Random-Access Video Scrubbing Simulation (O(1) Block vs O(N) Stream HTTP Range Seeking).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional, Tuple

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Util.Padding import pad, unpad


# Core configuration parameters
PBKDF2_ROUNDS = 100_000
DEFAULT_SALT_LEN = 16


def _coerce_bytes(key: bytes | str) -> bytes:
    """Coerce hex string or raw bytes into bytes."""
    if isinstance(key, str):
        try:
            return bytes.fromhex(key)
        except ValueError:
            return key.encode("utf-8")
    return key


def hash_password(password: str, salt_hex: Optional[str] = None) -> Dict[str, str]:
    """
    Hashes a customer password using PBKDF2-HMAC-SHA256 with 100,000 iterations
    and a cryptographically secure 16-byte random salt.

    Args:
        password: Plaintext customer password.
        salt_hex: Optional pre-existing 16-byte salt as hex string.

    Returns:
        Dict with "salt_hex" and "hash_hex".
    """
    if salt_hex is None:
        salt_bytes = os.urandom(16)
        salt_hex = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt_hex)

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        PBKDF2_ROUNDS
    )
    return {
        "salt_hex": salt_hex,
        "hash_hex": derived.hex()
    }


def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    """
    Verifies a customer password against an expected hash using constant-time comparison
    to prevent timing attacks.
    """
    computed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        PBKDF2_ROUNDS
    ).hex()
    return hmac.compare_digest(computed, expected_hash_hex)


def generate_dek_bundle() -> Dict[str, str]:
    """
    Generates a unique CSPRNG Data Encryption Key (DEK) bundle for an individual user:
    - aes_key: 32 bytes (256-bit) hex
    - des_key: 8 bytes (64-bit / 56-bit effective) hex
    - rc4_key: 32 bytes (256-bit master key) hex
    - hmac_key: 32 bytes (256-bit) hex

    Returns:
        Dict mapping key names to hex strings.
    """
    return {
        "aes_key": os.urandom(32).hex(),
        "des_key": os.urandom(8).hex(),
        "rc4_key": os.urandom(32).hex(),
        "hmac_key": os.urandom(32).hex(),
    }


def derive_kek(password: str, kdf_salt_hex: str) -> bytes:
    """
    Derives a 256-bit Key Encryption Key (KEK) from the customer password and KDF salt
    using PBKDF2-HMAC-SHA256 (100,000 iterations).
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(kdf_salt_hex),
        PBKDF2_ROUNDS
    )


def wrap_dek_bundle(
    dek_bundle: Dict[str, str],
    password: str,
    kdf_salt_hex: Optional[str] = None
) -> Dict[str, str]:
    """
    Wraps (encrypts) the user's DEK bundle with a password-derived KEK using AES-256-GCM.
    Enforces that only the authenticated user can access their keys.

    Returns:
        Dict containing:
        - "kdf_salt_hex": 16-byte hex salt for KDF
        - "wrapped_bundle_json": JSON string containing nonce_b64, ciphertext_b64, tag_b64
    """
    if kdf_salt_hex is None:
        kdf_salt_hex = os.urandom(16).hex()

    kek = derive_kek(password, kdf_salt_hex)
    nonce = os.urandom(12)  # 96-bit standard GCM nonce
    cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce)

    bundle_json_bytes = json.dumps(dek_bundle).encode("utf-8")
    ciphertext, tag = cipher.encrypt_and_digest(bundle_json_bytes)

    wrapped_bundle = {
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "tag_b64": base64.b64encode(tag).decode("ascii"),
    }

    return {
        "kdf_salt_hex": kdf_salt_hex,
        "wrapped_bundle_json": json.dumps(wrapped_bundle)
    }


def unwrap_dek_bundle(wrapped_bundle_json: str, password: str, kdf_salt_hex: str) -> Dict[str, str]:
    """
    Unwraps (decrypts and verifies) the user's DEK bundle using AES-256-GCM.

    Raises:
        ValueError("Invalid password or corrupted key bundle") on authentication tag failure or invalid JSON.
    """
    try:
        kek = derive_kek(password, kdf_salt_hex)
        data = json.loads(wrapped_bundle_json)
        nonce = base64.b64decode(data["nonce_b64"])
        ciphertext = base64.b64decode(data["ciphertext_b64"])
        tag = base64.b64decode(data["tag_b64"])

        cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce)
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        bundle = json.loads(decrypted_bytes.decode("utf-8"))
        return bundle
    except Exception as e:
        raise ValueError("Invalid password or corrupted key bundle") from e




# TODO: Implement symmetric block ciphers and stream ciphers

