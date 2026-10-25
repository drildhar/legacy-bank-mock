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


# =====================================================================
# Internal Type Coercion Helpers
# =====================================================================

def _coerce_bytes(key: bytes | str) -> bytes:
    """Coerce hex string or raw bytes into bytes."""
    if isinstance(key, str):
        try:
            return bytes.fromhex(key)
        except ValueError:
            return key.encode("utf-8")
    return key


# =====================================================================
# 1. Customer Authentication & Password Hashing
# =====================================================================

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
        100_000
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
        100_000
    ).hex()
    return hmac.compare_digest(computed, expected_hash_hex)


# =====================================================================
# 2. User-Bound Envelope Encryption (KEK & DEK Bundle)
# =====================================================================

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
        100_000
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


# =====================================================================
# 3. Individual Cipher Encrypt & Decrypt (Encrypt-then-MAC Integrity)
# =====================================================================

# ----------------- AES-256-CBC + HMAC-SHA256 -----------------

def encrypt_aes(
    plaintext: bytes,
    aes_key: bytes | str,
    hmac_key: bytes | str,
    aad: bytes = b""
) -> Dict[str, Any]:
    """
    Encrypts plaintext with AES-256-CBC and appends an HMAC-SHA256 over (IV || Ciphertext || AAD).

    Returns detailed operational and size metrics for comparative evaluation.
    """
    k_aes = _coerce_bytes(aes_key)
    k_hmac = _coerce_bytes(hmac_key)
    iv = os.urandom(16)

    t0 = time.perf_counter_ns()
    cipher = AES.new(k_aes, AES.MODE_CBC, iv=iv)
    padded_pt = pad(plaintext, 16)
    ciphertext = cipher.encrypt(padded_pt)
    mac = hmac.new(k_hmac, iv + ciphertext + aad, hashlib.sha256).digest()
    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

    return {
        "cipher": "AES-256-CBC",
        "iv_b64": base64.b64encode(iv).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "hmac_b64": base64.b64encode(mac).decode("ascii"),
        "plaintext_size": len(plaintext),
        "ciphertext_size": len(ciphertext),
        "iv_size": 16,
        "mac_size": 32,
        "block_plus_iv_size": len(ciphertext) + 16,
        "total_protected_size": len(ciphertext) + 16 + 32,
        "padding_bytes": len(ciphertext) - len(plaintext),
        "encrypt_ms": round(elapsed_ms, 4)
    }


def decrypt_aes(
    payload: Dict[str, Any],
    aes_key: bytes | str,
    hmac_key: bytes | str,
    aad: bytes = b""
) -> Tuple[bytes, float]:
    """
    Verifies HMAC-SHA256 over (IV || Ciphertext || AAD) first, then decrypts AES-256-CBC
    and unpads PKCS#7.

    Raises:
        ValueError if HMAC verification fails or ciphertext is tampered with.
    """
    k_aes = _coerce_bytes(aes_key)
    k_hmac = _coerce_bytes(hmac_key)

    iv = base64.b64decode(payload["iv_b64"])
    ciphertext = base64.b64decode(payload["ciphertext_b64"])
    mac = base64.b64decode(payload["hmac_b64"])

    t0 = time.perf_counter_ns()
    expected_mac = hmac.new(k_hmac, iv + ciphertext + aad, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("AES Integrity Check Failed: HMAC mismatch (ciphertext or AAD tampered)")

    cipher = AES.new(k_aes, AES.MODE_CBC, iv=iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    try:
        plaintext = unpad(decrypted_padded, 16)
    except Exception as e:
        raise ValueError("AES Decryption Failed: Invalid padding") from e

    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    return plaintext, round(elapsed_ms, 4)


# ----------------- DES-CBC + HMAC-SHA256 -----------------

def encrypt_des(
    plaintext: bytes,
    des_key: bytes | str,
    hmac_key: bytes | str,
    aad: bytes = b""
) -> Dict[str, Any]:
    """
    Encrypts plaintext with 64-bit DES-CBC (ANSI X9.8 / ISO 8583 legacy standard)
    and appends an HMAC-SHA256 over (IV || Ciphertext || AAD).
    """
    k_des = _coerce_bytes(des_key)
    k_hmac = _coerce_bytes(hmac_key)
    iv = os.urandom(8)  # 64-bit block size

    t0 = time.perf_counter_ns()
    cipher = DES.new(k_des, DES.MODE_CBC, iv=iv)
    padded_pt = pad(plaintext, 8)
    ciphertext = cipher.encrypt(padded_pt)
    mac = hmac.new(k_hmac, iv + ciphertext + aad, hashlib.sha256).digest()
    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

    return {
        "cipher": "DES-CBC",
        "iv_b64": base64.b64encode(iv).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "hmac_b64": base64.b64encode(mac).decode("ascii"),
        "plaintext_size": len(plaintext),
        "ciphertext_size": len(ciphertext),
        "iv_size": 8,
        "mac_size": 32,
        "block_plus_iv_size": len(ciphertext) + 8,
        "total_protected_size": len(ciphertext) + 8 + 32,
        "padding_bytes": len(ciphertext) - len(plaintext),
        "encrypt_ms": round(elapsed_ms, 4)
    }


def decrypt_des(
    payload: Dict[str, Any],
    des_key: bytes | str,
    hmac_key: bytes | str,
    aad: bytes = b""
) -> Tuple[bytes, float]:
    """
    Verifies HMAC-SHA256 over (IV || Ciphertext || AAD) first, then decrypts DES-CBC
    and unpads PKCS#7 (8-byte block).

    Raises:
        ValueError if HMAC verification fails or ciphertext is tampered with.
    """
    k_des = _coerce_bytes(des_key)
    k_hmac = _coerce_bytes(hmac_key)

    iv = base64.b64decode(payload["iv_b64"])
    ciphertext = base64.b64decode(payload["ciphertext_b64"])
    mac = base64.b64decode(payload["hmac_b64"])

    t0 = time.perf_counter_ns()
    expected_mac = hmac.new(k_hmac, iv + ciphertext + aad, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("DES Integrity Check Failed: HMAC mismatch")

    cipher = DES.new(k_des, DES.MODE_CBC, iv=iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    try:
        plaintext = unpad(decrypted_padded, 8)
    except Exception as e:
        raise ValueError("DES Decryption Failed: Invalid padding") from e

    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    return plaintext, round(elapsed_ms, 4)


# ----------------- RC4 Stream + Salted Subkey + HMAC-SHA256 -----------------

def encrypt_rc4(
    plaintext: bytes,
    rc4_key: bytes | str,
    hmac_key: bytes | str,
    aad: bytes = b""
) -> Dict[str, Any]:
    """
    Encrypts plaintext with RC4 stream cipher.
    To prevent catastrophic keystream reuse across banking records, derives a unique
    per-record 32-byte frame key using a random 16-byte salt:
      frame_key = HMAC-SHA256(rc4_key, "RC4-FRAME-KEY:" || salt)
    Drops initial 768 bytes of keystream to resist Fluhrer-Mantin-Shamir (FMS) bias.
    Appends HMAC-SHA256 over (Salt || Ciphertext || AAD) for cryptographic integrity.
    """
    k_rc4 = _coerce_bytes(rc4_key)
    k_hmac = _coerce_bytes(hmac_key)
    salt = os.urandom(16)

    t0 = time.perf_counter_ns()
    frame_key = hmac.new(k_rc4, b"RC4-FRAME-KEY:" + salt, hashlib.sha256).digest()
    cipher = ARC4.new(frame_key, drop=768)
    ciphertext = cipher.encrypt(plaintext)
    mac = hmac.new(k_hmac, salt + ciphertext + aad, hashlib.sha256).digest()
    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

    return {
        "cipher": "RC4-Stream",
        "iv_b64": base64.b64encode(salt).decode("ascii"),  # Salt stored in iv_b64
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "hmac_b64": base64.b64encode(mac).decode("ascii"),
        "plaintext_size": len(plaintext),
        "ciphertext_size": len(ciphertext),
        "iv_size": 16,
        "mac_size": 32,
        "block_plus_iv_size": len(ciphertext) + 16,
        "total_protected_size": len(ciphertext) + 16 + 32,
        "padding_bytes": 0,
        "encrypt_ms": round(elapsed_ms, 4)
    }


def decrypt_rc4(
    payload: Dict[str, Any],
    rc4_key: bytes | str,
    hmac_key: bytes | str,
    aad: bytes = b""
) -> Tuple[bytes, float]:
    """
    Verifies HMAC-SHA256 over (Salt || Ciphertext || AAD) first, then regenerates
    frame key, drops 768 bytes, and decrypts RC4 stream.

    Raises:
        ValueError if HMAC verification fails.
    """
    k_rc4 = _coerce_bytes(rc4_key)
    k_hmac = _coerce_bytes(hmac_key)

    salt = base64.b64decode(payload["iv_b64"])
    ciphertext = base64.b64decode(payload["ciphertext_b64"])
    mac = base64.b64decode(payload["hmac_b64"])

    t0 = time.perf_counter_ns()
    expected_mac = hmac.new(k_hmac, salt + ciphertext + aad, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("RC4 Integrity Check Failed: HMAC mismatch")

    frame_key = hmac.new(k_rc4, b"RC4-FRAME-KEY:" + salt, hashlib.sha256).digest()
    cipher = ARC4.new(frame_key, drop=768)
    plaintext = cipher.decrypt(ciphertext)
    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    return plaintext, round(elapsed_ms, 4)


# ----------------- AES-256-GCM (Optional AEAD Reference) -----------------

def encrypt_aes_gcm(
    plaintext: bytes,
    aes_key: bytes | str,
    aad: bytes = b""
) -> Dict[str, Any]:
    """
    Encrypts plaintext with AES-256-GCM (AEAD standard).
    Provides zero padding overhead and hardware-accelerated GHASH authentication.
    """
    k_aes = _coerce_bytes(aes_key)
    nonce = os.urandom(12)

    t0 = time.perf_counter_ns()
    cipher = AES.new(k_aes, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

    return {
        "cipher": "AES-256-GCM",
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "iv_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "tag_b64": base64.b64encode(tag).decode("ascii"),
        "hmac_b64": base64.b64encode(tag).decode("ascii"),
        "plaintext_size": len(plaintext),
        "ciphertext_size": len(ciphertext),
        "iv_size": 12,
        "mac_size": 16,
        "block_plus_iv_size": len(ciphertext) + 12,
        "total_protected_size": len(ciphertext) + 12 + 16,
        "padding_bytes": 0,
        "encrypt_ms": round(elapsed_ms, 4)
    }


def decrypt_aes_gcm(
    payload: Dict[str, Any],
    aes_key: bytes | str,
    aad: bytes = b""
) -> Tuple[bytes, float]:
    """
    Decrypts and verifies AES-256-GCM ciphertext and authentication tag.
    """
    k_aes = _coerce_bytes(aes_key)
    nonce = base64.b64decode(payload.get("nonce_b64") or payload["iv_b64"])
    ciphertext = base64.b64decode(payload["ciphertext_b64"])
    tag = base64.b64decode(payload.get("tag_b64") or payload.get("hmac_b64", ""))

    t0 = time.perf_counter_ns()
    cipher = AES.new(k_aes, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        raise ValueError("AES-GCM Integrity Check Failed: Authentication tag mismatch") from e

    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    return plaintext, round(elapsed_ms, 4)


# =====================================================================
# 4. Tri-Cipher Helper Functions for Text Fields & Binary Files
# =====================================================================

def encrypt_field_tri(
    plaintext_str: str,
    dek_bundle: Dict[str, Any],
    aad: bytes = b""
) -> Dict[str, Dict[str, Any]]:
    """
    Encrypts a sensitive customer or ATM text field (e.g., NIK, PAN, STAN)
    concurrently through AES-256-CBC, DES-CBC, and RC4.
    """
    pt_bytes = plaintext_str.encode("utf-8")
    aes_res = encrypt_aes(pt_bytes, dek_bundle["aes_key"], dek_bundle["hmac_key"], aad=aad)
    des_res = encrypt_des(pt_bytes, dek_bundle["des_key"], dek_bundle["hmac_key"], aad=aad)
    rc4_res = encrypt_rc4(pt_bytes, dek_bundle["rc4_key"], dek_bundle["hmac_key"], aad=aad)

    return {
        "aes": aes_res,
        "des": des_res,
        "rc4": rc4_res
    }


def decrypt_field_tri(
    enc_field_dict: Dict[str, Any],
    dek_bundle: Dict[str, Any],
    cipher_choice: str = "aes",
    aad: bytes = b""
) -> Tuple[str, float]:
    """
    Decrypts an encrypted field dictionary using the customer's specified cipher:
    'aes', 'des', or 'rc4'.

    Returns:
        (decrypted_text_string, decrypt_ms)
    """
    choice = cipher_choice.lower().strip()
    if choice in ("aes", "aes_cbc", "aes-cbc", "aes-256", "aes-256-cbc"):
        pt_bytes, dec_ms = decrypt_aes(enc_field_dict["aes"], dek_bundle["aes_key"], dek_bundle["hmac_key"], aad=aad)
    elif choice in ("des", "des_cbc", "des-cbc"):
        pt_bytes, dec_ms = decrypt_des(enc_field_dict["des"], dek_bundle["des_key"], dek_bundle["hmac_key"], aad=aad)
    elif choice in ("rc4", "rc4_stream", "rc4-stream"):
        pt_bytes, dec_ms = decrypt_rc4(enc_field_dict["rc4"], dek_bundle["rc4_key"], dek_bundle["hmac_key"], aad=aad)
    elif choice in ("gcm", "aes_gcm", "aes-gcm", "aes-256-gcm"):
        pt_bytes, dec_ms = decrypt_aes_gcm(enc_field_dict["gcm"], dek_bundle["aes_key"], aad=aad)
    else:
        raise ValueError(f"Unsupported cipher choice: {cipher_choice}. Expected 'aes', 'des', or 'rc4'.")

    return pt_bytes.decode("utf-8"), dec_ms


def encrypt_bytes_tri(
    plaintext: bytes,
    dek_bundle: Dict[str, Any],
    aad: bytes = b""
) -> Dict[str, Dict[str, Any]]:
    """
    Encrypts binary file bytes (KTP scan, PDF e-Statement, or CCTV video) with AES, DES, and RC4.
    Returns raw ciphertext bytes alongside metadata for persistence to disk.
    """
    aes_res = encrypt_aes(plaintext, dek_bundle["aes_key"], dek_bundle["hmac_key"], aad=aad)
    des_res = encrypt_des(plaintext, dek_bundle["des_key"], dek_bundle["hmac_key"], aad=aad)
    rc4_res = encrypt_rc4(plaintext, dek_bundle["rc4_key"], dek_bundle["hmac_key"], aad=aad)

    aes_ct = base64.b64decode(aes_res.pop("ciphertext_b64"))
    des_ct = base64.b64decode(des_res.pop("ciphertext_b64"))
    rc4_ct = base64.b64decode(rc4_res.pop("ciphertext_b64"))

    aes_entry = {
        "ciphertext_bytes": aes_ct,
        "meta": aes_res,
        "metadata": aes_res,
        **aes_res
    }
    des_entry = {
        "ciphertext_bytes": des_ct,
        "meta": des_res,
        "metadata": des_res,
        **des_res
    }
    rc4_entry = {
        "ciphertext_bytes": rc4_ct,
        "meta": rc4_res,
        "metadata": rc4_res,
        **rc4_res
    }

    return {
        "aes": aes_entry,
        "des": des_entry,
        "rc4": rc4_entry
    }


def decrypt_bytes_single(
    ciphertext: bytes,
    meta: Dict[str, Any],
    dek_bundle: Dict[str, Any],
    cipher_choice: str,
    aad: bytes = b""
) -> Tuple[bytes, float]:
    """
    Verifies HMAC and decrypts raw ciphertext bytes from disk for 'aes', 'des', or 'rc4'.
    Operates directly on binary buffers in memory without redundant base64 re-encoding.
    """
    # Handle wrapped metadata structures
    if "meta" in meta and isinstance(meta["meta"], dict):
        meta = meta["meta"]
    elif "metadata" in meta and isinstance(meta["metadata"], dict):
        meta = meta["metadata"]

    choice = cipher_choice.lower().strip()
    hmac_key = _coerce_bytes(dek_bundle["hmac_key"])

    if choice in ("aes", "aes_cbc", "aes-cbc", "aes-256", "aes-256-cbc"):
        aes_key = _coerce_bytes(dek_bundle["aes_key"])
        iv = base64.b64decode(meta["iv_b64"])
        mac = base64.b64decode(meta["hmac_b64"])

        t0 = time.perf_counter_ns()
        expected_mac = hmac.new(hmac_key, iv + ciphertext + aad, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("AES Integrity Check Failed: HMAC mismatch (ciphertext or AAD tampered)")

        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), 16)
        elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        return plaintext, round(elapsed_ms, 4)

    elif choice in ("des", "des_cbc", "des-cbc"):
        des_key = _coerce_bytes(dek_bundle["des_key"])
        iv = base64.b64decode(meta["iv_b64"])
        mac = base64.b64decode(meta["hmac_b64"])

        t0 = time.perf_counter_ns()
        expected_mac = hmac.new(hmac_key, iv + ciphertext + aad, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("DES Integrity Check Failed: HMAC mismatch")

        cipher = DES.new(des_key, DES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), 8)
        elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        return plaintext, round(elapsed_ms, 4)

    elif choice in ("rc4", "rc4_stream", "rc4-stream"):
        rc4_key = _coerce_bytes(dek_bundle["rc4_key"])
        salt = base64.b64decode(meta["iv_b64"])
        mac = base64.b64decode(meta["hmac_b64"])

        t0 = time.perf_counter_ns()
        expected_mac = hmac.new(hmac_key, salt + ciphertext + aad, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("RC4 Integrity Check Failed: HMAC mismatch")

        frame_key = hmac.new(rc4_key, b"RC4-FRAME-KEY:" + salt, hashlib.sha256).digest()
        cipher = ARC4.new(frame_key, drop=768)
        plaintext = cipher.decrypt(ciphertext)
        elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        return plaintext, round(elapsed_ms, 4)

    elif choice in ("gcm", "aes_gcm", "aes-gcm", "aes-256-gcm"):
        aes_key = _coerce_bytes(dek_bundle["aes_key"])
        nonce = base64.b64decode(meta.get("nonce_b64") or meta["iv_b64"])
        tag = base64.b64decode(meta.get("tag_b64") or meta["hmac_b64"])

        t0 = time.perf_counter_ns()
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        return plaintext, round(elapsed_ms, 4)

    else:
        raise ValueError(f"Unsupported cipher choice: {cipher_choice}. Expected 'aes', 'des', or 'rc4'.")


# =====================================================================
# 5. Random-Access Video Scrubbing Simulation (HTTP Range Seeking)
# =====================================================================

def simulate_random_access_seek(
    plaintext_video: bytes,
    dek_bundle: Dict[str, Any],
    seek_offset: int,
    chunk_size: int = 65536
) -> Dict[str, Any]:
    """
    Benchmarks jumping directly to `seek_offset` and decrypting a `chunk_size`
    video frame buffer (simulating an HTTP 206 Partial Content Range request).

    Demonstrates the fundamental architectural difference:
    - AES-CBC: O(1) random-access seek by slicing ciphertext[seek_offset-16 : seek_offset] as IV.
    - DES-CBC: O(1) random-access seek by slicing ciphertext[seek_offset-8 : seek_offset] as IV.
    - RC4: O(N) linear stream seek requiring discarding `seek_offset` bytes of keystream.

    Verifies bit-for-bit authenticity against `plaintext_video[seek_offset : seek_offset + chunk_size]`.
    """
    aes_key = _coerce_bytes(dek_bundle["aes_key"])
    des_key = _coerce_bytes(dek_bundle["des_key"])
    rc4_key = _coerce_bytes(dek_bundle["rc4_key"])

    # Align seek_offset to 16 bytes (AES block size)
    seek_offset = (seek_offset // 16) * 16
    if seek_offset < 16:
        seek_offset = 16

    # Ensure chunk_size is aligned and within bounds
    if seek_offset + chunk_size > len(plaintext_video):
        chunk_size = ((len(plaintext_video) - seek_offset) // 16) * 16

    expected_chunk = plaintext_video[seek_offset : seek_offset + chunk_size]

    # Pre-encrypt the full video buffer
    aes_iv = os.urandom(16)
    aes_cipher_full = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
    aes_ct = aes_cipher_full.encrypt(pad(plaintext_video, 16))

    des_iv = os.urandom(8)
    des_cipher_full = DES.new(des_key, DES.MODE_CBC, iv=des_iv)
    des_ct = des_cipher_full.encrypt(pad(plaintext_video, 8))

    rc4_salt = os.urandom(16)
    rc4_frame_key = hmac.new(rc4_key, b"RC4-FRAME-KEY:" + rc4_salt, hashlib.sha256).digest()
    rc4_cipher_full = ARC4.new(rc4_frame_key, drop=768)
    rc4_ct = rc4_cipher_full.encrypt(plaintext_video)

    # 1. AES-CBC O(1) Seek: Read previous 16 bytes of ciphertext as IV
    t0 = time.perf_counter_ns()
    aes_block_iv = aes_ct[seek_offset - 16 : seek_offset]
    aes_seek_cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_block_iv)
    aes_decrypted = aes_seek_cipher.decrypt(aes_ct[seek_offset : seek_offset + chunk_size])
    aes_seek_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

    if aes_decrypted != expected_chunk:
        raise RuntimeError("AES-CBC seek verification failed: Decrypted chunk mismatch!")

    # 2. DES-CBC O(1) Seek: Read previous 8 bytes of ciphertext as IV
    t0 = time.perf_counter_ns()
    des_block_iv = des_ct[seek_offset - 8 : seek_offset]
    des_seek_cipher = DES.new(des_key, DES.MODE_CBC, iv=des_block_iv)
    des_decrypted = des_seek_cipher.decrypt(des_ct[seek_offset : seek_offset + chunk_size])
    des_seek_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

    if des_decrypted != expected_chunk:
        raise RuntimeError("DES-CBC seek verification failed: Decrypted chunk mismatch!")

    # 3. RC4 Stream O(N) Seek: Must generate and discard seek_offset keystream bytes from byte 0
    t0 = time.perf_counter_ns()
    rc4_seek_cipher = ARC4.new(rc4_frame_key, drop=768)
    # Discard seek_offset keystream bytes in 64 KB buffers
    discard_buf_len = 65536
    dummy_zeros = b"\x00" * discard_buf_len
    remaining_bytes = seek_offset
    while remaining_bytes > 0:
        step = min(remaining_bytes, discard_buf_len)
        rc4_seek_cipher.encrypt(dummy_zeros[:step])
        remaining_bytes -= step
    rc4_decrypted = rc4_seek_cipher.decrypt(rc4_ct[seek_offset : seek_offset + chunk_size])
    rc4_seek_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

    if rc4_decrypted != expected_chunk:
        raise RuntimeError("RC4 stream seek verification failed: Decrypted chunk mismatch!")

    ratio = round(rc4_seek_ms / max(aes_seek_ms, 1e-6), 2)

    return {
        "seek_offset": seek_offset,
        "seek_offset_mb": round(seek_offset / (1024 * 1024), 2),
        "chunk_size": chunk_size,
        "chunk_size_kb": round(chunk_size / 1024, 2),
        "aes_seek_ms": round(aes_seek_ms, 4),
        "des_seek_ms": round(des_seek_ms, 4),
        "rc4_seek_ms": round(rc4_seek_ms, 4),
        "verified": True,
        "ratio_rc4_to_aes": ratio,
        "interpretation": (
            f"At byte offset {seek_offset:,} ({seek_offset / (1024 * 1024):.2f} MB), "
            f"AES-256-CBC completed O(1) random-access seek in {aes_seek_ms:.4f} ms and "
            f"DES-CBC in {des_seek_ms:.4f} ms, whereas RC4 required {rc4_seek_ms:.4f} ms "
            f"({ratio:.1f}x slower) due to O(N) sequential keystream discarding. "
            f"This proves stream ciphers like RC4 are architecturally unsuitable for "
            f"HTTP Range video scrubbing in ATM CCTV / e-KYC evidence portals."
        )
    }
