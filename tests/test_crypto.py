"""
Unit Tests for Cryptographic Engine and Benchmark Suite.
Bank ATM Dispute, Fraud & e-KYC Customer Vault.
Compliant with Indonesian UU PDP No. 27/2022 and POJK No. 22/2023.
"""

from __future__ import annotations

import base64
import json
import os
import unittest

from app.crypto_engine import (
    decrypt_aes,
    decrypt_aes_gcm,
    decrypt_bytes_single,
    decrypt_des,
    decrypt_field_tri,
    decrypt_rc4,
    derive_kek,
    encrypt_aes,
    encrypt_aes_gcm,
    encrypt_bytes_tri,
    encrypt_des,
    encrypt_field_tri,
    encrypt_rc4,
    generate_dek_bundle,
    hash_password,
    simulate_random_access_seek,
    unwrap_dek_bundle,
    verify_password,
    wrap_dek_bundle,
)
from app.benchmark import (
    generate_benchmark_payloads,
    run_full_benchmark_suite,
)


class TestPasswordHashingAndVerification(unittest.TestCase):
    """Tests PBKDF2-HMAC-SHA256 password hashing and constant-time verification."""

    def test_hash_password_produces_salt_and_hash(self):
        res = hash_password("CustomerP@ssw0rd2026!")
        self.assertIn("salt_hex", res)
        self.assertIn("hash_hex", res)
        self.assertEqual(len(bytes.fromhex(res["salt_hex"])), 16)
        self.assertEqual(len(bytes.fromhex(res["hash_hex"])), 32)

    def test_verify_password_success(self):
        pwd = "ATM-Dispute-Valid-Password#1"
        res = hash_password(pwd)
        self.assertTrue(verify_password(pwd, res["salt_hex"], res["hash_hex"]))

    def test_verify_password_failure_wrong_password(self):
        res = hash_password("CorrectPassword123")
        self.assertFalse(verify_password("WrongPassword123", res["salt_hex"], res["hash_hex"]))

    def test_verify_password_failure_wrong_salt(self):
        res = hash_password("SamePassword")
        wrong_salt = os.urandom(16).hex()
        self.assertFalse(verify_password("SamePassword", wrong_salt, res["hash_hex"]))


class TestEnvelopeEncryption(unittest.TestCase):
    """Tests user-bound DEK bundle generation, KEK derivation, and GCM envelope wrapping."""

    def test_generate_dek_bundle_structure_and_lengths(self):
        bundle = generate_dek_bundle()
        self.assertIn("aes_key", bundle)
        self.assertIn("des_key", bundle)
        self.assertIn("rc4_key", bundle)
        self.assertIn("hmac_key", bundle)

        self.assertEqual(len(bytes.fromhex(bundle["aes_key"])), 32)   # 256-bit AES
        self.assertEqual(len(bytes.fromhex(bundle["des_key"])), 8)    # 64-bit DES
        self.assertEqual(len(bytes.fromhex(bundle["rc4_key"])), 32)   # 256-bit RC4
        self.assertEqual(len(bytes.fromhex(bundle["hmac_key"])), 32)  # 256-bit HMAC

    def test_derive_kek(self):
        salt = os.urandom(16).hex()
        kek1 = derive_kek("TestPassword", salt)
        kek2 = derive_kek("TestPassword", salt)
        self.assertEqual(len(kek1), 32)
        self.assertEqual(kek1, kek2)

    def test_wrap_and_unwrap_dek_bundle_roundtrip(self):
        bundle = generate_dek_bundle()
        pwd = "SecureCustomerBankKey!99"
        wrapped = wrap_dek_bundle(bundle, pwd)

        self.assertIn("kdf_salt_hex", wrapped)
        self.assertIn("wrapped_bundle_json", wrapped)

        unwrapped = unwrap_dek_bundle(wrapped["wrapped_bundle_json"], pwd, wrapped["kdf_salt_hex"])
        self.assertEqual(bundle, unwrapped)

    def test_unwrap_dek_bundle_wrong_password_raises(self):
        bundle = generate_dek_bundle()
        wrapped = wrap_dek_bundle(bundle, "PasswordA")

        with self.assertRaises(ValueError) as ctx:
            unwrap_dek_bundle(wrapped["wrapped_bundle_json"], "PasswordB", wrapped["kdf_salt_hex"])
        self.assertIn("Invalid password or corrupted key bundle", str(ctx.exception))

    def test_unwrap_dek_bundle_tampered_tag_raises(self):
        bundle = generate_dek_bundle()
        wrapped = wrap_dek_bundle(bundle, "PasswordA")

        data = json.loads(wrapped["wrapped_bundle_json"])
        tag = bytearray(base64.b64decode(data["tag_b64"]))
        tag[0] ^= 0xFF  # Tamper tag byte
        data["tag_b64"] = base64.b64encode(tag).decode("ascii")

        with self.assertRaises(ValueError):
            unwrap_dek_bundle(json.dumps(data), "PasswordA", wrapped["kdf_salt_hex"])


class TestAES256CBCWithHMAC(unittest.TestCase):
    """Tests AES-256-CBC with PKCS#7 padding and Encrypt-then-MAC HMAC-SHA256 integrity."""

    def setUp(self):
        self.aes_key = os.urandom(32)
        self.hmac_key = os.urandom(32)
        self.aad = b"user_1234_case_5678"

    def test_aes_cbc_roundtrip_intact(self):
        test_payloads = [
            b"",
            b"A",
            b"STAN4829",
            b"3171012345678901",  # Exactly 16 bytes
            b"31710123456789012",  # 17 bytes
            b"Bank dispute customer evidence document bytes" * 50
        ]
        for pt in test_payloads:
            enc = encrypt_aes(pt, self.aes_key, self.hmac_key, aad=self.aad)
            self.assertEqual(enc["cipher"], "AES-256-CBC")
            self.assertEqual(enc["plaintext_size"], len(pt))
            self.assertEqual(enc["iv_size"], 16)
            self.assertEqual(enc["mac_size"], 32)
            self.assertEqual(enc["block_plus_iv_size"], enc["ciphertext_size"] + 16)
            self.assertEqual(enc["total_protected_size"], enc["ciphertext_size"] + 16 + 32)

            dec, dec_ms = decrypt_aes(enc, self.aes_key, self.hmac_key, aad=self.aad)
            self.assertEqual(dec, pt, "Plaintext must come back intact bit-for-bit!")
            self.assertGreaterEqual(dec_ms, 0.0)

    def test_aes_cbc_tamper_ciphertext_fails_hmac(self):
        pt = b"Disputed amount: IDR 1,500,000"
        enc = encrypt_aes(pt, self.aes_key, self.hmac_key, aad=self.aad)

        # Bit flip in ciphertext
        ct_bytes = bytearray(base64.b64decode(enc["ciphertext_b64"]))
        ct_bytes[5] ^= 0x01
        enc["ciphertext_b64"] = base64.b64encode(ct_bytes).decode("ascii")

        with self.assertRaises(ValueError) as ctx:
            decrypt_aes(enc, self.aes_key, self.hmac_key, aad=self.aad)
        self.assertIn("AES Integrity Check Failed", str(ctx.exception))

    def test_aes_cbc_tamper_iv_fails_hmac(self):
        pt = b"Disputed amount: IDR 1,500,000"
        enc = encrypt_aes(pt, self.aes_key, self.hmac_key, aad=self.aad)

        # Bit flip in IV
        iv_bytes = bytearray(base64.b64decode(enc["iv_b64"]))
        iv_bytes[0] ^= 0x01
        enc["iv_b64"] = base64.b64encode(iv_bytes).decode("ascii")

        with self.assertRaises(ValueError) as ctx:
            decrypt_aes(enc, self.aes_key, self.hmac_key, aad=self.aad)
        self.assertIn("AES Integrity Check Failed", str(ctx.exception))

    def test_aes_cbc_tamper_aad_fails_hmac(self):
        pt = b"Disputed amount: IDR 1,500,000"
        enc = encrypt_aes(pt, self.aes_key, self.hmac_key, aad=self.aad)

        # Tampered AAD
        with self.assertRaises(ValueError) as ctx:
            decrypt_aes(enc, self.aes_key, self.hmac_key, aad=b"tampered_aad")
        self.assertIn("AES Integrity Check Failed", str(ctx.exception))

    def test_aes_cbc_padding_boundary(self):
        # 16-byte input must append a full 16-byte pad block
        pt_16 = b"0123456789abcdef"
        enc = encrypt_aes(pt_16, self.aes_key, self.hmac_key)
        self.assertEqual(enc["ciphertext_size"], 32)
        self.assertEqual(enc["padding_bytes"], 16)


class TestDESCBCWithHMAC(unittest.TestCase):
    """Tests DES-CBC with 64-bit blocks and Encrypt-then-MAC HMAC-SHA256."""

    def setUp(self):
        self.des_key = os.urandom(8)
        self.hmac_key = os.urandom(32)
        self.aad = b"iso8583-terminal-01"

    def test_des_cbc_roundtrip_intact(self):
        test_payloads = [
            b"STAN4829",
            b"ID-091",
            b"3171012345678901",
            b"DES ATM PIN block emulation record" * 10
        ]
        for pt in test_payloads:
            enc = encrypt_des(pt, self.des_key, self.hmac_key, aad=self.aad)
            self.assertEqual(enc["cipher"], "DES-CBC")
            self.assertEqual(enc["iv_size"], 8)
            self.assertEqual(enc["mac_size"], 32)
            self.assertEqual(enc["block_plus_iv_size"], enc["ciphertext_size"] + 8)

            dec, dec_ms = decrypt_des(enc, self.des_key, self.hmac_key, aad=self.aad)
            self.assertEqual(dec, pt)

    def test_des_cbc_block_granularity(self):
        # 6-byte short code -> 8 bytes ciphertext (2 bytes padding) + 8B IV = 16B block+IV
        enc_6b = encrypt_des(b"ID-091", self.des_key, self.hmac_key)
        self.assertEqual(enc_6b["ciphertext_size"], 8)
        self.assertEqual(enc_6b["padding_bytes"], 2)
        self.assertEqual(enc_6b["block_plus_iv_size"], 16)

        # 16-byte NIK -> 24 bytes ciphertext (8 bytes padding) + 8B IV = 32B block+IV
        enc_16b = encrypt_des(b"3171012345678901", self.des_key, self.hmac_key)
        self.assertEqual(enc_16b["ciphertext_size"], 24)
        self.assertEqual(enc_16b["padding_bytes"], 8)
        self.assertEqual(enc_16b["block_plus_iv_size"], 32)

    def test_des_cbc_tamper_fails_hmac(self):
        enc = encrypt_des(b"Secret ISO 8583 STAN", self.des_key, self.hmac_key, aad=self.aad)
        ct_bytes = bytearray(base64.b64decode(enc["ciphertext_b64"]))
        ct_bytes[0] ^= 0x01
        enc["ciphertext_b64"] = base64.b64encode(ct_bytes).decode("ascii")

        with self.assertRaises(ValueError) as ctx:
            decrypt_des(enc, self.des_key, self.hmac_key, aad=self.aad)
        self.assertIn("DES Integrity Check Failed", str(ctx.exception))


class TestRC4StreamWithHMAC(unittest.TestCase):
    """Tests RC4 stream cipher with salted frame key, 768-drop, and HMAC-SHA256."""

    def setUp(self):
        self.rc4_key = os.urandom(32)
        self.hmac_key = os.urandom(32)
        self.aad = b"rc4-stream-audit"

    def test_rc4_roundtrip_intact(self):
        test_payloads = [
            b"",
            b"RC4 Stream test string",
            b"12345678",
            b"Long e-statement PDF stream chunk " * 20
        ]
        for pt in test_payloads:
            enc = encrypt_rc4(pt, self.rc4_key, self.hmac_key, aad=self.aad)
            self.assertEqual(enc["cipher"], "RC4-Stream")
            self.assertEqual(enc["padding_bytes"], 0)
            self.assertEqual(enc["ciphertext_size"], len(pt))

            dec, dec_ms = decrypt_rc4(enc, self.rc4_key, self.hmac_key, aad=self.aad)
            self.assertEqual(dec, pt)

    def test_rc4_unique_frame_key_per_encryption(self):
        # Two encryptions of the same plaintext must produce different ciphertexts due to salt
        pt = b"Identical Bank Statement Line Item"
        enc1 = encrypt_rc4(pt, self.rc4_key, self.hmac_key)
        enc2 = encrypt_rc4(pt, self.rc4_key, self.hmac_key)

        self.assertNotEqual(enc1["iv_b64"], enc2["iv_b64"])
        self.assertNotEqual(enc1["ciphertext_b64"], enc2["ciphertext_b64"])

    def test_rc4_tamper_fails_hmac(self):
        enc = encrypt_rc4(b"Sensitive Financial Data", self.rc4_key, self.hmac_key, aad=self.aad)
        ct_bytes = bytearray(base64.b64decode(enc["ciphertext_b64"]))
        ct_bytes[0] ^= 0x01
        enc["ciphertext_b64"] = base64.b64encode(ct_bytes).decode("ascii")

        with self.assertRaises(ValueError) as ctx:
            decrypt_rc4(enc, self.rc4_key, self.hmac_key, aad=self.aad)
        self.assertIn("RC4 Integrity Check Failed", str(ctx.exception))


class TestAES256GCM(unittest.TestCase):
    """Tests AES-256-GCM AEAD reference cipher."""

    def test_aes_gcm_roundtrip_and_tamper(self):
        key = os.urandom(32)
        pt = b"GCM authenticated encryption reference payload"
        aad = b"gcm-aad-header"

        enc = encrypt_aes_gcm(pt, key, aad=aad)
        self.assertEqual(enc["cipher"], "AES-256-GCM")
        self.assertEqual(enc["padding_bytes"], 0)

        dec, _ = decrypt_aes_gcm(enc, key, aad=aad)
        self.assertEqual(dec, pt)

        # Tamper tag
        tag_bytes = bytearray(base64.b64decode(enc["tag_b64"]))
        tag_bytes[0] ^= 0xFF
        enc["tag_b64"] = base64.b64encode(tag_bytes).decode("ascii")

        with self.assertRaises(ValueError):
            decrypt_aes_gcm(enc, key, aad=aad)


class TestTriCipherFieldAndBytesHelpers(unittest.TestCase):
    """Tests high-level tri-cipher field and binary vault helpers."""

    def setUp(self):
        self.bundle = generate_dek_bundle()

    def test_encrypt_and_decrypt_field_tri(self):
        text = "Indonesian NIK: 3171012345678901 - Andi Wijaya"
        enc = encrypt_field_tri(text, self.bundle, aad=b"user_andi")

        for cp in ["aes", "des", "rc4"]:
            dec, ms = decrypt_field_tri(enc, self.bundle, cipher_choice=cp, aad=b"user_andi")
            self.assertEqual(dec, text)
            self.assertGreaterEqual(ms, 0.0)

    def test_decrypt_field_tri_invalid_choice_raises(self):
        enc = encrypt_field_tri("Test", self.bundle)
        with self.assertRaises(ValueError):
            decrypt_field_tri(enc, self.bundle, cipher_choice="rot13")

    def test_encrypt_bytes_tri_and_decrypt_single(self):
        raw_bytes = b"Raw binary file buffer for PDF or image scan" * 100
        enc_res = encrypt_bytes_tri(raw_bytes, self.bundle, aad=b"doc_case_1")

        for cp in ["aes", "des", "rc4"]:
            ct_bytes = enc_res[cp]["ciphertext_bytes"]
            meta = enc_res[cp]["meta"]
            dec, ms = decrypt_bytes_single(ct_bytes, meta, self.bundle, cipher_choice=cp, aad=b"doc_case_1")
            self.assertEqual(dec, raw_bytes)
            self.assertGreaterEqual(ms, 0.0)

    def test_decrypt_bytes_single_tamper_raises(self):
        raw_bytes = b"Bank statement transaction rows" * 20
        enc_res = encrypt_bytes_tri(raw_bytes, self.bundle, aad=b"doc_case_2")

        # Tamper AES raw ciphertext
        tampered_aes = bytearray(enc_res["aes"]["ciphertext_bytes"])
        tampered_aes[3] ^= 0x01

        with self.assertRaises(ValueError):
            decrypt_bytes_single(bytes(tampered_aes), enc_res["aes"]["meta"], self.bundle, "aes", aad=b"doc_case_2")


class TestRandomAccessVideoSeek(unittest.TestCase):
    """Tests random-access video scrubbing simulation."""

    def test_random_access_seek_verification(self):
        bundle = generate_dek_bundle()
        # 256 KB test video buffer
        video_buf = os.urandom(256 * 1024)
        seek_offset = 64 * 1024  # 64 KB offset
        chunk_size = 4096

        res = simulate_random_access_seek(video_buf, bundle, seek_offset=seek_offset, chunk_size=chunk_size)
        self.assertTrue(res["verified"])
        self.assertEqual(res["seek_offset"], seek_offset)
        self.assertEqual(res["chunk_size"], chunk_size)
        self.assertIn("aes_seek_ms", res)
        self.assertIn("des_seek_ms", res)
        self.assertIn("rc4_seek_ms", res)
        self.assertIn("ratio_rc4_to_aes", res)
        self.assertIn("interpretation", res)


class TestBenchmarkSuite(unittest.TestCase):
    """Tests execution of the full benchmark suite."""

    def test_generate_benchmark_payloads(self):
        payloads = generate_benchmark_payloads()
        self.assertEqual(len(payloads["atm_stan_8b"]), 8)
        self.assertEqual(len(payloads["short_code_6b"]), 6)
        self.assertEqual(len(payloads["nik_16b"]), 16)
        self.assertEqual(len(payloads["dispute_json_256b"]), 256)
        self.assertEqual(len(payloads["personal_data"]), 512)
        self.assertEqual(len(payloads["id_scan"]), 512_000)
        self.assertEqual(len(payloads["office_doc"]), 2_097_152)
        self.assertEqual(len(payloads["video_evidence"]), 8_388_608)

    def test_run_full_benchmark_suite_smoke(self):
        # 1 iteration smoke test for swift CI verification
        res = run_full_benchmark_suite(iterations=1)
        self.assertIn("metadata", res)
        self.assertIn("short_fields", res)
        self.assertIn("scenarios", res)
        self.assertIn("video_seek", res)
        self.assertIn("interpretations", res)

        # Check scenarios contain all 4 mandatory types
        for expected in ["personal_data", "id_scan", "office_doc", "video_evidence"]:
            self.assertIn(expected, res["scenarios"])
            scen = res["scenarios"][expected]
            for cipher in ["aes_cbc", "des_cbc", "rc4", "aes_gcm"]:
                self.assertIn(cipher, scen["ciphers"])
                c = scen["ciphers"][cipher]
                self.assertGreater(c["enc_throughput_mb_s"], 0)
                self.assertGreater(c["dec_throughput_mb_s"], 0)


if __name__ == "__main__":
    unittest.main()
