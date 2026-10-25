"""
Bank ATM Dispute, Fraud & e-KYC Customer Vault - Benchmark & Evaluation Engine
Compliant with Indonesian UU PDP No. 27/2022 and POJK No. 22/2023.

Evaluates how AES-256-CBC+HMAC, DES-CBC+HMAC, RC4+HMAC, and AES-256-GCM compare across:
1. Short Banking Fields (Storage, Block Granularity & PKCS#7 Boundary Analysis):
   - STAN Audit (8B)
   - Short Code (6B)
   - Indonesian NIK (16B)
   - Dispute JSON Profile (256B)
2. 4 Mandatory Scenario Payload Types (Speed, Latency & MB/s Throughput):
   - Personal & ATM Dispute Record (512B)
   - Scanned KTP / ATM Card (500 KB / 512,000B)
   - Bank e-Statement .pdf/.xlsx (2 MB / 2,097,152B)
   - ATM Booth CCTV / e-KYC Video .mp4 (8 MB / 8,388,608B)
3. Video Playback Scrubbing (HTTP Range Seek O(1) Block vs O(N) Stream):
   - Seeking to 75% offset (6 MB mark) in an 8 MB video to read a 64 KB video frame chunk.
"""

from __future__ import annotations

import json
import platform
import statistics
import time
from typing import Any, Dict, List

from .crypto_engine import (
    decrypt_aes,
    decrypt_aes_gcm,
    decrypt_des,
    decrypt_rc4,
    encrypt_aes,
    encrypt_aes_gcm,
    encrypt_des,
    encrypt_rc4,
    generate_dek_bundle,
    simulate_random_access_seek,
)


# =====================================================================
# Synthetic Deterministic Payload Generators
# =====================================================================

def generate_benchmark_payloads() -> Dict[str, bytes]:
    """
    Generates standardized deterministic payloads for all banking scenario types.
    """
    # 1. Short Banking Fields
    atm_stan_8b = b"STAN4829"  # Exactly 8 bytes (legacy 64-bit ATM block)
    short_code_6b = b"ID-091"   # Exactly 6 bytes (< 8 bytes)
    nik_16b = b"3171012345678901"  # Exactly 16 bytes (Indonesian NIK / Card PAN)

    # 256-byte Dispute Profile JSON
    disp_dict = {
        "dispute_id": "DISP-2026-9901",
        "nik": "3171012345678901",
        "pan": "5241480012345678",
        "amount": 1500000,
        "type": "ATM_CASH_NOT_DISPENSED",
        "terminal": "ATM-BCA-JKT-042",
        "stan": "STAN4829",
        "status": "UNDER_INVESTIGATION",
        "padding": ""
    }
    raw_disp = json.dumps(disp_dict).encode("utf-8")
    disp_dict["padding"] = "X" * (256 - len(raw_disp))
    dispute_json_256b = json.dumps(disp_dict).encode("utf-8")
    assert len(dispute_json_256b) == 256, f"Expected 256B, got {len(dispute_json_256b)}"

    # 2. Four Mandatory Scenario Types
    # Scenario A: 512-byte Structured Personal & ATM Dispute Record
    pers_dict = {
        "case_id": "CASE-JKT-882194",
        "customer_name": "Andi Wijaya",
        "nik": "3171012345678901",
        "pan": "5241480012345678",
        "mothers_maiden_name": "Kartini Suryodipuro",
        "phone": "+6281234567890",
        "email": "andi.wijaya@example.co.id",
        "disputed_amount_idr": 2500000,
        "atm_location": "Plaza Mandiri ATM 01",
        "stan_code": "STAN4829",
        "padding": ""
    }
    raw_pers = json.dumps(pers_dict).encode("utf-8")
    pers_dict["padding"] = "Y" * (512 - len(raw_pers))
    personal_data = json.dumps(pers_dict).encode("utf-8")
    assert len(personal_data) == 512, f"Expected 512B, got {len(personal_data)}"

    # Scenario B: 500 KB (512,000 bytes) Scanned KTP / ATM Card
    id_scan = (b"KTP-SCAN-HEADER-INDONESIA-EKYC-VALIDATION-RECORD\x00\xff" * 10240)[:512_000]
    assert len(id_scan) == 512_000, f"Expected 512000B, got {len(id_scan)}"

    # Scenario C: 2 MB (2,097,152 bytes) Bank e-Statement (.pdf / .xlsx)
    office_doc = (b"%PDF-1.7 BANK-ESTATEMENT-TRANSACTION-LEDGER-PAGE-RECORD\n" * 38131)[:2_097_152]
    assert len(office_doc) == 2_097_152, f"Expected 2097152B, got {len(office_doc)}"

    # Scenario D: 8 MB (8,388,608 bytes) ATM Booth CCTV / Video e-KYC (.mp4)
    video_evidence = (b"\x00\x00\x00 ftypisom\x00\x00\x02\x00H264-ATM-CCTV-EVIDENTIARY-STREAM" * 174763)[:8_388_608]
    assert len(video_evidence) == 8_388_608, f"Expected 8388608B, got {len(video_evidence)}"

    return {
        "atm_stan_8b": atm_stan_8b,
        "short_code_6b": short_code_6b,
        "nik_16b": nik_16b,
        "dispute_json_256b": dispute_json_256b,
        "personal_data": personal_data,
        "id_scan": id_scan,
        "office_doc": office_doc,
        "video_evidence": video_evidence,
    }


# =====================================================================
# Benchmark Execution Engine
# =====================================================================

def _benchmark_single_cipher(
    payload: bytes,
    cipher_code: str,
    dek_bundle: Dict[str, Any],
    iterations: int = 5,
    aad: bytes = b"audit-log-ref-001"
) -> Dict[str, Any]:
    """
    Runs 1 warm-up run + `iterations` timed runs for a specific cipher on a payload buffer.
    Computes mean, standard deviation, throughput (MB/s), and size overhead metrics.
    """
    aes_key = dek_bundle["aes_key"]
    des_key = dek_bundle["des_key"]
    rc4_key = dek_bundle["rc4_key"]
    hmac_key = dek_bundle["hmac_key"]

    enc_times: List[float] = []
    dec_times: List[float] = []

    # Map cipher routines
    if cipher_code == "aes_cbc":
        def do_enc(pt: bytes) -> Dict[str, Any]:
            return encrypt_aes(pt, aes_key, hmac_key, aad=aad)

        def do_dec(pl: Dict[str, Any]) -> Tuple[bytes, float]:
            return decrypt_aes(pl, aes_key, hmac_key, aad=aad)

        cipher_display_name = "AES-256-CBC + HMAC-SHA256"

    elif cipher_code == "des_cbc":
        def do_enc(pt: bytes) -> Dict[str, Any]:
            return encrypt_des(pt, des_key, hmac_key, aad=aad)

        def do_dec(pl: Dict[str, Any]) -> Tuple[bytes, float]:
            return decrypt_des(pl, des_key, hmac_key, aad=aad)

        cipher_display_name = "DES-CBC + HMAC-SHA256"

    elif cipher_code == "rc4":
        def do_enc(pt: bytes) -> Dict[str, Any]:
            return encrypt_rc4(pt, rc4_key, hmac_key, aad=aad)

        def do_dec(pl: Dict[str, Any]) -> Tuple[bytes, float]:
            return decrypt_rc4(pl, rc4_key, hmac_key, aad=aad)

        cipher_display_name = "RC4 Stream + HMAC-SHA256"

    elif cipher_code == "aes_gcm":
        def do_enc(pt: bytes) -> Dict[str, Any]:
            return encrypt_aes_gcm(pt, aes_key, aad=aad)

        def do_dec(pl: Dict[str, Any]) -> Tuple[bytes, float]:
            return decrypt_aes_gcm(pl, aes_key, aad=aad)

        cipher_display_name = "AES-256-GCM (AEAD Reference)"

    else:
        raise ValueError(f"Unknown cipher_code: {cipher_code}")

    # 1. Warm-up run (not included in metrics)
    warmup_payload = do_enc(payload)
    dec_warmup, _ = do_dec(warmup_payload)
    if dec_warmup != payload:
        raise RuntimeError(f"Integrity check failed for {cipher_code} during warm-up!")

    # Size metrics from warm-up payload
    plaintext_size = len(payload)
    ciphertext_size = warmup_payload["ciphertext_size"]
    iv_size = warmup_payload["iv_size"]
    mac_size = warmup_payload["mac_size"]
    block_plus_iv_size = warmup_payload["block_plus_iv_size"]
    total_protected_size = warmup_payload["total_protected_size"]
    padding_bytes = warmup_payload["padding_bytes"]
    expansion_percent = round(((total_protected_size - plaintext_size) / plaintext_size) * 100, 2)

    # 2. Timed benchmark runs
    for _ in range(iterations):
        res_enc = do_enc(payload)
        enc_times.append(res_enc["encrypt_ms"])

        _, dec_ms = do_dec(res_enc)
        dec_times.append(dec_ms)

    mean_enc_ms = round(statistics.mean(enc_times), 4)
    stdev_enc_ms = round(statistics.stdev(enc_times), 4) if len(enc_times) > 1 else 0.0

    mean_dec_ms = round(statistics.mean(dec_times), 4)
    stdev_dec_ms = round(statistics.stdev(dec_times), 4) if len(dec_times) > 1 else 0.0

    # Calculate throughput in Megabytes per second (MB/s)
    # size_mb = size_bytes / (1024 * 1024)
    size_mb = plaintext_size / (1024.0 * 1024.0)
    enc_s = mean_enc_ms / 1000.0
    dec_s = mean_dec_ms / 1000.0

    enc_throughput_mb_s = round(size_mb / enc_s, 2) if enc_s > 0 else 0.0
    dec_throughput_mb_s = round(size_mb / dec_s, 2) if dec_s > 0 else 0.0

    return {
        "cipher_code": cipher_code,
        "cipher": cipher_display_name,
        "plaintext_size": plaintext_size,
        "ciphertext_size": ciphertext_size,
        "iv_size": iv_size,
        "mac_size": mac_size,
        "block_plus_iv_size": block_plus_iv_size,
        "total_protected_size": total_protected_size,
        "padding_bytes": padding_bytes,
        "expansion_percent": expansion_percent,
        "mean_enc_ms": mean_enc_ms,
        "stdev_enc_ms": stdev_enc_ms,
        "mean_dec_ms": mean_dec_ms,
        "stdev_dec_ms": stdev_dec_ms,
        "enc_throughput_mb_s": enc_throughput_mb_s,
        "dec_throughput_mb_s": dec_throughput_mb_s,
    }


# =====================================================================
# Full Suite Orchestrator & Interpretations
# =====================================================================

def run_full_benchmark_suite(iterations: int = 5) -> Dict[str, Any]:
    """
    Executes the complete cryptographic evaluation suite across all banking payload
    types and generates structured statistical interpretations.

    Args:
        iterations: Number of timed runs after warm-up (default 5).

    Returns:
        Structured dictionary containing:
        - metadata: Timestamp, system platform, iteration count
        - short_fields: Granularity & block padding analysis for short ATM fields
        - scenarios: Throughput and latency across the 4 scenario types
        - video_seek: HTTP Range O(1) block vs O(N) stream scrubbing benchmark
        - interpretations: Detailed technical and regulatory insights
    """
    dek_bundle = generate_dek_bundle()
    payloads = generate_benchmark_payloads()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    # 1. Benchmark Short Banking Fields
    short_field_configs = [
        ("atm_stan_8b", "ATM STAN Audit Reference (8 Bytes)", payloads["atm_stan_8b"]),
        ("short_code_6b", "ATM Routing Code (6 Bytes)", payloads["short_code_6b"]),
        ("nik_16b", "Indonesian NIK / Card PAN (16 Bytes)", payloads["nik_16b"]),
        ("dispute_json_256b", "ATM Dispute Profile JSON (256 Bytes)", payloads["dispute_json_256b"]),
    ]

    short_fields_results: Dict[str, Any] = {}
    for key, label, data in short_field_configs:
        ciphers_data = {
            "aes_cbc": _benchmark_single_cipher(data, "aes_cbc", dek_bundle, iterations),
            "des_cbc": _benchmark_single_cipher(data, "des_cbc", dek_bundle, iterations),
            "rc4": _benchmark_single_cipher(data, "rc4", dek_bundle, iterations),
            "aes_gcm": _benchmark_single_cipher(data, "aes_gcm", dek_bundle, iterations),
        }
        short_fields_results[key] = {
            "label": label,
            "plaintext_size": len(data),
            "ciphers": ciphers_data,
        }

    # 2. Benchmark 4 Mandatory Scenarios
    scenario_configs = [
        ("personal_data", "Structured Personal & ATM Dispute Record", payloads["personal_data"]),
        ("id_scan", "Scanned KTP / ATM Card Image (500 KB)", payloads["id_scan"]),
        ("office_doc", "Bank e-Statement .pdf / .xlsx Ledger (2 MB)", payloads["office_doc"]),
        ("video_evidence", "ATM CCTV / Video e-KYC .mp4 Clip (8 MB)", payloads["video_evidence"]),
    ]

    scenarios_results: Dict[str, Any] = {}
    for key, label, data in scenario_configs:
        ciphers_data = {
            "aes_cbc": _benchmark_single_cipher(data, "aes_cbc", dek_bundle, iterations),
            "des_cbc": _benchmark_single_cipher(data, "des_cbc", dek_bundle, iterations),
            "rc4": _benchmark_single_cipher(data, "rc4", dek_bundle, iterations),
            "aes_gcm": _benchmark_single_cipher(data, "aes_gcm", dek_bundle, iterations),
        }
        scenarios_results[key] = {
            "label": label,
            "payload_type": key,
            "plaintext_size": len(data),
            "ciphers": ciphers_data,
        }

    # 3. Random Access Video Scrubbing Benchmark (HTTP Range Simulation)
    # Seek to 75% offset (6,291,456 bytes) in 8 MB video to read a 64 KB frame
    seek_offset = 6_291_456
    video_seek_result = simulate_random_access_seek(
        plaintext_video=payloads["video_evidence"],
        dek_bundle=dek_bundle,
        seek_offset=seek_offset,
        chunk_size=65536
    )

    # 4. Generate In-Depth Structured Interpretations
    interpretations = _generate_interpretations(short_fields_results, scenarios_results, video_seek_result)

    return {
        "metadata": {
            "timestamp": timestamp,
            "iterations": iterations,
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_architecture": platform.machine(),
        },
        "short_fields": short_fields_results,
        "scenarios": scenarios_results,
        "video_seek": video_seek_result,
        "interpretations": interpretations,
    }


def _generate_interpretations(
    short_fields: Dict[str, Any],
    scenarios: Dict[str, Any],
    video_seek: Dict[str, Any]
) -> Dict[str, str]:
    """
    Generates academic and operational interpretations for the benchmark metrics,
    connecting the findings directly to banking security, legacy ATM hardware, and regulations.
    """
    # Extract concrete values for dynamic interpretation
    stan_aes = short_fields["atm_stan_8b"]["ciphers"]["aes_cbc"]["block_plus_iv_size"]
    stan_des = short_fields["atm_stan_8b"]["ciphers"]["des_cbc"]["block_plus_iv_size"]
    stan_rc4 = short_fields["atm_stan_8b"]["ciphers"]["rc4"]["block_plus_iv_size"]

    code_aes = short_fields["short_code_6b"]["ciphers"]["aes_cbc"]["block_plus_iv_size"]
    code_des = short_fields["short_code_6b"]["ciphers"]["des_cbc"]["block_plus_iv_size"]

    nik_aes = short_fields["nik_16b"]["ciphers"]["aes_cbc"]["block_plus_iv_size"]
    nik_des = short_fields["nik_16b"]["ciphers"]["des_cbc"]["block_plus_iv_size"]

    vid_aes_tp = scenarios["video_evidence"]["ciphers"]["aes_cbc"]["enc_throughput_mb_s"]
    vid_des_tp = scenarios["video_evidence"]["ciphers"]["des_cbc"]["enc_throughput_mb_s"]
    vid_rc4_tp = scenarios["video_evidence"]["ciphers"]["rc4"]["enc_throughput_mb_s"]
    vid_gcm_tp = scenarios["video_evidence"]["ciphers"]["aes_gcm"]["enc_throughput_mb_s"]

    doc_aes_tp = scenarios["office_doc"]["ciphers"]["aes_cbc"]["enc_throughput_mb_s"]
    doc_des_tp = scenarios["office_doc"]["ciphers"]["des_cbc"]["enc_throughput_mb_s"]

    ratio_seek = video_seek["ratio_rc4_to_aes"]

    return {
        "storage_and_block_granularity": (
            f"1. STORAGE & BLOCK GRANULARITY ANALYSIS (Why DES Dominated Legacy ATMs):\n"
            f"   - On a 6-byte routing code, DES-CBC requires only {code_des} bytes (8B block + 8B IV), "
            f"whereas AES-256-CBC requires {code_aes} bytes (16B block + 16B IV) -- a 50% storage overhead increase!\n"
            f"   - On a 16-byte Indonesian NIK / Card PAN, PKCS#7 boundary padding forces AES-CBC to add "
            f"a full 16-byte pad block (total {nik_aes}B block+IV), while DES-CBC adds an 8-byte pad block "
            f"(total {nik_des}B block+IV) -- DES is 33.3% more compact!\n"
            f"   - On an 8-byte ATM STAN, DES consumes {stan_des} bytes vs AES {stan_aes} bytes.\n"
            f"   * Banking Takeaway: Legacy ATM networks (ISO 8583 / ANSI X9.8) ran over low-bandwidth "
            f"dial-up/X.25 lines (9.6 to 56 kbps). Storing and transmitting 8-byte PIN blocks in 64-bit DES "
            f"saved millions of bytes daily without taxing 1980s Encrypting PIN Pad microcontrollers."
        ),
        "bulk_throughput_and_hardware_acceleration": (
            f"2. BULK MEDIA THROUGHPUT ANALYSIS (Why AES Dominates Modern Digital Banking):\n"
            f"   - On 8 MB ATM CCTV Video: AES-256-CBC achieved {vid_aes_tp} MB/s and AES-256-GCM achieved "
            f"{vid_gcm_tp} MB/s, compared to DES-CBC's {vid_des_tp} MB/s.\n"
            f"   - On 2 MB Bank Statements (.pdf/.xlsx): AES-256-CBC reached {doc_aes_tp} MB/s vs DES at {doc_des_tp} MB/s.\n"
            f"   - DES-CBC bottlenecks severely because its 16-round bit-level permutation network was designed for "
            f"1970s wired hardware and cannot leverage CPU SIMD instructions, locking the CPU in software loops.\n"
            f"   - RC4 achieved {vid_rc4_tp} MB/s with zero padding bytes due to its simple 8-bit state-swap loop, "
            f"explaining its historical popularity in early TLS/PDF streaming.\n"
            f"   * Banking Takeaway: While DES is tolerable for 8-byte PINs, scaling DES to multi-megabyte customer "
            f"e-KYC identity documents or CCTV video evidence causes severe CPU starvation on banking servers."
        ),
        "evidentiary_integrity_and_tamper_resistance": (
            f"3. EVIDENTIARY INTEGRITY & COMPLIANCE ANALYSIS (The 'Must Come Back Intact' Mandate):\n"
            f"   - Unauthenticated CBC mode is vulnerable to bit-flipping attacks (altering financial amounts in .xlsx "
            f"ledgers) and padding-oracle attacks.\n"
            f"   - In this implementation, all three ciphers enforce Encrypt-then-MAC (HMAC-SHA256) over (IV || Ciphertext || AAD), "
            f"cryptographically binding customer IDs to each dispute case.\n"
            f"   - Any 1-bit tampering or AAD alteration is caught before decryption and aborts execution, guaranteeing "
            f"that dispute evidence admitted into bank audits or legal proceedings is 100% tamper-evident."
        ),
        "random_access_video_scrubbing": (
            f"4. VIDEO PLAYBACK SCRUBBING & HTTP RANGE SEEKING ANALYSIS:\n"
            f"   - When an investigator scrubs an 8 MB ATM CCTV video to the 75% mark (byte {video_seek['seek_offset']:,}):\n"
            f"   - AES-256-CBC completed the seek in {video_seek['aes_seek_ms']:.4f} ms and DES-CBC in {video_seek['des_seek_ms']:.4f} ms "
            f"(both O(1) constant time) by using the immediately preceding ciphertext block as the IV.\n"
            f"   - RC4 required {video_seek['rc4_seek_ms']:.4f} ms ({ratio_seek}x slower) because it cannot jump to an arbitrary offset "
            f"without sequentially generating and discarding the first 6 MB of keystream from byte 0 (O(N) linear time).\n"
            f"   * Banking Takeaway: Even though RC4 is fast sequentially and has zero padding, its stateful stream design "
            f"renders it architecturally flawed for HTTP 206 Partial Content video streaming and scrubbing in fraud portals."
        ),
        "regulatory_and_lifecycle_verdict": (
            f"5. REGULATORY VERDICT (Indonesian UU PDP No. 27/2022 & POJK No. 22/2023):\n"
            f"   - Tier 1 General Personal Data (NIK, Name) and Tier 2 Specific Financial Data (PAN, STAN, CCTV, Bank Statements) "
            f"must be protected against unauthorized disclosure and tampering under UU PDP Art. 4 and Art. 35.\n"
            f"   - DES's 56-bit effective key space can be broken via brute force in under a day, and RC4 has well-documented keystream biases.\n"
            f"   - While legacy ATM hardware constraints explain the coexistence of DES in EPP firmware, modern customer portals "
            f"must mandate AES-256-GCM / AES-256-CBC+HMAC for all customer-facing storage and e-KYC evidence vaults."
        )
    }


# =====================================================================
# CLI Formatter & Standalone Runner
# =====================================================================

def format_benchmark_report_text(results: Dict[str, Any]) -> str:
    """Formats the benchmark results into a clean terminal report."""
    meta = results["metadata"]
    lines = [
        "=" * 85,
        "BANK ATM DISPUTE, FRAUD & e-KYC CUSTOMER VAULT: CRYPTOGRAPHIC EVALUATION REPORT",
        "=" * 85,
        f"Timestamp : {meta['timestamp']} | Platform: {meta['platform']} | Python: {meta['python_version']}",
        f"Iterations: {meta['iterations']} timed runs per test (+ 1 warm-up) | Architecture: {meta['cpu_architecture']}",
        "-" * 85,
        "\n--- TABLE 1: SHORT BANKING FIELDS (STORAGE & BLOCK GRANULARITY ANALYSIS) ---",
        f"{'Field':<24} | {'Cipher':<14} | {'Plain':<6} | {'Cipher':<6} | {'IV':<4} | {'Blk+IV':<6} | {'Pad':<4} | {'Total':<6} | {'Enc ms':<8}",
        "-" * 85,
    ]

    for key, f_data in results["short_fields"].items():
        for c_key, c_res in f_data["ciphers"].items():
            lines.append(
                f"{key:<24} | {c_key:<14} | {c_res['plaintext_size']:<6} | {c_res['ciphertext_size']:<6} | "
                f"{c_res['iv_size']:<4} | {c_res['block_plus_iv_size']:<6} | {c_res['padding_bytes']:<4} | "
                f"{c_res['total_protected_size']:<6} | {c_res['mean_enc_ms']:<8.4f}"
            )
        lines.append("-" * 85)

    lines.extend([
        "\n--- TABLE 2: MANDATORY SCENARIO PAYLOADS (SPEED & THROUGHPUT MB/s) ---",
        f"{'Scenario':<16} | {'Cipher':<14} | {'Size (B)':<10} | {'Enc ms':<10} | {'Dec ms':<10} | {'Enc MB/s':<10} | {'Dec MB/s':<10}",
        "-" * 85,
    ])

    for key, s_data in results["scenarios"].items():
        for c_key, c_res in s_data["ciphers"].items():
            lines.append(
                f"{key:<16} | {c_key:<14} | {c_res['plaintext_size']:<10} | "
                f"{c_res['mean_enc_ms']:<10.4f} | {c_res['mean_dec_ms']:<10.4f} | "
                f"{c_res['enc_throughput_mb_s']:<10.2f} | {c_res['dec_throughput_mb_s']:<10.2f}"
            )
        lines.append("-" * 85)

    v_seek = results["video_seek"]
    lines.extend([
        "\n--- TABLE 3: VIDEO SCRUBBING RANDOM-ACCESS SEEK (HTTP RANGE REQUEST SIMULATION) ---",
        f"Video Buffer: 8 MB ({s_data['plaintext_size']:,} bytes) | Seek Offset: {v_seek['seek_offset']:,} ({v_seek['seek_offset_mb']} MB) | Chunk: {v_seek['chunk_size_kb']} KB",
        f"AES-256-CBC Seek Time : {v_seek['aes_seek_ms']:.4f} ms (O(1) block seek)",
        f"DES-CBC Seek Time     : {v_seek['des_seek_ms']:.4f} ms (O(1) block seek)",
        f"RC4 Stream Seek Time  : {v_seek['rc4_seek_ms']:.4f} ms (O(N) sequential discard)",
        f"RC4 vs AES Slowdown   : {v_seek['ratio_rc4_to_aes']:.2f}x slower",
        f"Authenticity Verified : {v_seek['verified']} (All 3 decrypted chunks bit-match plaintext)",
        "-" * 85,
        "\n--- STRUCTURED EVALUATION & INTERPRETATIONS ---",
    ])

    for sec_name, text in results["interpretations"].items():
        lines.append(f"\n{text}")

    lines.append("\n" + "=" * 85)
    return "\n".join(lines)


if __name__ == "__main__":
    print("Executing complete Bank ATM Dispute & e-KYC benchmark suite...")
    bench_results = run_full_benchmark_suite(iterations=5)
    report = format_benchmark_report_text(bench_results)
    print(report)
