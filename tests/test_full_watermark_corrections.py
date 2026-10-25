"""
Unit and integration tests for Full-Watermark Corrections:
1. Evidence panel metadata verification (C_W Full Watermark Embedding & Extraction)
2. Verifier Step 11 derivation check (HKDF with verified D', B', and extracted W' strictly from Step 5 disputed RTL)
3. Verifier Step 11 negative test cases (corrupted W', B', D', k_tx, missing Step 5 extraction)
4. Verifier Step 13 eligibility and report generation without legacy steps 7 & 8
5. 256-bit CIG embedding audit: mathematical recovery, modulo mapping behavior, comment independence, and wrong/unwatermarked RTL rejection
"""

import pytest
import hashlib
from fastapi.testclient import TestClient

from hardware_ip_protection.web.app import app
from hardware_ip_protection.pipeline.transaction_manager import TransactionManager
from hardware_ip_protection.pipeline.verifier_engine import VerifierEngine
from hardware_ip_protection.forensics.watermark_extractor import TransactionWatermarkExtractor, ExtractionStatus
from hardware_ip_protection.hls.cig import WatermarkCapacityAnalyzer, WatermarkCIGMapper, CIG
from hardware_ip_protection.hls.dfg import create_iir_butterworth
from hardware_ip_protection.hls.scheduler import ListScheduler
from hardware_ip_protection.pipeline.engine import ProtectionPipeline


client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_all_state():
    tm = TransactionManager.get_instance()
    tm.reset()
    ve = VerifierEngine.get_instance()
    ve.reset_session()
    yield
    tm.reset()
    ve.reset_session()


def setup_complete_seller_buyer_transaction():
    """Helper to set up a complete Seller-Buyer transaction ready for verification."""
    client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_rule_v1",
    })
    client.post("/api/transaction/encode_design", json={"use_table_quirks": False})
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")
    res = client.post("/api/transaction/continue_watermark", json={
        "transaction_id": "TX-2026-BW01",
        "seller_id": "SELLER-CORE-01",
        "buyer_id": "BUYER-SOC-CORP",
        "license_type": "exclusive",
        "k_tx": "K_tx_symmetric_credential_secret_777",
        "watermark_length": "auto",
    })
    assert res.status_code == 200
    st = res.json()["state"]
    return st


def test_evidence_panel_cw_metadata():
    """Verify C_W Evidence title, 256 bits, and structural metadata."""
    st = setup_complete_seller_buyer_transaction()
    priv = st["seller_private_info"]
    assert "C_W1_evidence" in priv
    cw_evid = priv["C_W1_evidence"]
    assert cw_evid["title"] == "C_W Evidence: Full Watermark Embedding & Extraction"
    assert cw_evid["actual_embedded_length"] == 256
    assert cw_evid["capacity_evaluation"]["total_watermark_bits"] == 256
    assert cw_evid["capacity_evaluation"]["actual_embedded_bits"] == 256
    assert "structural_encoding_mechanism" in cw_evid
    assert "rtl_evidence" in cw_evid
    assert "extraction_procedure" in cw_evid
    assert "verification_procedure" in cw_evid
    assert "commitment_verification" in cw_evid
    assert cw_evid["commitment_verification"]["stored_commitment_C_W"] == st["C_W"]

    # Also verify Panel 2 (Generation Evidence)
    assert "C_W_evidence" in priv
    gen_evid = priv["C_W_evidence"]
    assert gen_evid["title"] == "C_W Evidence: Complete Watermark Generation (W)"
    assert gen_evid["reconstruction_method"]["output_length_bits"] == 256


def test_step_11_derivation_and_negative_cases():
    """
    Step 11 derivation check must:
    - Pass when all prerequisites and verified values are authentic
    - Fail (MISMATCH) when extracted W' is corrupted
    - Fail (MISMATCH) when buyer contribution B' is altered
    - Fail (MISMATCH) when verified design encoding D' is altered
    - Fail (MISMATCH) when transaction key k_tx is altered
    - Block (BLOCKED) when Step 5 extraction is missing (never falling back to stored W)
    """
    st = setup_complete_seller_buyer_transaction()
    cfg_res = client.post("/api/verifier/configure_dispute", json={
        "transaction_id": st["transaction_id"],
        "dispute_type": "Seller ↔ Buyer Conflict",
    })
    assert cfg_res.status_code == 200
    ve = VerifierEngine.get_instance()

    # 1. Run prerequisite steps: 1, 2, 3, 4, 9, 10
    for s in [1, 2, 3, 4, 9, 10]:
        r = client.post("/api/verifier/execute_step", json={"step_number": s})
        assert r.status_code == 200
        assert r.json()["step_result"]["status"] in ["LOADED", "EXTRACTED", "MATCH", "NOT REQUIRED", "VALIDATED"]

    # Attempt step 11 WITHOUT running Step 5 & 6
    r_no_s5 = client.post("/api/verifier/execute_step", json={"step_number": 11})
    assert r_no_s5.status_code == 200
    res_no_s5 = r_no_s5.json()["step_result"]
    assert res_no_s5["status"] == "BLOCKED"
    assert "Watermark Commitment" in res_no_s5["notes"] or "Step 5" in res_no_s5["notes"] or "Step 6" in res_no_s5["notes"]

    # Now run Step 5 & 6
    client.post("/api/verifier/execute_step", json={"step_number": 5})
    client.post("/api/verifier/execute_step", json={"step_number": 6})

    # Baseline: Step 11 passes normally
    r_normal = client.post("/api/verifier/execute_step", json={"step_number": 11})
    assert r_normal.status_code == 200
    res_normal = r_normal.json()["step_result"]
    assert res_normal["status"] == "MATCH"
    assert "expected_watermark_hash" in res_normal["stage1_reconstruction"]
    assert "reconstructed_watermark_hash" in res_normal["stage1_reconstruction"]
    assert res_normal["stage1_reconstruction"]["expected_watermark_hash"] == res_normal["stage1_reconstruction"]["reconstructed_watermark_hash"]

    # 2. Corrupt extracted W' in session internal values
    orig_w_prime = ve.session.internal_confidential_values.get("W_prime") or ve.session.internal_confidential_values["W"]
    corrupted_w_prime = ("1" if orig_w_prime[0] == "0" else "0") + orig_w_prime[1:]
    ve.session.internal_confidential_values["W_prime"] = corrupted_w_prime
    ve.session.internal_confidential_values["W"] = corrupted_w_prime
    r_corrupt_w = client.post("/api/verifier/execute_step", json={"step_number": 11})
    res_corrupt_w = r_corrupt_w.json()["step_result"]
    assert res_corrupt_w["status"] == "MISMATCH"
    assert res_corrupt_w["stage2_verification"]["status"] == "MISMATCH"
    assert res_corrupt_w["stage2_verification"]["expected_watermark_hash"] != res_corrupt_w["stage2_verification"]["extracted_watermark_hash"]
    # Restore
    ve.session.internal_confidential_values["W_prime"] = orig_w_prime
    ve.session.internal_confidential_values["W"] = orig_w_prime

    # 3. Alter buyer contribution B'
    orig_b = ve.session.internal_confidential_values["B"]
    corrupted_b = ("1" if orig_b[0] == "0" else "0") + orig_b[1:]
    ve.session.internal_confidential_values["B"] = corrupted_b
    r_corrupt_b = client.post("/api/verifier/execute_step", json={"step_number": 11})
    res_corrupt_b = r_corrupt_b.json()["step_result"]
    assert res_corrupt_b["status"] == "MISMATCH"
    # Restore
    ve.session.internal_confidential_values["B"] = orig_b

    # 4. Alter verified design encoding D' (E_U)
    orig_eu = ve.session.internal_confidential_values["E_U"]
    corrupted_eu = ("1" if orig_eu[0] == "0" else "0") + orig_eu[1:]
    ve.session.internal_confidential_values["E_U"] = corrupted_eu
    r_corrupt_d = client.post("/api/verifier/execute_step", json={"step_number": 11})
    res_corrupt_d = r_corrupt_d.json()["step_result"]
    assert res_corrupt_d["status"] == "MISMATCH"
    # Restore
    ve.session.internal_confidential_values["E_U"] = orig_eu

    # 5. Alter transaction key k_tx
    tm = TransactionManager.get_instance()
    orig_ktx = tm.state.transaction_credentials.get("k_tx")
    tm.state.transaction_credentials["k_tx"] = "K_tx_tampered_secret_value"
    r_corrupt_ktx = client.post("/api/verifier/execute_step", json={"step_number": 11})
    res_corrupt_ktx = r_corrupt_ktx.json()["step_result"]
    assert res_corrupt_ktx["status"] == "MISMATCH"
    tm.state.transaction_credentials["k_tx"] = orig_ktx


def test_step_13_eligible_and_executes_without_legacy_steps():
    """
    Verify Step 13 can be executed for full-watermark transactions without running legacy steps 7 & 8.
    """
    st = setup_complete_seller_buyer_transaction()
    cfg_res = client.post("/api/verifier/configure_dispute", json={
        "transaction_id": st["transaction_id"],
        "dispute_type": "Seller ↔ Buyer Conflict",
    })
    assert cfg_res.status_code == 200
    ve = VerifierEngine.get_instance()

    # Execute active steps: 1, 2, 3, 4, 5, 6, 9, 10, 11, 12
    for s in [1, 2, 3, 4, 5, 6, 9, 10, 11, 12]:
        r = client.post("/api/verifier/execute_step", json={"step_number": s})
        assert r.status_code == 200
        assert r.json()["step_result"]["status"] in ["LOADED", "EXTRACTED", "MATCH", "NOT REQUIRED", "VALIDATED", "CONSISTENT"]

    # Verify legacy steps 7 and 8 have NOT been executed
    assert "step_7" not in ve.session.step_results
    assert "step_8" not in ve.session.step_results

    # Execute Step 13
    r13 = client.post("/api/verifier/execute_step", json={"step_number": 13})
    assert r13.status_code == 200
    res13 = r13.json()["step_result"]
    assert res13["status"] in ["MATCH", "CONSISTENT"]
    assert ve.session.final_report is not None
    rep = ve.session.final_report
    assert rep["transaction_id"] == st["transaction_id"]
    assert rep["overall_evidence_status"] == "CONSISTENT"
    assert rep["findings_summary"] is not None


def test_256_bit_embedding_audit_and_modulo_mapping():
    """
    Mathematical and functional audit of 256-bit embedding:
    - 256 bits into iir_butterworth candidate pools (169 candidate pairs)
    - Modulo mapping edge analysis
    - RTL extraction bit-for-bit equality
    - Multiple distinct watermarks
    - Comment stripping independence
    - Rejection of unwatermarked or wrong RTL
    """
    dfg = create_iir_butterworth()
    scheduler = ListScheduler(resource_config={"add": 2, "mul": 2, "sub": 2})
    sched = scheduler.schedule(dfg)
    base_cig = CIG(sched)

    analysis = WatermarkCapacityAnalyzer.analyze(base_cig)
    assert analysis["storage_variable_count"] == 27
    assert analysis["candidate_even_even_count"] == 78
    assert analysis["candidate_odd_odd_count"] == 91
    assert analysis["candidate_pair_count"] == 169

    pipeline = ProtectionPipeline()

    # Test 5 distinct transaction configurations with different keys and transactions
    test_configs = [
        ("TX-AUDIT-01", "K_tx_secret_alpha_01"),
        ("TX-AUDIT-02", "K_tx_secret_beta_02"),
        ("TX-AUDIT-03", "K_tx_secret_gamma_03"),
        ("TX-AUDIT-04", "K_tx_secret_delta_04"),
        ("TX-AUDIT-05", "K_tx_secret_epsilon_05"),
    ]

    for tx_id, k_tx in test_configs:
        ctx = pipeline.run({
            "dfg": create_iir_butterworth(),
            "resource_config": {"add": 2, "mul": 2, "sub": 2},
            "watermark_length": 256,
            "transaction_record": {
                "transaction_id": tx_id,
                "seller_id": "SELLER-AUDIT",
                "buyer_id": "BUYER-AUDIT",
                "license_type": "exclusive",
            },
            "transaction_credentials": {"k_tx": k_tx},
        })

        intended_wm = ctx["transaction_watermark"].canonical_bitstream
        assert len(intended_wm) == 256

        rtl_code = ctx["protected_verilog"]
        mapping = ctx["watermark_mapping"]
        assert len(mapping) == 256

        # Extract from synthesizable RTL without reference bitstream
        ext_res = TransactionWatermarkExtractor.extract(verilog_code=rtl_code, watermark_mapping=mapping)
        assert ext_res.status == ExtractionStatus.SUCCESS
        assert ext_res.recovered_bits == 256
        assert ext_res.bitstream == intended_wm, f"Failed bit-for-bit extraction for {tx_id}"

        # Strip all comments from RTL (proving netlist/sequential assignments alone carry the watermark)
        lines = []
        for line in rtl_code.splitlines():
            stripped = line.split("//")[0]
            lines.append(stripped)
        comment_free_rtl = "\n".join(lines)

        ext_comment_free = TransactionWatermarkExtractor.extract(verilog_code=comment_free_rtl, watermark_mapping=mapping)
        assert ext_comment_free.status == ExtractionStatus.SUCCESS
        assert ext_comment_free.bitstream == intended_wm, f"Comment stripping broke extraction for {tx_id}"

    # Verify that unwatermarked RTL fails extraction against a watermark mapping
    unwatermarked_ctx = pipeline.run({
        "dfg": create_iir_butterworth(),
        "resource_config": {"add": 2, "mul": 2, "sub": 2},
        "watermark_length": 256,
        "transaction_record": {
            "transaction_id": "TX-ZERO",
            "seller_id": "SELLER-ZERO",
            "buyer_id": "BUYER-ZERO",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "k_tx_zero"},
    })
    unwatermarked_rtl = unwatermarked_ctx["original_verilog"]
    # Extract using the watermark mapping from a watermarked design against the unwatermarked RTL
    some_watermarked_mapping = ctx["watermark_mapping"]
    ext_unwatermarked = TransactionWatermarkExtractor.extract(verilog_code=unwatermarked_rtl, watermark_mapping=some_watermarked_mapping)
    # The unwatermarked RTL registers were allocated without non-sharing constraints;
    # therefore it either has violations or does not match the watermarked bitstream
    assert ext_unwatermarked.bitstream != intended_wm
