"""
Comprehensive Test Suite for Verifier Profile & Step-by-Step Verify Dispute Workflow.

Covers tests A through K from Section 11 of the specification:
- Test A: No transaction (clean empty state, no false success)
- Test B: Valid Seller-Buyer transaction (13-step sequence completes with CONSISTENT)
- Test C: Secured encoding unchanged (E_S = D -> C_ES NOT REQUIRED, not fabricated)
- Test D: Secured encoding changed (C_ES verified before transformation; failure blocks bypass)
- Test E: Incorrect commitment opening (recaculated commitment != stored -> MISMATCH)
- Test F: Incorrect reconstruction rule (fails reconstruction or commitment check)
- Test G: Incorrect W1 or W2 (corrupted watermark bitstreams fail C_W1 or C_W)
- Test H: Incorrect Buyer contribution (wrong length/bits or wrong r_B fails C_B)
- Test I: Missing private evidence (BLOCKED / INCOMPLETE, no synthetic values)
- Test J: Incorrect transaction record (mismatched parties/IDs reported inconsistent)
- Test K: Reference vs Suspicious design (re-uses existing checks, structural similarity Level 3 as future capability)
"""

import pytest
import hashlib
import re
from fastapi.testclient import TestClient

from hardware_ip_protection.web.app import app
from hardware_ip_protection.pipeline.transaction_manager import (
    TransactionManager,
    DEMO_BUYER_BITSTREAM,
)
from hardware_ip_protection.pipeline.verifier_engine import VerifierEngine
from hardware_ip_protection.crypto.pedersen import PedersenEngine, CommitmentVerificationStatus


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
    # 1. Seller selects design and rule
    client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_rule_v1",
    })
    # 2. Seller encodes design D and generates C_D
    client.post("/api/transaction/encode_design", json={"use_table_quirks": False})
    # 3. Seller requests Buyer contribution
    client.post("/api/transaction/request_buyer")
    # 4. Buyer approves with 555-bit demonstration bitstream
    client.post("/api/transaction/approve_buyer")
    # 5. Seller continues watermark workflow
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
    assert st["watermarked_RTL"] is not None
    assert st["C_D"] is not None
    assert st["C_W"] is not None
    assert st["C_W1"] is not None
    assert st["C_B"] is not None
    return st


# ==============================================================================
# UI & Banner Integrity Test
# ==============================================================================
def test_verifier_ui_and_banner_integrity():
    """Verify that index.html contains required Verifier profile banner notice and elements."""
    with open("hardware_ip_protection/web/static/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    # Exact top explanation banner notice from Section 2
    required_notice = (
        "The Verifier independently reconstructs committed values using the supplied rules, "
        "then checks their commitments against the stored evidence. "
        "Verification results indicate consistency of evidence and do not independently establish legal ownership."
    )
    assert required_notice in html

    # Empty state notice from Section 3
    required_empty_notice = "No transaction is available for verification. Complete the Seller/Buyer transaction first."
    assert required_empty_notice in html

    # Verifier profile containers
    assert 'id="profileVerifier"' in html
    assert 'id="verifierTxSelect"' in html
    assert 'id="verifierDisputeType"' in html
    assert 'id="verifierDisputeSubcategory"' in html
    assert 'id="verifierSellerBuyerWorkspace"' in html
    assert 'id="verifierFinalReportCard"' in html
    assert 'id="vActiveStepBox"' in html
    assert 'id="vStage1Content"' in html
    assert 'id="vStage2Content"' in html


# ==============================================================================
# Test A: No transaction
# ==============================================================================
def test_test_a_no_transaction():
    """
    Open Verify Dispute without a transaction.
    Expected: clear empty state and no false successful results.
    """
    # 1. State check
    res = client.get("/api/verifier/state")
    assert res.status_code == 200
    data = res.json()
    assert len(data["available_transactions"]) == 0

    # 2. Attempting Step 1 when no transaction exists yields BLOCKED
    step1_res = client.post("/api/verifier/execute_step", json={"step_number": 1})
    assert step1_res.status_code == 200
    s1_data = step1_res.json()["step_result"]
    assert s1_data["status"] == "BLOCKED"
    assert "Missing disputed RTL artifact" in s1_data["notes"]

    # 3. Running all steps does not result in false success
    run_all_res = client.post("/api/verifier/run_all_steps", json={})
    assert run_all_res.status_code == 200
    sess = run_all_res.json()["session"]
    report = sess["final_report"]
    assert report is not None
    assert report["overall_evidence_status"] in ("BLOCKED", "INCOMPLETE", "INCONSISTENT")
    assert report["overall_evidence_status"] != "CONSISTENT"


# ==============================================================================
# Test B: Valid Seller-Buyer transaction
# ==============================================================================
def test_test_b_valid_seller_buyer_transaction():
    """
    Use the existing IIR Butterworth demonstration transaction.
    Expected: the Verifier follows the required 13-step sequence and records actual comparison results.
    """
    st = setup_complete_seller_buyer_transaction()

    # Configure dispute
    cfg_res = client.post("/api/verifier/configure_dispute", json={
        "transaction_id": st["transaction_id"],
        "dispute_type": "Seller ↔ Buyer Conflict",
        "dispute_subcategory": "Buyer claims ownership; recorded transaction may grant only a license.",
    })
    assert cfg_res.status_code == 200

    # Execute all 13 steps
    run_res = client.post("/api/verifier/run_all_steps", json={})
    assert run_res.status_code == 200
    sess = run_res.json()["session"]
    results = sess["step_results"]

    # Check Step 1: Disputed RTL
    assert results["step_1"]["status"] == "LOADED"
    assert results["step_1"]["stage1_reconstruction"]["status"] == "LOADED"

    # Check Step 2: Extract secured encoding E_S'
    assert results["step_2"]["status"] == "EXTRACTED"
    assert results["step_2"]["stage1_reconstruction"]["canonical_hash"] is not None
    assert results["step_2"]["stage1_reconstruction"]["bit_length"] == 143
    assert "secured_encoding_ES" not in results["step_2"]["stage1_reconstruction"]

    # Check Step 3: Encoding invariance
    assert results["step_3"]["status"] == "NOT REQUIRED"
    assert results["step_3"]["stage2_verification"]["status"] == "NOT REQUIRED"

    # Check Step 4: Verify original design encoding D' and C_D
    assert results["step_4"]["status"] == "MATCH"
    assert results["step_4"]["stage2_verification"]["status"] == "MATCH"

    # Check Step 5: Extract embedded watermark W'
    assert results["step_5"]["status"] == "EXTRACTED"
    assert results["step_5"]["stage1_reconstruction"]["bit_length"] == 256

    # Check Step 6: Verify C_W
    assert results["step_6"]["status"] == "MATCH"
    assert results["step_6"]["stage2_verification"]["status"] == "MATCH"

    # Check Step 7: Reconstruct complete watermark W' (NOT REQUIRED in full watermark model)
    assert results["step_7"]["status"] == "NOT REQUIRED"
    assert results["step_7"]["stage1_reconstruction"]["status"] == "NOT REQUIRED"

    # Check Step 8: Verify C_W (NOT REQUIRED in full watermark model)
    assert results["step_8"]["status"] == "NOT REQUIRED"
    assert results["step_8"]["stage2_verification"]["status"] == "NOT REQUIRED"

    # Check Step 9: Validate Buyer contribution B' (555 bits, 242 zeros, 313 ones)
    assert results["step_9"]["status"] == "MATCH"
    assert results["step_9"]["stage1_reconstruction"]["bit_length"] == 555
    assert results["step_9"]["stage1_reconstruction"]["zeros_count"] == 242
    assert results["step_9"]["stage1_reconstruction"]["ones_count"] == 313

    # Check Step 10: Verify C_B (Buyer-owned)
    assert results["step_10"]["status"] == "MATCH"
    assert results["step_10"]["responsible_party"] == "Buyer"
    assert results["step_10"]["stage2_verification"]["status"] == "MATCH"

    # Check Step 11: Verify watermark-generation relationship W' = F(D', B', context, k_tx)
    assert results["step_11"]["status"] == "MATCH"

    # Check Step 12: Verify transaction evidence & rights
    assert results["step_12"]["status"] == "MATCH"
    assert results["step_12"]["stage1_reconstruction"]["recorded_rights_type"] == "License"

    # Check Step 13: Final report
    assert sess["is_completed"] is True
    report = sess["final_report"]
    assert report["overall_evidence_status"] == "CONSISTENT"
    assert report["recorded_rights"] == "License"
    assert "Verification results indicate consistency of evidence and do not independently establish legal ownership." in report["legal_notice"]


# ==============================================================================
# Test C: Secured encoding unchanged (E_S = D)
# ==============================================================================
def test_test_c_secured_encoding_unchanged():
    """
    When E_S equals D, the Verifier skips the C_ES verification branch and continues to C_D.
    Expected: C_ES is NOT REQUIRED, not fabricated.
    """
    setup_complete_seller_buyer_transaction()
    ve = VerifierEngine.get_instance()

    ve.execute_step(1)
    ve.execute_step(2)
    res3 = ve.execute_step(3)

    assert res3.status == "NOT REQUIRED"
    assert res3.stage2_verification["status"] == "NOT REQUIRED"
    assert "NOT_APPLICABLE" in res3.stage2_verification["recalculated_C_ES"]
    assert res3.stage2_verification["stored_C_ES"] == "NOT_REQUIRED"

    # Continues directly to Step 4 without inventing a fake C_ES
    res4 = ve.execute_step(4)
    assert res4.status == "MATCH"


# ==============================================================================
# Test D: Secured encoding changed (Branch B)
# ==============================================================================
def test_test_d_secured_encoding_changed_branch_b():
    """
    When the implementation supports a changed encoding and C_ES, verify C_ES
    before applying the design-specific transformation.
    Expected: transformation is not used to bypass a failed C_ES check.
    """
    setup_complete_seller_buyer_transaction()
    ve = VerifierEngine.get_instance()

    ve.execute_step(1)
    ve.execute_step(2)

    # 1. Test changed encoding with valid C_ES and transformation rule
    pe = PedersenEngine()
    dummy_es = "1" * 143
    dummy_r_es = 12345678901234567890
    dummy_comm, _ = pe.commit(dummy_es, blinding_factor=dummy_r_es)
    dummy_c_es = dummy_comm.commitment_hex

    res_valid_branch = ve.execute_step(3, overrides={
        "is_encoding_changed": True,
        "extracted_ES": dummy_es,
        "stored_C_ES": dummy_c_es,
        "r_ES": hex(dummy_r_es)[2:],
        "transformation_rule_id": "iir_butterworth_transform_v1",
    })
    assert res_valid_branch.status == "MATCH"
    assert res_valid_branch.stage2_verification["status"] == "MATCH"
    assert res_valid_branch.stage1_reconstruction["transformation_applied"] is True

    # 2. Test changed encoding with BAD C_ES opening factor
    bad_r_es = hex(999999999)[2:]
    res_bad_c_es = ve.execute_step(3, overrides={
        "is_encoding_changed": True,
        "extracted_ES": dummy_es,
        "stored_C_ES": dummy_c_es,
        "r_ES": bad_r_es,
        "transformation_rule_id": "iir_butterworth_transform_v1",
    })
    assert res_bad_c_es.status == "MISMATCH"
    assert res_bad_c_es.stage2_verification["status"] == "MISMATCH"
    # Transformation must NOT be applied to bypass failed C_ES check
    assert res_bad_c_es.stage1_reconstruction.get("transformation_applied") is False


# ==============================================================================
# Test E: Incorrect commitment opening
# ==============================================================================
def test_test_e_incorrect_commitment_opening():
    """
    Provide an incorrect opening factor for an existing commitment.
    Expected: MISMATCH, not MATCH.
    """
    setup_complete_seller_buyer_transaction()
    ve = VerifierEngine.get_instance()

    ve.execute_step(1)
    ve.execute_step(2)
    ve.execute_step(3)

    # In Step 4, provide incorrect r_D
    res4 = ve.execute_step(4, overrides={"r_D": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"})
    assert res4.status == "MISMATCH"
    assert res4.stage2_verification["status"] == "MISMATCH"
    assert res4.stage2_verification["recalculated_commitment_C_D"] != res4.stage2_verification["stored_commitment_C_D"]

    # In Step 6, provide incorrect r_w / r_w1 (verifies complete watermark commitment C_W)
    ve.execute_step(5)
    res6 = ve.execute_step(6, overrides={"r_w": "1111111111111111111111111111111111111111111111111111111111111111"})
    assert res6.status == "MISMATCH"
    assert res6.stage2_verification["status"] == "MISMATCH"

    # In full-watermark model, Step 7 and Step 8 are NOT REQUIRED
    ve.execute_step(7)
    res8 = ve.execute_step(8)
    assert res8.status == "NOT REQUIRED"

    # Legacy transaction test: if legacy transaction is flagged, Step 8 verifies C_W and fails on bad opening factor
    extracted_w = ve.session.internal_confidential_values.get("W") or ve.session.internal_confidential_values.get("W1")
    ve.session.internal_confidential_values["W1"] = extracted_w[:32]
    res7_legacy = ve.execute_step(7, overrides={"is_full_watermark": False, "w2_bitstream": "0" * 224})
    assert res7_legacy.status == "MATCH"
    res8_legacy = ve.execute_step(8, overrides={"is_full_watermark": False, "r_w": "2222222222222222222222222222222222222222222222222222222222222222"})
    assert res8_legacy.status == "MISMATCH"
    assert res8_legacy.stage2_verification["status"] == "MISMATCH"


# ==============================================================================
# Test F: Incorrect reconstruction rule
# ==============================================================================
def test_test_f_incorrect_reconstruction_rule():
    """
    Change or use an incorrect encoding or watermark rule.
    Expected: the resulting reconstruction or commitment check fails where appropriate.
    """
    setup_complete_seller_buyer_transaction()
    ve = VerifierEngine.get_instance()

    ve.execute_step(1)
    # Provide an unknown or incorrect encoding rule
    res2 = ve.execute_step(2, overrides={"encoding_rule_id": "invalid_foreign_rule_v99"})
    assert res2.status == "BLOCKED"
    assert "Unsupported or missing design encoding rule" in res2.notes

    # Provide an incorrect extraction method
    ve.execute_step(1)
    ve.execute_step(2)
    ve.execute_step(3)
    ve.execute_step(4)
    res5 = ve.execute_step(5, overrides={"extraction_method_id": "unsupported_frequency_domain_extractor"})
    assert res5.status == "BLOCKED"


# ==============================================================================
# Test G: Incorrect W1 or W2
# ==============================================================================
def test_test_g_incorrect_w1_or_w2():
    """
    Modify the embedded watermark or protected portion in a controlled test.
    Expected: the appropriate watermark commitment or reconstruction check fails.
    """
    setup_complete_seller_buyer_transaction()
    ve = VerifierEngine.get_instance()

    ve.execute_step(1)
    ve.execute_step(2)
    ve.execute_step(3)
    ve.execute_step(4)

    # 1. Flip a bit in extracted W1'
    ve.execute_step(5)
    assert "extracted_bitstream_W1" not in ve.get_session().step_results["step_5"].stage1_reconstruction
    assert ve.get_session().step_results["step_5"].stage1_reconstruction["canonical_hash"] is not None
    extracted_w = ve.get_session().internal_confidential_values.get("W") or ve.get_session().internal_confidential_values.get("W1")
    corrupted_w = ("1" if extracted_w[0] == "0" else "0") + extracted_w[1:]

    # Step 6 with corrupted watermark
    res6 = ve.execute_step(6, overrides={"w_bitstream": corrupted_w, "w1_bitstream": corrupted_w})
    assert res6.status == "MISMATCH"
    assert res6.stage2_verification["status"] == "MISMATCH"

    # In full-watermark model, Step 7 and Step 8 are NOT REQUIRED
    res7 = ve.execute_step(7)
    assert res7.status == "NOT REQUIRED"
    res8 = ve.execute_step(8)
    assert res8.status == "NOT REQUIRED"

    # Legacy test: corrupting W2 in Step 7 causes Step 8 mismatch
    ve.session.internal_confidential_values["W1"] = extracted_w[:32]
    res7_leg = ve.execute_step(7, overrides={"is_full_watermark": False, "w2_bitstream": "1" * 224})
    assert res7_leg.status == "MATCH"
    res8_leg = ve.execute_step(8, overrides={"is_full_watermark": False})
    assert res8_leg.status == "MISMATCH"
    assert res8_leg.stage2_verification["status"] == "MISMATCH"


# ==============================================================================
# Test H: Incorrect Buyer contribution
# ==============================================================================
def test_test_h_incorrect_buyer_contribution():
    """
    Use an incorrect B or opening factor.
    Expected: C_B verification fails.
    """
    setup_complete_seller_buyer_transaction()
    ve = VerifierEngine.get_instance()

    # 1. Bad bitstream length (554 instead of 555)
    short_bitstream = DEMO_BUYER_BITSTREAM[:-1]
    res9 = ve.execute_step(9, overrides={"buyer_bitstream": short_bitstream})
    assert res9.status == "MISMATCH"
    assert res9.stage1_reconstruction["status"] == "INVALID PROPERTIES"

    # 2. Corrupted bit with bad C_B verification
    corrupted_b = ("1" if DEMO_BUYER_BITSTREAM[0] == "0" else "0") + DEMO_BUYER_BITSTREAM[1:]
    ve.execute_step(9, overrides={"buyer_bitstream": corrupted_b})
    res10 = ve.execute_step(10)
    assert res10.status == "MISMATCH"
    assert res10.stage2_verification["status"] == "MISMATCH"

    # 3. Bad opening factor r_B
    ve.execute_step(9)  # valid B
    res10_bad_r = ve.execute_step(10, overrides={"r_b": "1234567890abcdef"})
    assert res10_bad_r.status == "MISMATCH"
    assert res10_bad_r.stage2_verification["status"] == "MISMATCH"


# ==============================================================================
# Test I: Missing private evidence
# ==============================================================================
def test_test_i_missing_private_evidence():
    """
    Remove or omit a required rule or opening factor.
    Expected: BLOCKED or INCOMPLETE. No invented values or false success.
    """
    setup_complete_seller_buyer_transaction()
    ve = VerifierEngine.get_instance()

    ve.execute_step(1)
    ve.execute_step(2)
    ve.execute_step(3)

    # Missing r_D
    res4 = ve.execute_step(4, overrides={"r_D": ""})
    assert res4.status == "BLOCKED"
    assert "Missing Seller opening factor r_D" in res4.stage2_verification["detail"]

    # Missing stored C_D
    res4_no_comm = ve.execute_step(4, overrides={"C_D": ""})
    assert res4_no_comm.status == "BLOCKED"


# ==============================================================================
# Test J: Incorrect transaction record
# ==============================================================================
def test_test_j_incorrect_transaction_record():
    """
    Use inconsistent transaction IDs, parties, or rights information.
    Expected: transaction evidence is reported as inconsistent.
    """
    setup_complete_seller_buyer_transaction()
    ve = VerifierEngine.get_instance()

    # Adversarial override of seller_id
    res12 = ve.execute_step(12, overrides={"seller_id": "UNAUTHORIZED-IMPOSTOR"})
    assert res12.status == "MISMATCH"
    assert res12.stage2_verification["status"] == "MISMATCH"

    # Adversarial override of transaction_id
    res12_tx = ve.execute_step(12, overrides={"transaction_id": "TX-FORGED-999"})
    assert res12_tx.status == "MISMATCH"


# ==============================================================================
# Test K: Reference versus suspicious design
# ==============================================================================
def test_test_k_reference_versus_suspicious_design():
    """
    Verify that the second dispute type accepts two design inputs and uses only existing comparison capabilities.
    Expected: unsupported similarity features are clearly marked as unavailable.
    """
    st = setup_complete_seller_buyer_transaction()

    # Call /api/verifier/audit_ref_sus with Untouched Design
    res = client.post("/api/verifier/audit_ref_sus", json={
        "scenario_name": "Untouched Design",
        "subcategory": "Exact or near-copy suspicion.",
        "suspicious_verilog": st["watermarked_RTL"],
    })
    assert res.status_code == 200
    data = res.json()

    assert data["dispute_type"] == "Reference Design ↔ Suspicious Design"
    assert data["dispute_subcategory"] == "Exact or near-copy suspicion."
    assert "behavioral_verification" in data
    assert "watermark_extraction" in data
    assert "commitment_checks" in data

    # Behavioral verification re-used
    bv = data["behavioral_verification"]
    assert bv["exact_output_matches"] > 0
    assert bv["status"] in ("MATCH", "IDENTICAL")

    # Structural similarity explicitly marked as FUTURE CAPABILITY
    sim_status = data["structural_similarity_status"]
    assert sim_status["status"] == "FUTURE CAPABILITY"
    assert "Level 3 Structural Similarity & Node Correspondence is an intentionally deferred future extension" in sim_status["detail"]

    # Verify that different subcategories are supported
    res_mod = client.post("/api/verifier/audit_ref_sus", json={
        "scenario_name": "Modified Design",
        "subcategory": "Modified design.",
        "suspicious_verilog": st["watermarked_RTL"] + "\n// modified unauthorized variant\n",
    })
    assert res_mod.status_code == 200
    assert res_mod.json()["dispute_subcategory"] == "Modified design."


# ==============================================================================
# Test L: Independent RTL Reconstruction & Tamper Detection
# ==============================================================================
def test_independent_rtl_reconstruction_and_tamper():
    """
    Confirms Verifier reconstructs the encoding directly from the disputed synthesizable RTL.
    Tampering with the RTL operations or states must alter the reconstructed encoding,
    proving no stored Seller encoding is reused.
    """
    setup_complete_seller_buyer_transaction()
    ve = VerifierEngine.get_instance()
    tm = TransactionManager.get_instance()
    st = tm.get_state()

    # Step 1 establishes parameters
    res1 = ve.execute_step(1)
    assert res1.status == "LOADED"

    # 1. Normal reconstruction from authentic RTL
    res2_norm = ve.execute_step(2)
    assert res2_norm.status == "EXTRACTED"
    assert "extracted_bitstream" not in res2_norm.stage1_reconstruction
    hash_norm = res2_norm.stage1_reconstruction["canonical_hash"]
    assert len(hash_norm) == 64
    assert res2_norm.stage1_reconstruction["bit_length"] == 143
    encoding_norm = ve.session.internal_confidential_values["E_S"]
    assert len(encoding_norm) == 143

    # 2. Tampered RTL: change an addition to multiplication in the RTL text
    if "R5 <= R3 + R0;" in st.watermarked_RTL:
        tampered_rtl = st.watermarked_RTL.replace("R5 <= R3 + R0;", "R5 <= R3 * R0;")
    else:
        tampered_rtl = re.sub(r'(\b\w+\s*<=\s*[^;]*?)\+([^;]*?;)', r'\1*\2', st.watermarked_RTL, count=1)
    assert tampered_rtl != st.watermarked_RTL

    res2_tampered = ve.execute_step(2, overrides={"disputed_rtl": tampered_rtl})
    assert res2_tampered.status == "EXTRACTED"
    hash_tampered = res2_tampered.stage1_reconstruction["canonical_hash"]
    # The reconstructed hash MUST differ because node operation opcode changed
    assert hash_tampered != hash_norm

    # 3. Malformed RTL that violates synthesizable state comments
    malformed_rtl = "module broken_filter(input clk); wire x; endmodule"
    res2_malformed = ve.execute_step(2, overrides={"disputed_rtl": malformed_rtl})
    assert res2_malformed.status == "MISMATCH"
    assert "Failed to parse scheduled FSM states" in res2_malformed.stage1_reconstruction["detail"]


# ==============================================================================
# Test M: Prerequisite Failure Blocking Chain
# ==============================================================================
def test_prerequisite_blocking_chain():
    """
    Ensures that a failed prerequisite strictly blocks dependent verification steps.
    - Failed Step 2 blocks Step 3.
    - Failed Step 3 blocks Step 4.
    - Failed Step 4 blocks Step 11.
    """
    setup_complete_seller_buyer_transaction()
    ve = VerifierEngine.get_instance()

    ve.execute_step(1)

    # Cause Step 2 to fail
    malformed_rtl = "module bad(); endmodule"
    res2 = ve.execute_step(2, overrides={"disputed_rtl": malformed_rtl})
    assert res2.status == "MISMATCH"

    # Step 3 must be BLOCKED because Step 2 failed
    res3 = ve.execute_step(3)
    assert res3.status == "BLOCKED"
    assert "Prerequisite Step 2" in res3.stage2_verification["detail"]

    # Step 4 must be BLOCKED because Step 3 failed
    res4 = ve.execute_step(4)
    assert res4.status == "BLOCKED"
    assert "Prerequisite Step 3" in res4.stage2_verification["detail"]

    # Step 11 must be BLOCKED because Step 4 failed
    # First execute intermediate steps 5, 6, 7, 8, 9, 10
    ve.execute_step(5)
    ve.execute_step(6)
    ve.execute_step(7)
    ve.execute_step(8)
    ve.execute_step(9)
    ve.execute_step(10)
    res11 = ve.execute_step(11)
    assert res11.status == "BLOCKED"
    assert "Step 4 (C_D)" in res11.stage2_verification["detail"]


# ==============================================================================
# Test N: Transaction Rights Conflict Separation
# ==============================================================================
def test_transaction_rights_conflict_separation():
    """
    Confirms cryptographic consistency is separated from recorded rights.
    When a Buyer claims ownership but transaction records Exclusive License,
    the verifier reports cryptographic consistency while explicitly flagging
    the rights conflict.
    """
    setup_complete_seller_buyer_transaction()
    ve = VerifierEngine.get_instance()

    # Execute all steps up to 11 cleanly
    for step_num in range(1, 12):
        ve.execute_step(step_num)

    # Step 12 with ownership claim subcategory on a license transaction
    res12 = ve.execute_step(12, overrides={
        "dispute_subcategory": "Buyer claims full ownership and unrestricted patent rights"
    })
    # Cryptographic identifiers match
    assert res12.status == "MATCH"
    # But rights conflict must be explicitly detected
    assert res12.stage2_verification.get("rights_conflict_detected") is True
    assert "RIGHTS CONFLICT:" in res12.stage2_verification["rights_conflict_details"]

    # Step 13 final report must report rights conflict
    res13 = ve.execute_step(13)
    assert res13.status == "CONSISTENT"
    assert res13.stage2_verification["rights_conflict"] is True
    assert "RIGHTS CONFLICT:" in res13.stage2_verification["rights_conflict_details"]
    assert "do not independently establish legal ownership" in res13.stage2_verification["legal_notice"]


# ==============================================================================
# Test O: Pedersen Cryptographic Engine Correctness
# ==============================================================================
def test_pedersen_cryptographic_engine_correctness():
    """
    Validates actual PedersenEngine implementation:
    - Elliptic-curve scalar multiplication and point addition on NIST P-256.
    - Modulo reduction with curve order n.
    - NUMS derivation of H and verification that n * H == Infinity.
    - Additive homomorphic property of Pedersen commitments.
    """
    from hardware_ip_protection.crypto.pedersen import PedersenEngine
    import ecdsa

    engine = PedersenEngine()
    curve = ecdsa.NIST256p
    n = curve.order
    G = curve.generator
    H = engine.H

    # 1. Curve properties
    assert engine.order == n
    assert H is not None
    # H must be a valid point on the curve
    assert curve.curve.contains_point(H.x(), H.y())
    # H multiplied by curve order n must equal the point at infinity
    assert (n * H) == ecdsa.ellipticcurve.INFINITY

    # 2. Scalar reduction mod n
    s1 = engine.hash_to_scalar("message_design_A")
    r1 = 1337
    comm1, _ = engine.commit("message_design_A", blinding_factor=r1)
    # Committing with r1 + n yields identical commitment due to scalar reduction mod n
    comm1_reduced, _ = engine.commit("message_design_A", blinding_factor=r1 + n)
    assert comm1.commitment_hex == comm1_reduced.commitment_hex

    # 3. Additive homomorphic property over E(F_p):
    # C(s1, r1) + C(s2, r2) == C(s1 + s2 mod n, r1 + r2 mod n)
    s2 = engine.hash_to_scalar("message_design_B")
    r2 = 200
    p1 = (s1 * G) + (r1 * H)
    p2 = (s2 * G) + (r2 * H)
    p_added = p1 + p2

    p_expected = (((s1 + s2) % n) * G) + (((r1 + r2) % n) * H)
    assert engine.point_to_hex(p_added) == engine.point_to_hex(p_expected)
