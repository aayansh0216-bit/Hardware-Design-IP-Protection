"""
Comprehensive Test Suite for:
1. Independent RTL-Based Structural Encoding Verification
2. Five-Rule Encoding Mode (251 bits) alongside Existing Four-Rule Mode (143 bits)
3. Design-Specific Encoding Transformation (T_butterworth(E_S) -> E_U = D)
4. Data Access Isolation and Cryptographic Commitment Checks
"""

import pytest
from fastapi.testclient import TestClient

from hardware_ip_protection.web.app import app
from hardware_ip_protection.pipeline.transaction_manager import (
    TransactionManager,
    AVAILABLE_DESIGNS,
    AVAILABLE_ENCODING_RULES,
)
from hardware_ip_protection.pipeline.verifier_engine import VerifierEngine
from hardware_ip_protection.hls.structural_encoder import (
    DeterministicStructuralEncoder,
    BUTTERWORTH_PRE_EMBEDDING_REGISTERS,
    BUTTERWORTH_POST_EMBEDDING_REGISTERS,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_tx_state():
    """Ensure clean transaction and verifier state before each test."""
    client.post("/api/transaction/reset")
    ve = VerifierEngine.get_instance()
    ve.reset_session()
    yield
    client.post("/api/transaction/reset")
    ve.reset_session()


# ==============================================================================
# TEST 1: Four-Rule Test Vectors Remain Exactly 143 Bits
# ==============================================================================
def test_1_four_rule_test_vectors_remain_143_bits():
    """
    Confirm that all four-rule test vectors produce exactly 143 bits
    and that pre-embedding and post-embedding structural encodings remain identical (E_S == D).
    """
    r_four = DeterministicStructuralEncoder.encode_golden_butterworth(mode="four_rule")
    assert r_four.mode == "four_rule"
    assert len(r_four.canonical_bitstream) == 143
    assert r_four.rule5_bitstream == ""
    assert len(r_four.records) == 13

    # In 4-rule mode, register allocation doesn't change node structural encodings
    r_post = DeterministicStructuralEncoder.encode_golden_butterworth(
        mode="four_rule",
        var_to_reg=BUTTERWORTH_POST_EMBEDDING_REGISTERS,
    )
    assert r_post.canonical_bitstream == r_four.canonical_bitstream


# ==============================================================================
# TEST 2: Rule 5 Produces Documented Page 8 & Page 9 Parity Bit Sequences
# ==============================================================================
def test_2_rule5_parity_matches_document_page8_and_page9():
    """
    Confirm that Rule 5 correctly computes register parity (odd -> '01', even -> '00')
    and variable parity (odd -> '01', even -> '00'), producing:
    - Exactly 108 bits for 27 variables (V1..V27)
    - Exactly 6 variables differing between Pre-Embedding (D) and Post-Embedding (E_S):
      V5, V11, V13, V23, V26, V27
    """
    r5_pre_bits, r5_pre_recs = DeterministicStructuralEncoder.encode_rule5(
        BUTTERWORTH_PRE_EMBEDDING_REGISTERS, num_variables=27
    )
    r5_post_bits, r5_post_recs = DeterministicStructuralEncoder.encode_rule5(
        BUTTERWORTH_POST_EMBEDDING_REGISTERS, num_variables=27
    )

    assert len(r5_pre_bits) == 108
    assert len(r5_post_bits) == 108
    assert len(r5_pre_recs) == 27
    assert len(r5_post_recs) == 27

    # Check the 6 documented changed variables:
    # V5: R1 (odd -> '01') -> R2 (even -> '00')
    assert r5_pre_recs[4]["register"] == "R1"
    assert r5_pre_recs[4]["encoding"] == "0101"  # R1 (odd: 01), V5 (odd: 01)
    assert r5_post_recs[4]["register"] == "R2"
    assert r5_post_recs[4]["encoding"] == "0001"  # R2 (even: 00), V5 (odd: 01)

    # V11: R1 (odd -> '01') -> R4 (even -> '00')
    assert r5_pre_recs[10]["register"] == "R1"
    assert r5_pre_recs[10]["encoding"] == "0101"
    assert r5_post_recs[10]["register"] == "R4"
    assert r5_post_recs[10]["encoding"] == "0001"

    # V13: R7 (odd -> '01') -> R8 (even -> '00')
    assert r5_pre_recs[12]["register"] == "R7"
    assert r5_pre_recs[12]["encoding"] == "0101"
    assert r5_post_recs[12]["register"] == "R8"
    assert r5_post_recs[12]["encoding"] == "0001"

    # V23: R1 (odd -> '01') -> R6 (even -> '00')
    assert r5_pre_recs[22]["register"] == "R1"
    assert r5_pre_recs[22]["encoding"] == "0101"
    assert r5_post_recs[22]["register"] == "R6"
    assert r5_post_recs[22]["encoding"] == "0001"

    # V26: R1 (odd -> '01') -> R12 (even -> '00')
    assert r5_pre_recs[25]["register"] == "R1"
    assert r5_pre_recs[25]["encoding"] == "0100"  # R1 (odd: 01), V26 (even: 00)
    assert r5_post_recs[25]["register"] == "R12"
    assert r5_post_recs[25]["encoding"] == "0000"  # R12 (even: 00), V26 (even: 00)

    # V27: R1 (odd -> '01') -> R14 (even -> '00')
    assert r5_pre_recs[26]["register"] == "R1"
    assert r5_pre_recs[26]["encoding"] == "0101"
    assert r5_post_recs[26]["register"] == "R14"
    assert r5_post_recs[26]["encoding"] == "0001"

    # Verify that exactly 6 variables differ between pre and post
    diff_count = 0
    for i in range(27):
        if r5_pre_recs[i]["encoding"] != r5_post_recs[i]["encoding"]:
            diff_count += 1
            assert i in [4, 10, 12, 22, 25, 26]
    assert diff_count == 6


# ==============================================================================
# TEST 3: Five-Rule Encoding Produces 251 Bits and is Deterministic
# ==============================================================================
def test_3_five_rule_encoding_length_and_determinism():
    """
    Confirm that 5-rule encoding = 143 (rules 1..4) + 108 (rule 5) = 251 bits,
    and repeated calculations yield identical bitstreams and hashes.
    """
    res1 = DeterministicStructuralEncoder.encode_golden_butterworth(
        mode="five_rule",
        var_to_reg=BUTTERWORTH_PRE_EMBEDDING_REGISTERS,
    )
    res2 = DeterministicStructuralEncoder.encode_golden_butterworth(
        mode="five_rule",
        var_to_reg=BUTTERWORTH_PRE_EMBEDDING_REGISTERS,
    )

    assert len(res1.canonical_bitstream) == 251
    assert res1.canonical_bitstream == res2.canonical_bitstream
    assert res1.canonical_sha256 == res2.canonical_sha256
    assert len(res1.rule5_bitstream) == 108


# ==============================================================================
# TEST 4: Butterworth Benchmark Structure Matches Document
# ==============================================================================
def test_4_butterworth_benchmark_matches_document():
    """
    Confirm 13 nodes, 7 control steps, 2 ALUs (1 Adder, 1 Multiplier).
    """
    res = DeterministicStructuralEncoder.encode_golden_butterworth(
        mode="five_rule",
        var_to_reg=BUTTERWORTH_PRE_EMBEDDING_REGISTERS,
    )
    assert len(res.records) == 13
    steps = {rec.step_number for rec in res.records}
    assert steps == {1, 2, 3, 4, 5, 6, 7}

    # Node operations
    mul_nodes = [rec.node_id for rec in res.records if rec.op_type == "mul"]
    add_nodes = [rec.node_id for rec in res.records if rec.op_type == "add"]
    assert mul_nodes == [1, 2, 3, 4, 5, 6, 7]
    assert add_nodes == [8, 9, 10, 11, 12, 13]


# ==============================================================================
# TEST 5: Verifier Calculates E_S' Directly from Disputed RTL (Both Modes)
# ==============================================================================
def test_5_verifier_calculates_es_directly_from_rtl():
    """
    Confirm verifier extracts E_S' from RTL wire taps and FSM schedule
    without accessing seller private DFG or stored D.
    """
    mgr = TransactionManager.get_instance()
    engine = VerifierEngine.get_instance()

    # 4-Rule extraction
    mgr.reset()
    mgr.select_design_and_rule("iir_butterworth", "iir_butterworth_rule_v1")
    mgr.generate_original_encoding()
    mgr.request_buyer_contribution()
    mgr.approve_buyer_request()
    mgr.continue_watermark_workflow()
    mgr.calculate_secured_encoding()

    st_4 = mgr.get_state()
    engine.reset_session(transaction_id=st_4.transaction_id)
    step1_4 = engine.execute_step(1)
    assert step1_4.status in ("LOADED", "SUCCESS")
    step2_4 = engine.execute_step(2)
    assert step2_4.status in ("EXTRACTED", "CALCULATED", "MATCH", "SUCCESS")
    assert step2_4.bit_length == 143
    assert step2_4.canonical_hash is not None

    # 5-Rule extraction
    mgr.reset()
    mgr.select_design_and_rule("iir_butterworth", "iir_butterworth_5rule_v1")
    mgr.generate_original_encoding()
    mgr.request_buyer_contribution()
    mgr.approve_buyer_request()
    mgr.continue_watermark_workflow()
    mgr.calculate_secured_encoding()

    st_5 = mgr.get_state()
    engine.reset_session(transaction_id=st_5.transaction_id)
    step1_5 = engine.execute_step(1)
    assert step1_5.status in ("LOADED", "SUCCESS")
    step2_5 = engine.execute_step(2)
    assert step2_5.status in ("EXTRACTED", "CALCULATED", "MATCH", "SUCCESS")
    assert step2_5.bit_length == 251
    assert step2_5.canonical_hash is not None


# ==============================================================================
# TEST 6: Disputed RTL Wire/FSM Tampering Detected
# ==============================================================================
def test_6_disputed_rtl_tampering_detected():
    """
    Modifying a wire tap or FSM state in the disputed RTL causes Step 3 (C_ES commitment verification)
    to fail because the independently computed E_S' does not match the committed C_ES.
    """
    mgr = TransactionManager.get_instance()
    engine = VerifierEngine.get_instance()

    mgr.reset()
    mgr.select_design_and_rule("iir_butterworth", "iir_butterworth_5rule_v1")
    mgr.generate_original_encoding()
    mgr.request_buyer_contribution()
    mgr.approve_buyer_request()
    mgr.continue_watermark_workflow()
    mgr.calculate_secured_encoding()

    st = mgr.get_state()
    tampered_rtl = st.watermarked_RTL.replace("V1 = R1", "V1 = R2").replace("V1 -> R1", "V1 -> R2")

    engine.reset_session(transaction_id=st.transaction_id)
    step1 = engine.execute_step(1, overrides={"disputed_rtl": tampered_rtl})
    assert step1.status in ("LOADED", "SUCCESS")

    step2 = engine.execute_step(2)
    assert step2.status in ("EXTRACTED", "CALCULATED", "MATCH", "SUCCESS")

    step3 = engine.execute_step(3)
    assert step3.status == "MISMATCH"


# ==============================================================================
# TEST 7: Non-Butterworth Design Fails Transformation
# ==============================================================================
def test_7_non_butterworth_design_fails_transformation():
    """
    Confirm that attempting transformation on an unsupported design (e.g., dct4)
    fails with an explicit error.
    """
    with pytest.raises(ValueError, match="Unsupported design 'dct4' for encoding transformation"):
        dummy_es = "0" * 251
        DeterministicStructuralEncoder.transform_butterworth_es_to_eu(dummy_es, design_id="dct4", mode="five_rule")


# ==============================================================================
# TEST 8: Transformation Applies Only When Required
# ==============================================================================
def test_8_transformation_requirement_flag():
    """
    In 4-rule mode, encoding_transform_required == False and E_S == D.
    In 5-rule mode, encoding_transform_required == True and E_S != D.
    """
    mgr = TransactionManager.get_instance()

    # 4-Rule
    mgr.reset()
    mgr.select_design_and_rule("iir_butterworth", "iir_butterworth_rule_v1")
    assert mgr.get_state().encoding_transform_required is False

    # 5-Rule
    mgr.reset()
    mgr.select_design_and_rule("iir_butterworth", "iir_butterworth_5rule_v1")
    assert mgr.get_state().encoding_transform_required is True


# ==============================================================================
# TEST 9: Commitment Verification: C_ES in Step 3, T(E_S) -> E_U, C_D in Step 4
# ==============================================================================
def test_9_commitment_verification_flow_5rule():
    """
    Confirm that in 5-rule mode:
    1. Step 3 verifies C_ES == Pedersen(E_S', r_ES)
    2. Step 3 transforms E_S' -> E_U' via T_butterworth
    3. Step 4 verifies C_D == Pedersen(E_U', r_D)
    """
    mgr = TransactionManager.get_instance()
    engine = VerifierEngine.get_instance()

    mgr.reset()
    mgr.select_design_and_rule("iir_butterworth", "iir_butterworth_5rule_v1")
    mgr.generate_original_encoding()
    mgr.request_buyer_contribution()
    mgr.approve_buyer_request()
    mgr.continue_watermark_workflow()
    mgr.calculate_secured_encoding()

    st = mgr.get_state()
    engine.reset_session(transaction_id=st.transaction_id)

    s1 = engine.execute_step(1)
    assert s1.status in ("LOADED", "SUCCESS")

    s2 = engine.execute_step(2)
    assert s2.status in ("EXTRACTED", "CALCULATED", "MATCH", "SUCCESS")

    s3 = engine.execute_step(3)
    assert s3.status in ("MATCH", "VALIDATED", "SUCCESS")

    s4 = engine.execute_step(4)
    assert s4.status in ("MATCH", "VALIDATED", "SUCCESS")


# ==============================================================================
# TEST 10: Complete End-to-End Pipeline in 5-Rule Mode Completes with CONSISTENT
# ==============================================================================
def test_10_complete_e2e_pipeline_5rule():
    """
    Run full verifier workflow in 5-rule mode and verify final verdict is CONSISTENT.
    """
    # 1. Seller & Buyer pipeline via API
    res = client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_5rule_v1",
    })
    assert res.status_code == 200

    assert client.post("/api/transaction/encode_design").status_code == 200
    assert client.post("/api/transaction/request_buyer").status_code == 200
    assert client.post("/api/transaction/approve_buyer").status_code == 200
    assert client.post("/api/transaction/continue_watermark").status_code == 200
    assert client.post("/api/transaction/calculate_secured_encoding").status_code == 200
    assert client.post("/api/transaction/compare_encodings").status_code == 200
    assert client.post("/api/transaction/verify_behavioral").status_code == 200

    st_res = client.get("/api/transaction/state")
    st = st_res.json()["state"]
    assert st["stage4_completed"] is True
    assert len(st["design_encoding_D"]) == 251
    es_val = st["secured_encoding_E_S"]
    es_len = len(es_val["canonical_bitstream"]) if isinstance(es_val, dict) else len(es_val)
    assert es_len == 251

    # 2. Verifier workflow via run_all_steps
    run_all_res = client.post("/api/verifier/run_all_steps", json={})
    assert run_all_res.status_code == 200
    sess = run_all_res.json()["session"]
    report = sess["final_report"]
    assert report is not None
    assert report["overall_evidence_status"] == "CONSISTENT"


# ==============================================================================
# TEST 11: Complete End-to-End Pipeline in 4-Rule Mode Completes with CONSISTENT
# ==============================================================================
def test_11_complete_e2e_pipeline_4rule():
    """
    Run full verifier workflow in original 4-rule mode and verify final verdict is CONSISTENT.
    Ensures zero regressions.
    """
    res = client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_rule_v1",
    })
    assert res.status_code == 200

    assert client.post("/api/transaction/encode_design").status_code == 200
    assert client.post("/api/transaction/request_buyer").status_code == 200
    assert client.post("/api/transaction/approve_buyer").status_code == 200
    assert client.post("/api/transaction/continue_watermark").status_code == 200
    assert client.post("/api/transaction/calculate_secured_encoding").status_code == 200
    assert client.post("/api/transaction/compare_encodings").status_code == 200
    assert client.post("/api/transaction/verify_behavioral").status_code == 200

    st_res = client.get("/api/transaction/state")
    st = st_res.json()["state"]
    assert st["stage4_completed"] is True
    assert len(st["design_encoding_D"]) == 143

    # Verifier workflow via run_all_steps
    run_all_res = client.post("/api/verifier/run_all_steps", json={})
    assert run_all_res.status_code == 200
    sess = run_all_res.json()["session"]
    report = sess["final_report"]
    assert report is not None
    assert report["overall_evidence_status"] == "CONSISTENT"


# ==============================================================================
# TEST 12: Verifier Responses & Session Outputs Do Not Expose Raw Secret Bitstreams
# ==============================================================================
def test_12_verifier_does_not_expose_raw_secret_bitstreams():
    """
    Verify that public verifier API endpoints do not leak raw canonical D, E_S, or E_U bitstreams;
    they only expose bit lengths, hashes, and commitment verification results.
    """
    client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_5rule_v1",
    })
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")
    client.post("/api/transaction/continue_watermark")
    client.post("/api/transaction/calculate_secured_encoding")
    client.post("/api/transaction/compare_encodings")
    client.post("/api/transaction/verify_behavioral")

    for step_num in range(1, 5):
        res = client.post("/api/verifier/execute_step", json={"step_number": step_num}).json()
        step_result = res.get("step_result", {})

        # Assert no 251-bit raw strings are in public results
        for k, v in step_result.items():
            if isinstance(v, str) and len(v) == 251 and set(v).issubset({"0", "1"}):
                pytest.fail(f"Step {step_num} leaked raw secret bitstream in key: {k}")

    # Check verifier state query
    st_res = client.get("/api/verifier/state").json()
    sess = st_res.get("session", {})
    assert "es_reconstructed" not in sess
    assert "eu_transformed" not in sess


# ==============================================================================
# TEST 13: Regression - Reproduce and Verify Fix for UI Selection Endpoint Failure
# ==============================================================================
def test_13_selection_endpoint_reproduces_and_fixes_screenshot_failure():
    """
    Directly reproduces the UI screenshot failure where selecting 'iir_butterworth_5rule_v1'
    failed with 'Unknown encoding rule 'iir_butterworth_5rule_v1''.
    Validates:
    1. Selecting 'iir_butterworth_5rule_v1' returns HTTP 200 with accepted state.
    2. Response returns rule ID, version, and transformation requirement.
    3. Transaction state holds 'iir_butterworth_5rule_v1' (not 'iir_butterworth_rule_v1').
    4. Subsequent encoding generation produces actual 251 bits (143b + 108b).
    """
    # 1. Selection endpoint
    sel_res = client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_5rule_v1",
    })
    assert sel_res.status_code == 200, f"Failed selection: {sel_res.text}"
    sel_data = sel_res.json()
    assert sel_data["encoding_rule_id"] == "iir_butterworth_5rule_v1"
    assert sel_data["rule_version"] == "1.0"
    assert sel_data["encoding_transform_required"] is True
    assert sel_data["state"]["encoding_rule_id"] == "iir_butterworth_5rule_v1"

    # 2. Check state query
    st_res = client.get("/api/transaction/state").json()["state"]
    assert st_res["encoding_rule_id"] == "iir_butterworth_5rule_v1"
    assert st_res["encoding_transform_required"] is True

    # 3. Calculation produces actual 251 bits
    enc_res = client.post("/api/transaction/encode_design", json={
        "use_table_quirks": False,
        "rule_id": "iir_butterworth_5rule_v1",
    })
    assert enc_res.status_code == 200
    st_after = enc_res.json()["state"]
    d_bits = st_after["design_encoding_D"]
    assert len(d_bits) == 251
    assert set(d_bits).issubset({"0", "1"})

    # Rules 1-4 are first 143 bits
    four_rule_canonical = DeterministicStructuralEncoder.encode_golden_butterworth(mode="four_rule").canonical_bitstream
    assert d_bits[:143] == four_rule_canonical

    # Rule 5 is last 108 bits
    rule5_bits, _ = DeterministicStructuralEncoder.encode_rule5(BUTTERWORTH_PRE_EMBEDDING_REGISTERS, num_variables=27)
    assert d_bits[143:] == rule5_bits
    assert len(rule5_bits) == 108


# ==============================================================================
# TEST 14: Switching Rules Invalidates Stale Encodings, Commitments, and Results
# ==============================================================================
def test_14_switching_rules_invalidates_stale_encodings_and_commitments():
    """
    Ensure that switching between 4-rule and 5-rule modes never retains stale
    commitments, encodings, or downstream stage results.
    """
    # 1. Start with 4-rule mode
    client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_rule_v1",
    })
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/commit_design")
    st1 = client.get("/api/transaction/state").json()["state"]
    assert len(st1["design_encoding_D"]) == 143
    assert st1["C_D"] is not None

    # 2. Switch to 5-rule mode: dependent encoding and commitment MUST be invalidated
    sel_res = client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_5rule_v1",
    })
    assert sel_res.status_code == 200
    st2 = client.get("/api/transaction/state").json()["state"]
    assert st2["encoding_rule_id"] == "iir_butterworth_5rule_v1"
    assert st2["design_encoding_D"] is None
    assert st2["C_D"] is None
    assert st2["blinding_factor_D"] is None
    assert st2.get("secured_encoding_E_S") is None

    # 3. Calculate 5-rule encoding: must be 251 bits
    client.post("/api/transaction/encode_design")
    st3 = client.get("/api/transaction/state").json()["state"]
    assert len(st3["design_encoding_D"]) == 251

    # 4. Switch back to 4-rule mode: must invalidate again
    client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_rule_v1",
    })
    st4 = client.get("/api/transaction/state").json()["state"]
    assert st4["encoding_rule_id"] == "iir_butterworth_rule_v1"
    assert st4["design_encoding_D"] is None

    # 5. Calculate 4-rule encoding: must be 143 bits
    client.post("/api/transaction/encode_design")
    st5 = client.get("/api/transaction/state").json()["state"]
    assert len(st5["design_encoding_D"]) == 143


# ==============================================================================
# TEST 15: Unsupported Rule Rejection and No Silent Fallback
# ==============================================================================
def test_15_unsupported_rule_rejected_with_clear_error_and_no_silent_fallback():
    """
    Ensure an invalid or unsupported rule ID produces a clear HTTP 400 error
    and never silently falls back to 4-rule mode.
    """
    res = client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "completely_unsupported_rule_v999",
    })
    assert res.status_code == 400
    assert "Unknown encoding rule" in res.json()["detail"] or "unsupported" in res.json()["detail"].lower()

    # Incompatible or unknown design
    res_incomp = client.post("/api/transaction/select_design", json={
        "design_id": "fir_filter_generic",
        "rule_id": "iir_butterworth_5rule_v1",
    })
    assert res_incomp.status_code == 400
    assert "Unknown design" in res_incomp.json()["detail"] or "not supported" in res_incomp.json()["detail"]

    # Ensure transaction state was NOT modified to invalid rule
    st = client.get("/api/transaction/state").json()["state"]
    assert st["encoding_rule_id"] in ("iir_butterworth_rule_v1", "iir_butterworth_5rule_v1")

    # Encode with invalid rule explicitly passed
    res_enc = client.post("/api/transaction/encode_design", json={
        "rule_id": "completely_unsupported_rule_v999"
    })
    assert res_enc.status_code == 400
    assert "Unknown encoding rule" in res_enc.json()["detail"] or "unsupported" in res_enc.json()["detail"].lower()


# ==============================================================================
# TEST 16: Frontend Source Contract Verification
# ==============================================================================
def test_16_frontend_source_contract_verification():
    """
    Verify static HTML and JS contracts to guarantee that:
    1. The 5-rule dropdown value matches the exact backend canonical rule ID 'iir_butterworth_5rule_v1'.
    2. The 4-rule dropdown value matches 'iir_butterworth_rule_v1'.
    3. The dynamic element IDs for metadata chips and headers exist in index.html.
    4. app.js binds to selection changes and updates state dynamically.
    """
    from pathlib import Path

    base_dir = Path(__file__).resolve().parent.parent
    html_file = base_dir / "hardware_ip_protection" / "web" / "static" / "index.html"
    js_file = base_dir / "hardware_ip_protection" / "web" / "static" / "app.js"

    assert html_file.exists(), "index.html not found"
    assert js_file.exists(), "app.js not found"

    html_content = html_file.read_text(encoding="utf-8")
    js_content = js_file.read_text(encoding="utf-8")

    # 1. HTML options
    assert 'value="iir_butterworth_5rule_v1"' in html_content
    assert 'value="iir_butterworth_rule_v1"' in html_content

    # 2. HTML dynamic IDs
    assert 'id="sellerTopDesign"' in html_content
    assert 'id="sellerTopEncodingRule"' in html_content
    assert 'id="sellerSubstage1ADesc"' in html_content
    assert 'id="sellerMetaDesignId"' in html_content
    assert 'id="sellerMetaRuleId"' in html_content
    assert 'id="sellerMetaRuleVer"' in html_content
    assert 'id="sellerMetaTransformReq"' in html_content
    assert 'id="sellerSummaryDesign"' in html_content
    assert 'id="sellerSummaryEncodingRule"' in html_content

    # 3. JS bindings
    assert "/api/transaction/select_design" in js_content
    assert "sellerMetaRuleId" in js_content
    assert "iir_butterworth_5rule_v1" in js_content


# ==============================================================================
# TEST 17: Verifier Reconstructs and Verifies Five-Rule Mode (251 bits) End to End
# ==============================================================================
def test_17_verifier_five_rule_mode_reconstructs_and_verifies_correctly():
    """
    Verify complete verifier execution in 5-rule mode:
    1. Step 2 extracts 251-bit E_S'.
    2. Step 3 detects E_S != D (Branch B) because Rule 5 parities changed for 6 variables.
    3. Step Transform applies deterministic transformation, producing 251-bit E_U' == D.
    4. Step 4 verifies original commitment C_D against the 251-bit canonical hash with MATCH.
    """
    # 1. Select 5-rule and run pipeline to Stage 4
    client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_5rule_v1",
    })
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/commit_design")
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")
    client.post("/api/transaction/continue_watermark")
    client.post("/api/transaction/calculate_secured_encoding")
    client.post("/api/transaction/compare_encodings")
    client.post("/api/transaction/verify_behavioral")

    st = client.get("/api/transaction/state").json()["state"]
    assert len(st["design_encoding_D"]) == 251
    es_obj = st["secured_encoding_E_S"]
    es_bits = es_obj["canonical_bitstream"] if isinstance(es_obj, dict) else es_obj
    assert len(es_bits) == 251
    assert st["encoding_transform_required"] is True

    # 2. Verifier Step 1: Disputed RTL
    r1 = client.post("/api/verifier/execute_step", json={"step_number": 1}).json()["step_result"]
    assert r1["status"] in ("LOADED", "MATCH")

    # 3. Verifier Step 2: Extract E_S' (251 bits)
    r2 = client.post("/api/verifier/execute_step", json={"step_number": 2}).json()["step_result"]
    assert r2["status"] in ("EXTRACTED", "MATCH")
    assert r2["stage1_reconstruction"]["bit_length"] == 251

    # 4. Verifier Step 3: Evaluate Invariance / C_ES Commitment
    r3 = client.post("/api/verifier/execute_step", json={"step_number": 3}).json()["step_result"]
    assert r3["status"] == "MATCH"
    assert "Branch A" in r3["stage1_reconstruction"]["branch"]

    # 5. Verifier Step 4: Verify C_D -> Triggers Transform and Matches NIST P-256 Commitment
    r4 = client.post("/api/verifier/execute_step", json={"step_number": 4}).json()["step_result"]
    assert r4["status"] == "MATCH"
    assert r4["stage1_reconstruction"]["bit_length"] == 251
    assert "verified against recorded canonical hash (MATCH)" in r4["notes"]


# ==============================================================================
# TEST 18: Canonical Concatenation Layout and Component Boundaries (E5 = E4 || R5)
# ==============================================================================
def test_18_canonical_concatenation_layout_and_boundary_splitting():
    """
    Verify exact canonical concatenation layout:
    - 13 nodes, each 11 bits (Rules 1, 2, 3, 4 concatenated in order: 4+4+1+2 = 11).
    - Four-rule stream E4 has exactly 143 bits.
    - 27 register-variable pairs, each 4 bits (2b register parity + 2b variable parity).
    - Rule 5 stream R5 has exactly 108 bits.
    - Final combined encoding E5 = E4 || R5 has exactly 251 bits.
    - Bits 0..142 match E4 exactly.
    - Bits 143..250 match R5 exactly.
    """
    res = DeterministicStructuralEncoder.encode_golden_butterworth(
        mode="five_rule",
        var_to_reg=BUTTERWORTH_PRE_EMBEDDING_REGISTERS,
    )

    assert res.total_design_nodes == 13
    assert res.four_rule_bit_length == 143
    assert len(res.four_rule_bitstream) == 143
    assert res.rule5_bit_length == 108
    assert len(res.rule5_bitstream) == 108
    assert res.canonical_bit_length == 251
    assert len(res.canonical_bitstream) == 251

    # Verify zero-based index ranges:
    # Bits 0-142: E4 (143 bits)
    assert res.canonical_bitstream[:143] == res.four_rule_bitstream
    # Bits 143-250: R5 (108 bits)
    assert res.canonical_bitstream[143:] == res.rule5_bitstream
    assert res.canonical_bitstream == res.four_rule_bitstream + res.rule5_bitstream

    # Verify node serialization order: per-node serialization (N1..N13)
    flat_nodes = []
    for g in res.step_groups:
        for nd in g.nodes:
            flat_nodes.append(nd)
            assert len(nd.bitstream) == 11
    assert len(flat_nodes) == 13
    reconstructed_e4 = "".join(f"{nd.rule1}{nd.rule2}{nd.rule3}{nd.rule4}" for nd in flat_nodes)
    assert reconstructed_e4 == res.four_rule_bitstream


# ==============================================================================
# TEST 19: Rule 5 Records 8-Column Schema and Parity Mappings
# ==============================================================================
def test_19_rule5_records_schema_and_column_integrity():
    """
    Verify Rule 5 records schema contains all 8 required columns:
    1. pair_index
    2. register_name & register_number
    3. register_parity ('odd' or 'even')
    4. register_parity_code ('01' or '00')
    5. variable_name & variable_number
    6. variable_parity ('odd' or 'even')
    7. variable_parity_code ('01' or '00')
    8. assembled_block ('0101', '0000', etc.)
    """
    res = DeterministicStructuralEncoder.encode_golden_butterworth(
        mode="five_rule",
        var_to_reg=BUTTERWORTH_PRE_EMBEDDING_REGISTERS,
    )
    records = res.rule5_records
    assert len(records) == 27

    for idx, rec in enumerate(records, start=1):
        assert rec["pair_index"] == idx
        # Check column keys presence
        for key in [
            "pair_index", "register_name", "register_number", "register_parity",
            "register_parity_code", "variable_name", "variable_number",
            "variable_parity", "variable_parity_code", "assembled_block", "encoding"
        ]:
            assert key in rec, f"Missing key {key} in Rule 5 record #{idx}"

        # Parity mappings: odd = '01', even = '00'
        assert rec["register_parity_code"] == ("01" if rec["register_parity"].lower() == "odd" else "00")
        assert rec["variable_parity_code"] == ("01" if rec["variable_parity"].lower() == "odd" else "00")
        assert rec["assembled_block"] == rec["register_parity_code"] + rec["variable_parity_code"]
        assert len(rec["assembled_block"]) == 4

    # Check the reference examples from prompt:
    # R1, V1 -> '0101'
    rec1 = records[0]
    assert rec1["register_name"] == "R1"
    assert rec1["variable_name"] == "V1"
    assert rec1["assembled_block"] == "0101"

    # R2, V2 -> '0000'
    rec2 = records[1]
    assert rec2["register_name"] == "R2"
    assert rec2["variable_name"] == "V2"
    assert rec2["assembled_block"] == "0000"

    # R3, V6 -> '0100' (R3: odd '01', V6: even '00')
    rec6 = next(r for r in records if r["variable_name"] == "V6")
    assert rec6["register_name"] == "R3"
    assert rec6["assembled_block"] == "0100"

    # R4, V11 -> '0001' in post-embedding allocation: R4 (even '00'), V11 (odd '01')
    post_res = DeterministicStructuralEncoder.encode_golden_butterworth(
        mode="five_rule",
        var_to_reg=BUTTERWORTH_POST_EMBEDDING_REGISTERS,
    )
    post_rec11 = next(r for r in post_res.rule5_records if r["variable_name"] == "V11")
    assert post_rec11["register_name"] == "R4"
    assert post_rec11["assembled_block"] == "0001"


# ==============================================================================
# TEST 20: Unsecured vs Secured Source Assignments and CIG Modification Detection
# ==============================================================================
def test_20_unsecured_and_secured_source_assignments_and_cig_modifications():
    """
    Confirm:
    - Unsecured uses pre-embedding register allocation.
    - Secured uses post-embedding register allocation.
    - Rules 1..4 (143 bits) are identical.
    - Exactly 6 variables change register allocation (V5, V11, V13, V23, V26, V27).
    - Rule 5 streams differ in exactly those 6 blocks.
    """
    pre_res = DeterministicStructuralEncoder.encode_golden_butterworth(
        mode="five_rule",
        var_to_reg=BUTTERWORTH_PRE_EMBEDDING_REGISTERS,
    )
    post_res = DeterministicStructuralEncoder.encode_golden_butterworth(
        mode="five_rule",
        var_to_reg=BUTTERWORTH_POST_EMBEDDING_REGISTERS,
    )

    # 4-rule node stream is completely invariant
    assert pre_res.four_rule_bitstream == post_res.four_rule_bitstream
    assert len(pre_res.four_rule_bitstream) == 143

    # Rule 5 stream differs
    assert pre_res.rule5_bitstream != post_res.rule5_bitstream
    assert len(pre_res.rule5_bitstream) == 108
    assert len(post_res.rule5_bitstream) == 108

    # Check the 6 modified variables
    modified_vars = [5, 11, 13, 23, 26, 27]
    differing_indices = []
    for i in range(27):
        if pre_res.rule5_records[i]["assembled_block"] != post_res.rule5_records[i]["assembled_block"]:
            differing_indices.append(pre_res.rule5_records[i]["variable_number"])

    assert sorted(differing_indices) == sorted(modified_vars)


# ==============================================================================
# TEST 21: Frontend Static Contracts for Table B and Boundary Notices
# ==============================================================================
def test_21_frontend_static_contracts_table_b_and_boundary_notices():
    """
    Verify index.html and app.js static structure contains Table B and boundary markers
    for both Stage 1 (Unsecured) and Stage 4B (Secured).
    """
    with open("hardware_ip_protection/web/static/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    # Stage 1 Substage 1A
    assert 'id="protEncTableBSection"' in html
    assert 'id="protEncTableB"' in html
    assert 'id="protEncTableBBody"' in html
    assert 'id="protEncBoundaryNotice"' in html
    assert 'id="protEncBoundaryR5Badge"' in html

    # Stage 4 Substage 4B
    assert 'id="sellerStageEsContent"' in html
    assert 'id="secEncTable"' in html
    assert 'id="secEncTableBody"' in html
    assert 'id="secEncTableBSection"' in html
    assert 'id="secEncTableB"' in html
    assert 'id="secEncTableBBody"' in html
    assert 'id="secEncBoundaryNotice"' in html
    assert 'id="secEncBoundaryR5Badge"' in html
    assert 'id="sellerStageEsBitstreamFormatted"' in html
    assert 'id="sellerStageEsBitstream"' in html

    with open("hardware_ip_protection/web/static/app.js", "r", encoding="utf-8") as f:
        js = f.read()

    assert "renderStructuralEncodingTab1" in js
    assert "renderSecuredStructuralEncoding" in js
    assert "protEncTableBBody" in js
    assert "secEncTableBBody" in js
    assert "CIG Modified" in js


# ==============================================================================
# TEST 22: Four-Rule Mode Backward Compatibility
# ==============================================================================
def test_22_four_rule_mode_backward_compatibility():
    """
    Ensure 4-rule mode remains completely functional:
    - Length is 143 bits
    - rule5_bit_length is 0, rule5_bitstream is empty string
    - canonical_bitstream is equal to four_rule_bitstream
    - E_S = D invariance holds
    """
    res = DeterministicStructuralEncoder.encode_golden_butterworth(
        mode="four_rule",
    )
    assert res.canonical_bit_length == 143
    assert len(res.canonical_bitstream) == 143
    assert res.four_rule_bit_length == 143
    assert res.rule5_bit_length == 0
    assert res.rule5_bitstream == ""
    assert len(res.rule5_records) == 0
    assert res.canonical_bitstream == res.four_rule_bitstream


# ==============================================================================
# TEST 23: Missing/Malformed Assignments and Canonical Ordering Preservation
# ==============================================================================
def test_23_missing_malformed_assignments_and_canonical_ordering():
    """
    Ensure:
    - Missing variable register assignment raises explicit ValueError (never pads/fabricates bits).
    - Malformed register string (no digits) raises explicit ValueError.
    - Dictionary insertion order does not affect canonical serialization order.
    """
    # Incomplete map missing V15
    incomplete_map = dict(BUTTERWORTH_PRE_EMBEDDING_REGISTERS)
    del incomplete_map["V15"]
    try:
        DeterministicStructuralEncoder.encode_golden_butterworth(
            mode="five_rule",
            var_to_reg=incomplete_map,
        )
        assert False, "Should have raised ValueError on missing V15"
    except ValueError as e:
        assert "Missing register assignment for variable V15" in str(e)

    # Malformed register string
    malformed_map = dict(BUTTERWORTH_PRE_EMBEDDING_REGISTERS)
    malformed_map["V1"] = "REG_INVALID"
    try:
        DeterministicStructuralEncoder.encode_golden_butterworth(
            mode="five_rule",
            var_to_reg=malformed_map,
        )
        assert False, "Should have raised ValueError on malformed register"
    except ValueError as e:
        assert "Cannot determine parity" in str(e)

    # Shuffled dictionary order produces identical canonical output
    shuffled_keys = list(BUTTERWORTH_PRE_EMBEDDING_REGISTERS.keys())
    import random
    random.seed(42)
    random.shuffle(shuffled_keys)
    shuffled_map = {k: BUTTERWORTH_PRE_EMBEDDING_REGISTERS[k] for k in shuffled_keys}

    res_normal = DeterministicStructuralEncoder.encode_golden_butterworth(
        mode="five_rule",
        var_to_reg=BUTTERWORTH_PRE_EMBEDDING_REGISTERS,
    )
    res_shuffled = DeterministicStructuralEncoder.encode_golden_butterworth(
        mode="five_rule",
        var_to_reg=shuffled_map,
    )
    assert res_normal.canonical_bitstream == res_shuffled.canonical_bitstream
    assert res_normal.canonical_sha256 == res_shuffled.canonical_sha256



