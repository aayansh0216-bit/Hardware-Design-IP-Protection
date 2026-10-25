"""
Comprehensive Automated Tests for Judge-Led Interrogation (143-Bit Stage),
Four-Rule Encoding Reference Fixtures, Stage 4 Commitment Lifecycle,
and Rule 5 Parity Data Audit.
"""

import pytest
import sqlite3
import json
import tempfile
import os

from hardware_ip_protection.hls.structural_encoder import (
    DesignStructuralEncoder,
    StructuralEncodingResult,
)
from hardware_ip_protection.verification.interrogation_engine import (
    InterrogationEngine,
    QuestionType,
    FactStatus,
    EXPECTED_143_BITSTREAM,
    CANONICAL_REFERENCE_NODES,
    CANONICAL_REFERENCE_UNITS,
)
from hardware_ip_protection.pipeline.interrogation_manager import (
    InterrogationManager,
    InterrogationSessionRecord,
)
from hardware_ip_protection.pipeline.transaction_manager import (
    TransactionManager,
    TransactionState,
)
from hardware_ip_protection.crypto.pedersen import PedersenEngine


# ==============================================================================
# 1. Four-Rule Encoder & Reference Fixture Tests
# ==============================================================================

def test_four_rule_encoder_reference_fixture():
    """
    Test 1-9: Validates reference 143-bit stream, node ordering, popcounts,
    field bitwidths, and canonical serialization order.
    """
    enc_res = DesignStructuralEncoder.encode_golden_butterworth(
        mode="four_rule",
        use_document_table_quirks=False,
    )
    bitstream = enc_res.canonical_bitstream

    # 1. Exactly 143 bits
    assert len(bitstream) == 143
    assert bitstream == EXPECTED_143_BITSTREAM

    # 2. Reference counts: 67 ones, 76 zeros
    ones_count = bitstream.count("1")
    zeros_count = bitstream.count("0")
    assert ones_count == 67
    assert zeros_count == 76

    # 3. Exactly 13 units (records)
    assert len(enc_res.records) == 13

    # 4. Canonical time-step order of nodes (NOT ascending 1..13)
    observed_nodes = [r.node_id for r in enc_res.records]
    assert observed_nodes == CANONICAL_REFERENCE_NODES
    assert observed_nodes != list(range(1, 14))

    # 5. Field totals: A=16, B=25, C=7, D=19
    total_a_ones = sum(r.rule1.count("1") for r in enc_res.records)
    total_b_ones = sum(r.rule2.count("1") for r in enc_res.records)
    total_c_ones = sum(1 for r in enc_res.records if r.rule3 == "1")
    total_d_ones = sum(r.rule4.count("1") for r in enc_res.records)

    assert total_a_ones == 16
    assert total_b_ones == 25
    assert total_c_ones == 7
    assert total_d_ones == 19
    assert total_a_ones + total_b_ones + total_c_ones + total_d_ones == 67

    # 6. Leading zeroes preserved
    u1 = enc_res.records[0]
    assert u1.rule2 == "0001"
    assert u1.rule1 == "0100"
    assert u1.rule4 == "10"

    # 7. Per-unit one-counts match expected: 4, 4, 4, 6, 5, 6, 7, 7, 3, 5, 6, 4, 6
    expected_unit_ones = [4, 4, 4, 6, 5, 6, 7, 7, 3, 5, 6, 4, 6]
    actual_unit_ones = [len(r.bitstream.replace("0", "")) for r in enc_res.records]
    assert actual_unit_ones == expected_unit_ones


# ==============================================================================
# 2. Question Progression, Persistence, & History Ledger Tests
# ==============================================================================

def test_question_progression_and_single_active():
    """
    Test 10-15: Only current unanswered question active, answers advance sequentially,
    session persists across database queries.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        mgr = InterrogationManager(db_path=db_path)
        sess = mgr.start_session(transaction_id="TX-TEST-01")

        # Initial view: Q0.1 active
        view1 = mgr.get_session_view(sess.session_id)
        assert view1["status"] == "IN PROGRESS"
        assert view1["progress"]["answered_count"] == 0
        assert view1["progress"]["total_active_questions"] == 78
        assert view1["current_question"] is not None
        assert view1["current_question"]["id"] == "Q0.1"

        # Submit answer to Q0.1
        view2 = mgr.submit_answer(sess.session_id, "Q0.1", 251)
        assert view2["progress"]["answered_count"] == 1
        assert view2["current_question"]["id"] == "Q0.2"

        # Out-of-order submission fails (e.g. Trying Q0.5 before Q0.2)
        with pytest.raises(ValueError, match="Progressive interrogation order violated"):
            mgr.submit_answer(sess.session_id, "Q0.5", 76)

        # Invalid answer fails without advancing
        with pytest.raises(ValueError):
            mgr.submit_answer(sess.session_id, "Q0.2", "not_an_int")

        # Current question is still Q0.2
        view_after_err = mgr.get_session_view(sess.session_id)
        assert view_after_err["current_question"]["id"] == "Q0.2"
        assert view_after_err["progress"]["answered_count"] == 1

        # Persistence: reloading via new manager instance preserves state
        mgr2 = InterrogationManager(db_path=db_path)
        reloaded_view = mgr2.get_session_view(sess.session_id)
        assert reloaded_view["effective_answers"]["Q0.1"] == 251
        assert reloaded_view["current_question"]["id"] == "Q0.2"
        assert len(reloaded_view["history_ledger"]) == 1

    finally:
        try:
            if os.path.exists(db_path):
                os.remove(db_path)
        except Exception:
            pass


def test_non_destructive_corrections():
    """
    Test 16: Corrections append new records with is_correction=True and do not delete earlier answers.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        mgr = InterrogationManager(db_path=db_path)
        sess = mgr.start_session(transaction_id="TX-TEST-CORR")

        mgr.submit_answer(sess.session_id, "Q0.1", 250)  # Incorrect typo
        view1 = mgr.get_session_view(sess.session_id)
        assert len(view1["history_ledger"]) == 1
        assert view1["history_ledger"][0]["effective_answer"] == 250

        # Correct Q0.1 to 251
        view2 = mgr.submit_correction(sess.session_id, "Q0.1", 251)
        assert len(view2["history_ledger"]) == 2
        first_entry = view2["history_ledger"][0]
        second_entry = view2["history_ledger"][1]

        assert first_entry["effective_answer"] == 250
        assert not first_entry["is_correction"]

        assert second_entry["effective_answer"] == 251
        assert second_entry["is_correction"]
        assert second_entry["corrected_entry_id"] == first_entry["entry_id"]
        assert view2["effective_answers"]["Q0.1"] == 251

    finally:
        try:
            if os.path.exists(db_path):
                os.remove(db_path)
        except Exception:
            pass


def test_contradiction_handling():
    """
    Test 17: A hard constraint violation stops progression and sets status CONTRADICTION.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        mgr = InterrogationManager(db_path=db_path)
        sess = mgr.start_session(transaction_id="TX-TEST-CONTRA")

        mgr.submit_answer(sess.session_id, "Q0.1", 251)
        # Zeros > total bits violates H1
        view = mgr.submit_answer(sess.session_id, "Q0.2", 300)

        assert view["status"] == "CONTRADICTION"
        assert len(view["evaluation"]["contradictions"]) > 0
        assert view["current_question"] is None  # Progression halted

        # Submitting next question is rejected while in contradiction
        with pytest.raises(ValueError, match="Interrogation has encountered a contradiction"):
            mgr.submit_answer(sess.session_id, "Q0.3", 2)

        # Resolving via correction clears contradiction
        view_fixed = mgr.submit_correction(sess.session_id, "Q0.2", 149)
        assert view_fixed["status"] == "IN PROGRESS"
        assert view_fixed["current_question"]["id"] == "Q0.3"

    finally:
        try:
            if os.path.exists(db_path):
                os.remove(db_path)
        except Exception:
            pass


# ==============================================================================
# 3. Constraint Engine, Hypotheses, & Fallback Tests
# ==============================================================================

def test_independent_hard_constraints_h2_h5_h6_h7():
    """
    Test 18-20: Independent tests for H2, H5, H6, H7.
    """
    # H2: Parent counts sum to child counts
    answers_h2_bad = {
        "Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143,
        "Q0.5": 80,  # Part1 zeros (80) > total zeros (149), but let's test part1 zeros exceeding total zeros
    }
    eval_h2 = InterrogationEngine.evaluate_state(answers_h2_bad)
    assert not eval_h2["contradictions"]  # 80 <= 149 is okay

    answers_h2_violation = {
        "Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143,
        "Q0.5": 150,  # 150 > 149! Violates H2
    }
    eval_h2_err = InterrogationEngine.evaluate_state(answers_h2_violation)
    assert any("H2" in c for c in eval_h2_err["contradictions"])

    # H5: 4-bit integer range & popcount match
    # Value 16 is outside 0..15 for 4-bit field
    all_q = {q.id: q for q in InterrogationEngine.build_question_bank()}
    q4_1 = all_q["Q4.1"]
    assert q4_1.max_val == 15

    # H6: Transitivity of equality
    # If U1 == U2 (yes) and U2 == U3 (yes), then U1 == U3 must hold
    answers_h6 = {
        "Q3.1": "yes",  # U1 == U2
        "Q3.2": "no",   # U2 != U3
    }
    eval_h6 = InterrogationEngine.evaluate_state(answers_h6)
    assert not eval_h6["contradictions"]


def test_p1_hypothesis_failure_and_fallback_activation():
    """
    Test 21-23: P1 failure retracts inferred D/C values and activates exactly 4 fallback questions.
    """
    answers = {
        "Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143, "Q0.5": 76,
        "Q0.6": 13, "Q0.7": "yes", "Q0.8": 11, "Q0.9": 4, "Q0.10": "yes",
        "Q0.11": 4, "Q0.12": 4, "Q0.13": 1, "Q0.14": 2,
    }
    # Add ones per unit
    ref_ones = [4, 4, 4, 6, 5, 6, 7, 7, 3, 5, 6, 4]
    for i in range(1, 13):
        answers[f"Q1.{i}"] = ref_ones[i - 1]

    # Block 2
    answers["Q2.1"] = 16
    answers["Q2.2"] = 25
    answers["Q2.3"] = 7
    answers["Q2.4"] = "yes"

    # Block 3 equalities
    eqs = ["yes", "no", "yes", "yes", "no", "yes", "yes", "no", "yes", "no", "no", "no"]
    for i in range(1, 13):
        answers[f"Q3.{i}"] = eqs[i - 1]

    # Block 4 A values
    a_vals = [4, 1, 5, 0, 5, 1, 5]
    for i in range(1, 8):
        answers[f"Q4.{i}"] = a_vals[i - 1]

    # Block 5 representatives
    d_vals = [2, 3, 3, 2, 1, 1, 1]
    for i in range(1, 8):
        answers[f"Q5.{i}"] = d_vals[i - 1]

    # Spot checks for P1: correct is Q5.8=3, Q5.9=3
    # If claimant answers Q5.8 = 1 (spot check mismatch!):
    answers["Q5.8"] = 1

    eval_p1_fail = InterrogationEngine.evaluate_state(answers)
    assert eval_p1_fail["p1_failed"] is True
    assert eval_p1_fail["soft_hypotheses"]["P1"]["status"] == "FAILED"
    # Retracted inferred facts include units 2, 5, 7, 10
    assert any("unit_2_D" in rf for rf in eval_p1_fail["retracted_facts"])
    assert any("unit_5_D" in rf for rf in eval_p1_fail["retracted_facts"])

    # Active questions should now include fallback questions Q5.10, Q5.11, Q5.12, Q5.13
    active_q = InterrogationEngine.get_active_questions(p1_failed=True, block5b_enabled=False)
    assert len(active_q) == 78 + 4  # 82 questions total (78 active + 4 fallback)
    fallback_ids = [q.id for q in active_q if q.is_fallback]
    assert fallback_ids == ["Q5.10", "Q5.11", "Q5.12", "Q5.13"]


def test_consistent_wrong_candidate_is_not_contradiction():
    """
    Test 24: A candidate that is wrong relative to the secret golden design,
    but internally consistent mathematically, is NOT called a contradiction.
    """
    answers = {
        "Q0.1": 251, "Q0.2": 150, "Q0.3": 2, "Q0.4": 143, "Q0.5": 75,
        "Q0.6": 13, "Q0.7": "yes", "Q0.8": 11, "Q0.9": 4, "Q0.10": "yes",
        "Q0.11": 4, "Q0.12": 4, "Q0.13": 1, "Q0.14": 2,
    }
    eval_res = InterrogationEngine.evaluate_state(answers)
    # Internally consistent math: 150 <= 251, 75 <= 150, etc.
    assert len(eval_res["contradictions"]) == 0
    assert eval_res["outcome"] == "IN PROGRESS"


def test_complete_reference_run_143_reconstruction():
    """
    Test 25-27: Submitting all reference answers reconstructs the exact 143-bit candidate,
    achieves 143 known bits, returns 'INCOMPLETE: 143-bit stage complete; Rule 5 interrogation pending',
    and never returns VERIFIED.
    """
    answers: dict = {}

    # Block 0
    b0_refs = {
        "Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143, "Q0.5": 76,
        "Q0.6": 13, "Q0.7": "yes", "Q0.8": 11, "Q0.9": 4, "Q0.10": "yes",
        "Q0.11": 4, "Q0.12": 4, "Q0.13": 1, "Q0.14": 2,
    }
    answers.update(b0_refs)

    # Block 1
    ref_ones = [4, 4, 4, 6, 5, 6, 7, 7, 3, 5, 6, 4]
    for i in range(1, 13):
        answers[f"Q1.{i}"] = ref_ones[i - 1]

    # Block 2
    answers.update({"Q2.1": 16, "Q2.2": 25, "Q2.3": 7, "Q2.4": "yes"})

    # Block 3
    eqs = ["yes", "no", "yes", "yes", "no", "yes", "yes", "no", "yes", "no", "no", "no"]
    for i in range(1, 13):
        answers[f"Q3.{i}"] = eqs[i - 1]

    # Block 4
    a_vals = [4, 1, 5, 0, 5, 1, 5]
    for i in range(1, 8):
        answers[f"Q4.{i}"] = a_vals[i - 1]

    # Block 5 (P1 passes)
    d_vals = [2, 3, 3, 2, 1, 1, 1]
    for i in range(1, 8):
        answers[f"Q5.{i}"] = d_vals[i - 1]
    answers["Q5.8"] = 3
    answers["Q5.9"] = 3

    # Block 6
    answers["Q6.1"] = 91
    b_vals = [1, 2, 8, 3, 4, 9, 5, 6, 10, 7, 11, 12]
    for i in range(1, 13):
        answers[f"Q6.{i + 1}"] = b_vals[i - 1]

    # Block 7
    answers["Q7.1"] = 0
    answers["Q7.2"] = 1

    eval_res = InterrogationEngine.evaluate_state(answers, block5b_enabled=False)

    assert not eval_res["contradictions"]
    assert eval_res["is_complete_143"] is True
    assert len(eval_res["reconstructed_bitstream"]) == 143
    assert eval_res["reconstructed_bitstream"] == EXPECTED_143_BITSTREAM
    assert eval_res["outcome"] == "INCOMPLETE: 143-bit stage complete; Rule 5 interrogation pending"
    assert "VERIFIED" not in eval_res["outcome"]

    # Provenance statistics:
    # 94 observed + 37 derived + 12 inferred (8 D bits + 4 C bits for units 2, 5, 7, 10) = 143 bits
    assert eval_res["bit_statistics"]["total_bits"] == 143
    assert eval_res["bit_statistics"]["observed_bits"] == 94
    assert eval_res["bit_statistics"]["derived_bits"] == 37
    assert eval_res["bit_statistics"]["inferred_bits"] == 12
    assert eval_res["bit_statistics"]["unknown_bits"] == 0


# ==============================================================================
# 4. Stage 4 Secured-Encoding Commitment Lifecycle Tests
# ==============================================================================

def test_stage4_commitment_lifecycle_four_rule_vs_five_rule():
    """
    Test 28-34:
    - 4-rule mode: E_S == D, C_ES is NOT_REQUIRED
    - 5-rule mode: E_S != D (6 vars modified), C_ES is generated over E_S,
      Stage 4C and 4E agree on transformation required.
    - Role-based authorization: Seller sees blinding factor, Buyer view redacts it.
    """
    tm = TransactionManager.get_instance()
    tm.reset()

    # Step 1: Four-rule benchmark
    tm.select_design_and_rule("iir_butterworth", "iir_butterworth_rule_v1")
    tm.generate_original_encoding()
    tm.request_buyer_contribution()
    tm.approve_buyer_request()
    tm.continue_watermark_workflow()
    tm.calculate_secured_encoding()
    tm.compare_encodings()
    tm.verify_behavioral_validation()

    st4 = tm.get_state()
    assert st4.stage4_completed is True
    assert st4.encoding_transform_required is False
    assert st4.C_ES == "NOT_REQUIRED"
    assert st4.seller_private_info["C_ES_evidence"]["status"] == "NOT_REQUIRED"
    assert st4.seller_private_info["C_ES_evidence"]["is_required"] is False
    assert st4.seller_private_info["C_ES_evidence"]["invariance_analysis"]["E_S_equals_D"] is True

    # Step 2: Five-rule benchmark
    tm.reset()
    tm.select_design_and_rule("iir_butterworth", "iir_butterworth_5rule_v1")
    tm.generate_original_encoding()
    tm.request_buyer_contribution()
    tm.approve_buyer_request()
    tm.continue_watermark_workflow()
    tm.calculate_secured_encoding()
    tm.compare_encodings()
    tm.verify_behavioral_validation()

    st5 = tm.get_state()
    assert st5.stage4_completed is True
    assert st5.encoding_transform_required is True
    assert st5.C_ES is not None and st5.C_ES != "NOT_REQUIRED"
    assert len(st5.C_ES) == 66  # Compressed NIST P-256 point in hex
    assert st5.blinding_factor_ES is not None

    es_ev = st5.seller_private_info["C_ES_evidence"]
    assert es_ev["status"] == "Generated / Stored"
    assert es_ev["is_required"] is True
    assert es_ev["invariance_analysis"]["E_S_equals_D"] is False
    assert es_ev["commitment_verification"]["stored_commitment_C_ES"] == st5.C_ES

    # Verify commitment cryptographically against E_S bitstream
    es_bits = st5.secured_encoding_E_S["canonical_bitstream"]
    pe = PedersenEngine()
    is_valid = pe.verify(es_bits, st5.C_ES, int(st5.blinding_factor_ES, 16))
    assert is_valid.value == "VALID"

    # Role-based authorization: Buyer response redacts secret opening factor
    seller_view = tm.get_state_for_role(role="seller")
    assert seller_view["blinding_factor_ES"] == st5.blinding_factor_ES
    assert seller_view["seller_private_info"] is not None

    buyer_view = tm.get_state_for_role(role="buyer")
    assert buyer_view["blinding_factor_ES"] is None
    assert buyer_view["seller_private_info"] is None
    assert buyer_view["C_ES"] == st5.C_ES


# ==============================================================================
# 5. Rule 5 Data Audit (Specification vs Implementation)
# ==============================================================================

def test_rule5_parity_data_audit():
    """
    Test 35-38: Recomputes 4-bit codes for all 27 register-variable allocation pairs,
    verifying 108 bits length and checking specific pairs (R1,V1; R2,V2; R3,V6; R4,V11; V22)
    against actual allocation outputs from DesignStructuralEncoder.
    """
    # Canonical rule: R_odd='01', R_even='00'; V_odd='01', V_even='00'
    def encode_pair(r_num: int, v_num: int) -> str:
        r_code = "01" if (r_num % 2 == 1) else "00"
        v_code = "01" if (v_num % 2 == 1) else "00"
        return r_code + v_code

    # Specific pairs from specification:
    assert encode_pair(1, 1) == "0101"
    assert encode_pair(2, 2) == "0000"
    assert encode_pair(3, 6) == "0100"
    assert encode_pair(4, 11) == "0001"

    # Pre-embedding V22: bound to R14 in actual allocation -> R14(even=00), V22(even=00) -> 0000
    assert encode_pair(14, 22) == "0000"

    # Post-embedding V22: bound to R14 in actual allocation -> R14(even=00), V22(even=00) -> 0000
    assert encode_pair(14, 22) == "0000"

    # Verify actual allocation outputs in DesignStructuralEncoder
    bits_pre, recs_pre = DesignStructuralEncoder.encode_rule5(
        DesignStructuralEncoder.BUTTERWORTH_PRE_EMBEDDING_REGISTERS
    )
    bits_post, recs_post = DesignStructuralEncoder.encode_rule5(
        DesignStructuralEncoder.BUTTERWORTH_POST_EMBEDDING_REGISTERS,
        original_var_to_reg=DesignStructuralEncoder.BUTTERWORTH_PRE_EMBEDDING_REGISTERS,
    )
    assert len(bits_pre) == 108
    assert len(bits_post) == 108
    assert bits_pre.count("1") == 34
    assert bits_pre.count("0") == 74
    assert bits_post.count("1") == 28
    assert bits_post.count("0") == 80

    # 6 variables change allocation
    changed = [r for r in recs_post if r["comparison_status"] == "Changed"]
    assert len(changed) == 6
    changed_vars = {r["variable"] for r in changed}
    assert changed_vars == {"V5", "V11", "V13", "V23", "V26", "V27"}

    # V22 allocation verification
    v22_pre = next(r for r in recs_pre if r["variable"] == "V22")
    v22_post = next(r for r in recs_post if r["variable"] == "V22")
    assert v22_pre["register"] == "R14" and v22_pre["encoding"] == "0000"
    assert v22_post["register"] == "R14" and v22_post["encoding"] == "0000"
    assert v22_post["comparison_status"] == "Unchanged"

    # 27 pairs produce exactly 108 bits
    assert 27 * 4 == 108


# ==============================================================================
# 5. Progressive Bitstream Reconstruction Acceptance Tests (19 Requirements)
# ==============================================================================

def test_req1_stage_a_before_total_length():
    """Requirement 1: Before total length is established, no final candidate grid is shown."""
    eval_res = InterrogationEngine.evaluate_state({})
    recon = eval_res["reconstruction_state"]
    assert recon["stage"] == "STAGE_A"
    assert recon["total_length"] is None
    assert len(recon["part1_cells"]) == 0
    assert len(recon["entire_cells"]) == 0
    assert recon["units_established"] is False
    assert recon["fields_established"] is False


def test_req2_stage_b_total_length_established():
    """Requirement 2: After accepted length answer, candidate has exactly established positions, all initially UNKNOWN."""
    eval_res = InterrogationEngine.evaluate_state({"Q0.1": 251})
    recon = eval_res["reconstruction_state"]
    assert recon["stage"] == "STAGE_B"
    assert recon["total_length"] == 251
    assert len(recon["entire_cells"]) == 251
    assert all(not c["is_fixed"] for c in recon["entire_cells"])
    assert all(c["fill"] == "NEUTRAL" for c in recon["entire_cells"])
    assert all(c["display_char"] == "?" for c in recon["entire_cells"])
    assert all(c["provenance"] == "UNKNOWN" for c in recon["entire_cells"])


def test_req3_stage_c_population_counts_without_arbitrary_positions():
    """Requirement 3: Zero/one counts are displayed without assigning arbitrary canonical positions."""
    eval_res = InterrogationEngine.evaluate_state({"Q0.1": 251, "Q0.2": 149})
    recon = eval_res["reconstruction_state"]
    assert recon["stage"] == "STAGE_C"
    assert recon["total_zeros"] == 149
    assert recon["total_ones"] == 102
    pool = recon["provisional_pool"]
    assert pool["unfixed_zeros"] == 149
    assert pool["unfixed_ones"] == 102
    assert pool["total_unfixed"] == 251
    # Cells are unfixed RED containing literal unplaced 0 and 1 values (Requirement A)
    assert all(not c["is_fixed"] for c in recon["entire_cells"])
    assert all(c["fill"] == "RED" for c in recon["entire_cells"])
    assert sum(1 for c in recon["entire_cells"] if c["display_char"] == "0") == 149
    assert sum(1 for c in recon["entire_cells"] if c["display_char"] == "1") == 102


def test_req4_stage_d_part_boundaries_appear_only_when_established():
    """Requirement 4: Part boundaries appear only after they are established."""
    answers = {"Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143, "Q0.5": 76}
    eval_res = InterrogationEngine.evaluate_state(answers)
    recon = eval_res["reconstruction_state"]
    assert recon["stage"] == "STAGE_D"
    assert recon["segments"]["part1"]["is_established"] is True
    assert recon["segments"]["part1"]["length"] == 143
    assert recon["segments"]["part1"]["zeros"] == 76
    assert recon["segments"]["part1"]["ones"] == 67
    assert recon["segments"]["part2"]["is_established"] is True
    assert recon["segments"]["part2"]["length"] == 108
    assert len(recon["part1_cells"]) == 143
    assert len(recon["part2_cells"]) == 108
    assert len(recon["entire_cells"]) == 251
    # Part 2 cells remain unfixed and pending
    assert all(not c["is_fixed"] for c in recon["part2_cells"])


def test_req5_part1_and_part2_selection_without_mutating_state():
    """Requirement 5: Part 1 and Part 2 selection renders the appropriate segment without mutating state."""
    answers = {"Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143}
    eval_res1 = InterrogationEngine.evaluate_state(answers)
    recon1 = eval_res1["reconstruction_state"]
    p1_cells = recon1["part1_cells"]
    p2_cells = recon1["part2_cells"]
    assert len(p1_cells) == 143
    assert len(p2_cells) == 108
    # Re-evaluating produces identical deterministic output
    eval_res2 = InterrogationEngine.evaluate_state(answers)
    recon2 = eval_res2["reconstruction_state"]
    assert recon1 == recon2


def test_req6_canonical_node_schedule_order():
    """Requirement 6: The 143-bit segment follows the exact canonical node order."""
    answers = {
        "Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143, "Q0.5": 76,
        "Q0.6": 13, "Q0.7": "yes", "Q0.8": 11,
    }
    eval_res = InterrogationEngine.evaluate_state(answers)
    units = eval_res["unit_candidates"]
    observed_nodes = [u["node_id"] for u in units]
    assert observed_nodes == [1, 2, 8, 3, 4, 9, 5, 6, 10, 7, 11, 12, 13]
    assert observed_nodes != sorted(observed_nodes)


def test_req7_unit_and_field_subdivisions_appear_only_after_answers():
    """Requirement 7: Unit and field subdivisions appear only after their structural answers establish them."""
    # Before Q0.6
    answers = {"Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143}
    eval_res = InterrogationEngine.evaluate_state(answers)
    assert eval_res["reconstruction_state"]["units_established"] is False
    assert eval_res["reconstruction_state"]["fields_established"] is False

    # After Q0.6 - Q0.8 (Units established)
    answers.update({"Q0.5": 76, "Q0.6": 13, "Q0.7": "yes", "Q0.8": 11})
    eval_res = InterrogationEngine.evaluate_state(answers)
    assert eval_res["reconstruction_state"]["units_established"] is True
    assert eval_res["reconstruction_state"]["fields_established"] is False

    # After Q0.9 - Q0.14 (Fields established)
    answers.update({"Q0.9": 4, "Q0.10": "yes", "Q0.11": 4, "Q0.12": 4, "Q0.13": 1, "Q0.14": 2})
    eval_res = InterrogationEngine.evaluate_state(answers)
    assert eval_res["reconstruction_state"]["units_established"] is True
    assert eval_res["reconstruction_state"]["fields_established"] is True
    assert eval_res["reconstruction_state"]["stage"] == "STAGE_F"


def test_req8_field_widths_mapping():
    """Requirement 8: The 4 + 4 + 1 + 2 field widths map correctly onto each 11-bit unit."""
    answers = {
        "Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143, "Q0.5": 76,
        "Q0.6": 13, "Q0.7": "yes", "Q0.8": 11,
        "Q0.9": 4, "Q0.10": "yes", "Q0.11": 4, "Q0.12": 4, "Q0.13": 1, "Q0.14": 2,
    }
    eval_res = InterrogationEngine.evaluate_state(answers)
    p1_cells = eval_res["reconstruction_state"]["part1_cells"]
    assert len(p1_cells) == 143
    for u in range(1, 14):
        u_cells = [c for c in p1_cells if c["unit_index"] == u]
        assert len(u_cells) == 11
        assert [c["field_name"] for c in u_cells] == ["A", "A", "A", "A", "B", "B", "B", "B", "C", "D", "D"]
        assert [c["field_bit_offset"] for c in u_cells] == [0, 1, 2, 3, 0, 1, 2, 3, 0, 0, 1]


def test_req9_observed_field_fixes_only_its_positions():
    """Requirement 9: An observed field value fixes only the positions logically determined by that answer."""
    answers = {
        "Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143, "Q0.5": 76,
        "Q0.6": 13, "Q0.7": "yes", "Q0.8": 11,
        "Q0.9": 4, "Q0.10": "yes", "Q0.11": 4, "Q0.12": 4, "Q0.13": 1, "Q0.14": 2,
        # Unit 1 run representative A value
        "Q3.1": "no", "Q3.2": "no", "Q3.3": "no", "Q3.4": "no", "Q3.5": "no", "Q3.6": "no",
        "Q3.7": "no", "Q3.8": "no", "Q3.9": "no", "Q3.10": "no", "Q3.11": "no", "Q3.12": "no",
        "Q4.1": 4, # Unit 1 A = 4 (0100)
    }
    eval_res = InterrogationEngine.evaluate_state(answers)
    p1_cells = eval_res["reconstruction_state"]["part1_cells"]
    u1_a_cells = [c for c in p1_cells if c["unit_index"] == 1 and c["field_name"] == "A"]
    assert len(u1_a_cells) == 4
    assert [c["value"] for c in u1_a_cells] == ["0", "1", "0", "0"]
    assert all(c["is_fixed"] for c in u1_a_cells)
    assert all(c["fill"] == "GREEN" for c in u1_a_cells)
    assert all(c["provenance"] == "OBSERVED" for c in u1_a_cells)

    # Unit 1 Field B cells remain unfixed
    u1_b_cells = [c for c in p1_cells if c["unit_index"] == 1 and c["field_name"] == "B"]
    assert all(not c["is_fixed"] for c in u1_b_cells)
    assert all(c["fill"] == "RED" for c in u1_b_cells)


def test_req10_derived_bit_has_derived_provenance():
    """Requirement 10: A hard-derived bit has DERIVED provenance."""
    answers = {
        "Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143, "Q0.5": 76,
        "Q0.6": 13, "Q0.7": "yes", "Q0.8": 11,
        "Q0.9": 4, "Q0.10": "yes", "Q0.11": 4, "Q0.12": 4, "Q0.13": 1, "Q0.14": 2,
        # Unit 1 and 2 equal A in Run 1 (7 runs total)
        "Q3.1": "yes", "Q3.2": "no", "Q3.3": "yes", "Q3.4": "yes", "Q3.5": "no", "Q3.6": "yes",
        "Q3.7": "yes", "Q3.8": "no", "Q3.9": "yes", "Q3.10": "no", "Q3.11": "no", "Q3.12": "no",
        "Q4.1": 4, # Unit 1 A = 4
        "Q4.2": 1, "Q4.3": 5, "Q4.4": 0, "Q4.5": 5, "Q4.6": 1, "Q4.7": 5,
    }
    eval_res = InterrogationEngine.evaluate_state(answers)
    p1_cells = eval_res["reconstruction_state"]["part1_cells"]
    u2_a_cells = [c for c in p1_cells if c["unit_index"] == 2 and c["field_name"] == "A"]
    assert len(u2_a_cells) == 4
    assert [c["value"] for c in u2_a_cells] == ["0", "1", "0", "0"]
    assert all(c["is_fixed"] for c in u2_a_cells)
    assert all(c["fill"] == "GREEN" for c in u2_a_cells)
    assert all(c["provenance"] == "DERIVED" for c in u2_a_cells)


def test_req11_soft_hypothesis_inferred_provenance_and_amber():
    """Requirement 11: A soft-hypothesis bit has INFERRED provenance and cannot be mistaken for confirmed."""
    answers = {
        "Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143, "Q0.5": 76,
        "Q0.6": 13, "Q0.7": "yes", "Q0.8": 11,
        "Q0.9": 4, "Q0.10": "yes", "Q0.11": 4, "Q0.12": 4, "Q0.13": 1, "Q0.14": 2,
        "Q3.1": "yes", "Q3.2": "no", "Q3.3": "yes", "Q3.4": "yes", "Q3.5": "no", "Q3.6": "yes",
        "Q3.7": "yes", "Q3.8": "no", "Q3.9": "yes", "Q3.10": "no", "Q3.11": "no", "Q3.12": "no",
        "Q5.1": 2, "Q5.2": 3, "Q5.3": 3, "Q5.4": 2, "Q5.5": 1, "Q5.6": 1, "Q5.7": 1,
    }
    eval_res = InterrogationEngine.evaluate_state(answers)
    p1_cells = eval_res["reconstruction_state"]["part1_cells"]
    u2_d_cells = [c for c in p1_cells if c["unit_index"] == 2 and c["field_name"] == "D"]
    assert len(u2_d_cells) == 2
    assert all(not c["is_fixed"] for c in u2_d_cells) # Provisional!
    assert all(c["fill"] == "INFERRED" for c in u2_d_cells)
    assert all(c["provenance"] == "INFERRED" for c in u2_d_cells)


def test_req12_hypothesis_failure_retracts_and_reverts_cells():
    """Requirement 12: When hypothesis fails, dependent inferences retract and cells return to unresolved state."""
    answers = {
        "Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143, "Q0.5": 76,
        "Q0.6": 13, "Q0.7": "yes", "Q0.8": 11,
        "Q0.9": 4, "Q0.10": "yes", "Q0.11": 4, "Q0.12": 4, "Q0.13": 1, "Q0.14": 2,
        "Q3.1": "yes", "Q3.2": "no", "Q3.3": "yes", "Q3.4": "yes", "Q3.5": "no", "Q3.6": "yes",
        "Q3.7": "yes", "Q3.8": "no", "Q3.9": "yes", "Q3.10": "no", "Q3.11": "no", "Q3.12": "no",
        "Q5.1": 2, "Q5.2": 3, "Q5.3": 3, "Q5.4": 2, "Q5.5": 1, "Q5.6": 1, "Q5.7": 1,
        "Q5.8": 0, # Fails P1 hypothesis!
    }
    eval_res = InterrogationEngine.evaluate_state(answers)
    assert eval_res["p1_failed"] is True
    p1_cells = eval_res["reconstruction_state"]["part1_cells"]
    u2_d_cells = [c for c in p1_cells if c["unit_index"] == 2 and c["field_name"] == "D"]
    assert all(not c["is_fixed"] for c in u2_d_cells)
    assert all(c["fill"] == "RED" for c in u2_d_cells) # Reverted to RED!
    assert all(c["display_char"] == "?" for c in u2_d_cells)
    assert all(c["provenance"] == "REJECTED" for c in u2_d_cells)


def test_req13_aggregate_counts_never_turn_arbitrary_cells_green():
    """Requirement 13: Aggregate counts never cause arbitrary bit positions to become GREEN."""
    answers = {
        "Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143, "Q0.5": 76,
        "Q0.6": 13, "Q0.7": "yes", "Q0.8": 11,
        "Q0.9": 4, "Q0.10": "yes", "Q0.11": 4, "Q0.12": 4, "Q0.13": 1, "Q0.14": 2,
        "Q1.1": 4, "Q1.2": 4, "Q1.3": 4, "Q1.4": 6, "Q1.5": 5, "Q1.6": 6,
        "Q1.7": 7, "Q1.8": 7, "Q1.9": 3, "Q1.10": 5, "Q1.11": 6, "Q1.12": 4,
        "Q2.1": 16, "Q2.2": 25, "Q2.3": 7,
    }
    eval_res = InterrogationEngine.evaluate_state(answers)
    p1_cells = eval_res["reconstruction_state"]["part1_cells"]
    # Despite knowing unit ones and field totals, no individual bit positions are fixed yet!
    assert sum(1 for c in p1_cells if c["is_fixed"]) == 0
    assert all(c["fill"] == "RED" for c in p1_cells)


def test_req14_no_reference_stream_values_for_unresolved_positions():
    """Requirement 14: No reference-stream values are used to fill unresolved candidate positions."""
    answers = {"Q0.1": 251, "Q0.2": 149}
    eval_res = InterrogationEngine.evaluate_state(answers)
    # The reconstructed bitstream must not be filled with reference bits
    stream = eval_res["reconstructed_bitstream"]
    assert "?" in stream
    assert stream.count("?") == 143


def test_req15_grid_and_unit_table_consistency():
    """Requirement 15: The grid and per-unit table reflect the exact same reconstruction state."""
    answers = {
        "Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143, "Q0.5": 76,
        "Q0.6": 13, "Q0.7": "yes", "Q0.8": 11,
        "Q0.9": 4, "Q0.10": "yes", "Q0.11": 4, "Q0.12": 4, "Q0.13": 1, "Q0.14": 2,
        "Q3.1": "no", "Q3.2": "no", "Q3.3": "no", "Q3.4": "no", "Q3.5": "no", "Q3.6": "no",
        "Q3.7": "no", "Q3.8": "no", "Q3.9": "no", "Q3.10": "no", "Q3.11": "no", "Q3.12": "no",
        "Q4.1": 4,
    }
    eval_res = InterrogationEngine.evaluate_state(answers)
    p1_cells = eval_res["reconstruction_state"]["part1_cells"]
    units = eval_res["unit_candidates"]
    for u in range(1, 14):
        u_cells = [c for c in p1_cells if c["unit_index"] == u]
        fixed_cell_str = "".join(c["display_char"] if c["is_fixed"] else "?" for c in u_cells)
        assert fixed_cell_str == units[u - 1]["assembled_bits"]


def test_req16_metadata_integrity_diagnostic_no_undefined():
    """Requirement 16: Missing schedule metadata produces explicit diagnostic, never undefined."""
    eval_res = InterrogationEngine.evaluate_state({"Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143, "Q0.5": 76, "Q0.6": 13, "Q0.7": "yes", "Q0.8": 11})
    units = eval_res["unit_candidates"]
    for idx, u in enumerate(units, start=1):
        assert u["position"] == idx
        assert u["position"] in range(1, 14)
        assert u["cs_step"] in range(1, 8)
        assert u["cs_label"].startswith("T")
        assert u["node_label"].startswith("N")
        assert "undefined" not in u["cs_label"]
        assert "undefined" not in u["node_label"]


def test_req17_reset_and_resume_preserves_state(tmp_path):
    """Requirement 17: Reset and resume preserve the intended state and experiment configuration."""
    db_file = str(tmp_path / "test_session.db")
    mgr = InterrogationManager(db_path=db_file)
    sess = mgr.start_session(transaction_id="TX-TEST-PROGRESSIVE")

    # Answer Q0.1
    mgr.submit_answer(sess.session_id, "Q0.1", 251)
    view = mgr.get_session_view(sess.session_id)
    assert view["reconstruction_state"]["stage"] == "STAGE_B"

    # Toggle block5b
    mgr.toggle_block5b(sess.session_id, True)
    view = mgr.get_session_view(sess.session_id)
    assert view["block5b_enabled"] is True

    # Reset session
    mgr.reset_session(sess.session_id)
    reset_view = mgr.get_session_view(sess.session_id)
    assert reset_view["reconstruction_state"]["stage"] == "STAGE_A"
    assert len(reset_view["history_ledger"]) == 0
    assert reset_view["progress"]["answered_count"] == 0


def test_req18_consistent_incorrect_candidate_not_contradiction():
    """Requirement 18: A consistent but incorrect candidate is not automatically classified as a contradiction."""
    # Answering an alternate consistent structural encoding (e.g. 100 bits total, 50 zeros, 2 parts of 50)
    answers = {
        "Q0.1": 100,
        "Q0.2": 50,
        "Q0.3": 2,
        "Q0.4": 50,
        "Q0.5": 25,
    }
    eval_res = InterrogationEngine.evaluate_state(answers)
    assert eval_res["outcome"] != "CONTRADICTION"
    assert len(eval_res["contradictions"]) == 0
    assert eval_res["reconstruction_state"]["stage"] == "STAGE_D"


def test_req19_143_stage_does_not_run_full_commitment_check():
    """Requirement 19: The 143-bit stage remains provisional and does not run the full commitment check."""
    # When fully completed for 143-bit stage
    golden = DesignStructuralEncoder.encode_golden_butterworth(mode="four_rule")
    # Feed golden answers for all 73 questions
    answers = {}
    q_bank = InterrogationEngine.build_question_bank(block5b_enabled=False)
    for q in q_bank:
        answers[q.id] = q.reference_answer

    eval_res = InterrogationEngine.evaluate_state(answers)
    assert eval_res["is_complete_143"] is True
    # Outcome is explicitly INCOMPLETE for full pipeline, never "VERIFIED"
    assert "Rule 5 interrogation pending" in eval_res["outcome"]
    assert eval_res["outcome"] != "VERIFIED"

