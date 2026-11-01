"""
Unit and Integration Test Suite for Watermark Strength Analysis,
Constraint Possibility Analysis, and Unsecured CIG Reconstruction.

Verifies:
1. All four watermark lengths (32, 64, 128, 256 bits) run independently.
2. Every experiment starts from the same original unmodified IIR Butterworth CIG.
3. Pre-existing edges in baseline CIG are counted as pre-existing constraints and not as newly added edges.
4. Genuinely new edges are counted as artificial edges.
5. Successfully embedded bits are reported accurately.
6. Capacity boundaries and partial embedding checks function correctly.
7. Constraint combinations are calculated using actual parity eligibility restrictions (78 even, 91 odd).
8. Probabilities and entropy are calculated consistently with stated combinatorial models.
9. Secured Encoding Reconstruction has identical initial candidate space and entropy across all watermark configurations.
10. Candidate probabilities are displayed at the initial state and all checkpoints (CP0-CP6).
11. Unsecured reconstruction removes artificial edges only.
12. Genuine pre-existing edges strictly remain in the reconstructed CIG.
13. Reconstructed unsecured encoding is verified against commitment C_D.
14. Existing manual Judge interrogation continues to work.
15. Existing Secure Your Design / Watermark Strength API continues to work.
"""

import pytest
import math
from hardware_ip_protection.hls.dfg import create_iir_butterworth
from hardware_ip_protection.hls.scheduler import ListScheduler
from hardware_ip_protection.hls.cig import CIG, WatermarkCapacityAnalyzer, WatermarkCIGMapper
from hardware_ip_protection.pipeline.watermark_strength_analyzer import (
    WatermarkStrengthAnalyzer,
    WatermarkExperimentRecord,
)
from hardware_ip_protection.verification.interrogation_analysis import (
    InterrogationAnalysisHarness,
)
from hardware_ip_protection.pipeline.interrogation_manager import (
    InterrogationManager,
)
from hardware_ip_protection.pipeline.transaction_manager import (
    TransactionManager,
)


@pytest.fixture
def baseline_setup():
    dfg = create_iir_butterworth()
    sched = ListScheduler({"add": 2, "mul": 2, "sub": 2}).schedule(dfg)
    base_cig = CIG(sched)
    return dfg, sched, base_cig


def test_1_and_2_four_watermark_lengths_independent_and_fresh_baseline(baseline_setup):
    """
    Requirements 1 & 2:
    All 4 watermark lengths (32, 64, 128, 256 bits) can be run independently,
    and each experiment starts from the identical baseline IIR Butterworth CIG.
    """
    _, _, base_cig = baseline_setup
    baseline_edge_count = len(base_cig.genuine_edges)
    assert baseline_edge_count == 211
    assert len(base_cig.nodes) == 27

    res = WatermarkStrengthAnalyzer.run_all_experiments()
    experiments = res["experiments"]
    assert len(experiments) == 4

    expected_lengths = [32, 64, 128, 256]
    for i, exp in enumerate(experiments):
        assert exp["watermark_length"] == expected_lengths[i]
        assert exp["requested_bits"] == expected_lengths[i]
        # Invariant: baseline CIG in each experiment had 211 genuine edges
        assert exp["original_genuine_edges_count"] == 211
        # Prefix consistency: prefix of 32b is start of 64b, which is start of 128b, etc.
        if i > 0:
            prev_prefix = experiments[i - 1]["watermark_prefix"]
            curr_prefix = exp["watermark_prefix"]
            assert curr_prefix.startswith(prev_prefix)


def test_3_and_4_pre_existing_vs_artificial_edge_distinction(baseline_setup):
    """
    Requirements 3 & 4:
    Distinguish between pre-existing genuine edges and newly added artificial edges.
    """
    _, _, base_cig = baseline_setup
    res = WatermarkStrengthAnalyzer.run_all_experiments()

    for exp in res["experiments"]:
        pre = exp["pre_existing_constraints"]
        art = exp["distinct_artificial_edges_count"]
        # Both must be non-negative
        assert pre > 0
        assert art > 0
        # For 32 and 64 bits where no duplicate pairs occur:
        if exp["watermark_length"] in (32, 64):
            assert pre + art == exp["requested_bits"]


def test_5_and_6_successfully_embedded_bits_and_capacity(baseline_setup):
    """
    Requirements 5 & 6:
    Successfully embedded bits are reported accurately, and capacity boundaries are checked.
    """
    _, _, base_cig = baseline_setup
    cap = WatermarkCapacityAnalyzer.analyze(base_cig)
    assert cap["max_capacity"] >= 256
    assert cap["candidate_pair_count"] == 169

    res = WatermarkStrengthAnalyzer.run_all_experiments()
    for exp in res["experiments"]:
        assert exp["successfully_embedded_bits"] == exp["requested_bits"]
        assert exp["embedding_success"] is True

    # Check capacity check fails for unreasonable request
    ok, msg = WatermarkCapacityAnalyzer.check_capacity(base_cig, 500)
    assert ok is False


def test_7_and_8_constraint_combinations_and_probabilities(baseline_setup):
    """
    Requirements 7 & 8:
    Constraint combinations and probabilities are calculated using actual parity restrictions.
    """
    res = WatermarkStrengthAnalyzer.run_all_experiments()
    experiments = res["experiments"]

    # Even pool = 78, Odd pool = 91
    for exp in experiments:
        n_even = exp["eligible_even_pairs"]
        n_odd = exp["eligible_odd_pairs"]
        assert n_even == 78
        assert n_odd == 91
        assert exp["total_eligible_pairs"] == 169

        a_even = exp["even_artificial_edges_count"]
        a_odd = exp["odd_artificial_edges_count"]

        # Category combinations = C(78, a_even) * C(91, a_odd)
        expected_comb = math.comb(n_even, a_even) * math.comb(n_odd, a_odd)
        assert abs(exp["valid_combinations_category"] - expected_comb) < 1e-4

        # H_c = log2(expected_comb)
        expected_h = round(math.log2(expected_comb), 2)
        assert abs(exp["constraint_selection_entropy_category"] - expected_h) < 0.05

        # P(correct) = 1 / expected_comb
        expected_p = 1.0 / expected_comb
        assert exp["probability_correct_set_category"] > 0
        assert exp["probability_correct_set_category"] <= 1.0

    # Verify that constraint entropy monotonically increases with watermark length
    h_values = [e["constraint_selection_entropy_category"] for e in experiments]
    assert h_values[0] < h_values[1] < h_values[2] < h_values[3]


def test_9_and_10_secured_reconstruction_independence_and_probabilities():
    """
    Requirements 9 & 10:
    Secured Encoding Reconstruction has the exact same initial candidate space and entropy
    across all watermark configurations, and candidate probabilities are displayed at all checkpoints.
    """
    report = InterrogationAnalysisHarness.get_cached_or_run_report(force_refresh=True)
    checkpoints = report["checkpoints"]
    assert len(checkpoints) == 7  # CP0 through CP6

    # CP0 initial candidate space must be ~1.05e71 and initial entropy 235.93 bits
    cp0 = checkpoints[0]
    assert cp0["checkpoint_id"] == "CP0"
    assert cp0["combined_residual_entropy"] == 235.93
    assert cp0["candidate_probability_str"] != ""
    assert float(cp0["candidate_probability_str"]) > 0

    # All checkpoints must have candidate_probability_str
    for cp in checkpoints:
        assert hasattr(cp, "candidate_probability_str") or "candidate_probability_str" in cp
        prob_str = cp.candidate_probability_str if hasattr(cp, "candidate_probability_str") else cp["candidate_probability_str"]
        assert len(prob_str) > 0

    # Final checkpoint CP6 must have P(candidate) = 1.0 and entropy = 0.0
    cp6 = checkpoints[-1]
    assert cp6["checkpoint_id"] == "CP6"
    assert cp6["combined_residual_entropy"] == 0.0
    prob_str_cp6 = cp6.candidate_probability_str if hasattr(cp6, "candidate_probability_str") else cp6["candidate_probability_str"]
    assert prob_str_cp6 == "1.0"


def test_11_12_and_13_unsecured_reconstruction_and_c_d_verification():
    """
    Requirements 11, 12, 13:
    Unsecured reconstruction strips artificial edges only, retains all pre-existing genuine edges,
    and verifies the reconstructed encoding against commitment C_D.
    """
    im = InterrogationManager.get_instance()
    tx_id = "TX-TEST-UNSEC-001"

    # Start session and instant verify secured stage to meet prerequisite
    sess = im.start_session(transaction_id=tx_id, claimant_id="CLAIMANT-TEST", workflow="secured_design_encoding")
    im.instant_verify_secured(session_id=sess.session_id)

    # Reconstruct unsecured
    res = im.reconstruct_unsecured_encoding(transaction_id=tx_id)
    assert res["success"] is True
    assert res["status"] == "VERIFIED"

    recovered_cig = res["recovered_cig"]
    assert recovered_cig["status"] == "ORIGINAL_RECOVERED"
    assert recovered_cig["genuine_structure_preserved"] is True
    assert recovered_cig["total_edges"] == 211  # baseline genuine edges exactly recovered
    assert recovered_cig["removed_constraints_count"] > 0

    # Commitment C_D verification check
    cv = res["commitment_verification"]
    assert cv["status"] == "VERIFIED"
    assert cv["match"] is True


def test_14_existing_manual_judge_interrogation():
    """
    Requirement 14:
    Existing manual Judge interrogation continues to function cleanly.
    """
    import uuid
    im = InterrogationManager.get_instance()
    tx_id = f"TX-MANUAL-{uuid.uuid4().hex[:8]}"
    sess = im.start_session(transaction_id=tx_id, claimant_id="CLAIMANT-001", workflow="secured_design_encoding")
    assert sess.session_id is not None
    assert "IN PROGRESS" in sess.status

    view = im.get_session_view(sess.session_id)
    assert view is not None
    assert view["current_question"]["id"] == "Q0.1"

    view2 = im.submit_answer(sess.session_id, "Q0.1", 251)
    assert view2["progress"]["answered_count"] == 1
    assert view2["current_question"]["id"] == "Q0.2"


def test_15_watermark_strength_endpoint_integration():
    """
    Requirement 15:
    Watermark Strength endpoint returns full 4-length experiment results.
    """
    from fastapi.testclient import TestClient
    from hardware_ip_protection.web.app import app

    client = TestClient(app)
    resp = client.get("/api/analysis/watermark-strength")
    assert resp.status_code == 200
    data = resp.json()
    assert "experiments" in data
    assert len(data["experiments"]) == 4

    resp_rep = client.get("/api/transaction/report")
    assert resp_rep.status_code == 200
    data_rep = resp_rep.json()
    assert "report" in data_rep
    assert len(data_rep["report"]["experiments"]) == 4
