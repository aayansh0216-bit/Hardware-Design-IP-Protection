"""
Comprehensive tests for Adaptive Branching, Edge Cases, and Improved Questions
in the Judge-Led Interrogation Engine.
"""

import tempfile
import os
import pytest
from hardware_ip_protection.verification.interrogation_engine import (
    InterrogationEngine,
    QuestionDefinition,
    QuestionType,
    ReconstructionStage,
)
from hardware_ip_protection.pipeline.interrogation_manager import (
    InterrogationManager,
    InterrogationSessionRecord,
)


@pytest.fixture
def engine():
    return InterrogationEngine()


@pytest.fixture
def manager():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    mgr = InterrogationManager(db_path=db_path)
    yield mgr
    try:
        if os.path.exists(db_path):
            os.remove(db_path)
    except Exception:
        pass


def get_canonical_143_answers():
    answers = {
        "Q0.1": 251, "Q0.2": 149, "Q0.3": 2, "Q0.4": 143, "Q0.5": 76,
        "Q0.6": 13, "Q0.7": "yes", "Q0.8": 11, "Q0.9": 4, "Q0.10": "yes",
        "Q0.11": 3, "Q0.12": 3, "Q0.13": 3, "Q0.14": 2,
    }
    ref_ones = [4, 4, 4, 6, 5, 6, 7, 7, 3, 5, 6, 4]
    for i in range(1, 13):
        answers[f"Q1.{i}"] = ref_ones[i - 1]

    answers.update({"Q2.1": 16, "Q2.2": 25, "Q2.3": 7, "Q2.4": "yes"})

    eqs = ["yes", "no", "yes", "yes", "no", "yes", "yes", "no", "yes", "no", "no", "no"]
    for i in range(1, 13):
        answers[f"Q3.{i}"] = eqs[i - 1]

    a_vals = [4, 1, 5, 0, 5, 1, 5]
    for i in range(1, 8):
        answers[f"Q4.{i}"] = a_vals[i - 1]

    d_vals = [2, 3, 3, 2, 1, 1, 1]
    for i in range(1, 8):
        answers[f"Q5.{i}"] = d_vals[i - 1]
    answers["Q5.8"] = 3
    answers["Q5.9"] = 3

    answers["Q6.1"] = 91
    b_vals = [1, 2, 8, 3, 4, 9, 5, 6, 10, 7, 11, 12]
    for i in range(1, 13):
        answers[f"Q6.{i + 1}"] = b_vals[i - 1]

    answers["Q7.1"] = 0
    answers["Q7.2"] = 1
    return answers


# ============================================================================
# 1. PRECONDITIONS & GRAPH ELIGIBILITY TESTS
# ============================================================================

def test_initial_eligible_questions_do_not_assume_parts(engine):
    """Initial question is Q0.1. Once answered, Q0.2 and Q0.3 follow without assuming parts."""
    # When empty, Q0.1 is root
    eligible_0 = engine.get_eligible_questions(answers={}, workflow="secured_design_encoding")
    assert [q.id for q in eligible_0] == ["Q0.1"]

    # When total bits and zeros are provided, Q0.3 is eligible, but part count/length are NOT
    eligible_1 = engine.get_eligible_questions(answers={"Q0.1": 251, "Q0.2": 149}, workflow="secured_design_encoding")
    ids_1 = [q.id for q in eligible_1]
    assert "Q0.3" in ids_1
    assert "Q0.3_count" not in ids_1
    assert "Q0.3_equal" not in ids_1
    assert "Q0.4" not in ids_1
    assert "Q0.5" not in ids_1


def test_parts_divided_yes_enables_count_and_equality(engine):
    """Answering Q0.3='yes' makes Q0.3_count eligible; answering count enables Q0.3_equal."""
    answers = {"Q0.1": 251, "Q0.2": 149, "Q0.3": "yes"}
    eligible = engine.get_eligible_questions(answers=answers, workflow="secured_design_encoding")
    eligible_ids = [q.id for q in eligible]

    assert "Q0.3_count" in eligible_ids
    assert "Q0.4" not in eligible_ids

    # Once count is answered (>1), Q0.3_equal becomes eligible
    answers["Q0.3_count"] = 2
    eligible2 = engine.get_eligible_questions(answers=answers, workflow="secured_design_encoding")
    assert "Q0.3_equal" in [q.id for q in eligible2]


# ============================================================================
# 2. INDEPENDENT PARTS BRANCHING: YES / NO / UNKNOWN
# ============================================================================

def test_independent_parts_unknown_results_in_incomplete(engine):
    """Q0.3='unknown' halts the engine with status INCOMPLETE."""
    answers = {"Q0.1": 251, "Q0.2": 149, "Q0.3": "unknown"}
    result = engine.evaluate_state(answers=answers, workflow="secured_design_encoding")

    assert result["outcome"].startswith("INCOMPLETE")
    assert "incomplete_reason" in result
    assert "unknown" in result["incomplete_reason"].lower()
    assert result["reconstruction_state"]["stage"] == ReconstructionStage.STAGE_INCOMPLETE

    next_q = engine.get_next_question(answers=answers, workflow="secured_design_encoding")
    assert next_q is None  # Interrogation halts cleanly


def test_independent_parts_no_monolithic_branch(engine):
    """Q0.3='no' establishes a single monolithic complete-stream model."""
    answers = {"Q0.1": 251, "Q0.2": 149, "Q0.3": "no"}
    result = engine.evaluate_state(answers=answers, workflow="secured_design_encoding")

    assert result["outcome"] != "CONTRADICTION"
    recon = result["reconstruction_state"]
    assert recon["branch_info"]["parts_divided"] == "no"
    assert recon["total_length"] == 251
    assert recon["stage"] == ReconstructionStage.STAGE_MONOLITHIC
    assert len(recon["part1_cells"]) == 251

    eligible = engine.get_eligible_questions(answers=answers, workflow="secured_design_encoding")
    eligible_ids = [q.id for q in eligible]

    # Must NEVER ask part length or equal-part questions on monolithic branch
    assert "Q0.3_count" not in eligible_ids
    assert "Q0.3_equal" not in eligible_ids
    assert "Q0.4" not in eligible_ids
    assert "Q0.5" not in eligible_ids
    # Bypasses to units question
    assert "Q0.6_has_units" in eligible_ids


# ============================================================================
# 3. EQUAL-LENGTH PARTS & INDIVISIBLE CONTRADICTION
# ============================================================================

def test_equal_parts_indivisible_total_length_contradiction(engine):
    """251 total bits cannot be divided into 2 equal parts: hard contradiction H0.3."""
    answers = {
        "Q0.1": 251,
        "Q0.2": 149,
        "Q0.3": "yes",
        "Q0.3_count": 2,
        "Q0.3_equal": "yes",
    }
    result = engine.evaluate_state(answers=answers, workflow="secured_design_encoding")

    assert result["outcome"] == "CONTRADICTION"
    assert any("H0.3" in c or "indivisible" in c.lower() or "divisible" in c.lower() for c in result["contradictions"])

    next_q = engine.get_next_question(answers=answers, workflow="secured_design_encoding")
    assert next_q is None


def test_equal_parts_divisible_total_length_accepted(engine):
    """250 total bits divided into 2 equal parts is valid (125 bits each)."""
    answers = {
        "Q0.1": 250,
        "Q0.2": 149,
        "Q0.3": "yes",
        "Q0.3_count": 2,
        "Q0.3_equal": "yes",
    }
    result = engine.evaluate_state(answers=answers, workflow="secured_design_encoding")

    assert result["outcome"] != "CONTRADICTION"
    recon = result["reconstruction_state"]
    assert recon["segments"]["part1"]["length"] == 125
    assert recon["segments"]["part2"]["length"] == 125


def test_unequal_parts_enables_part1_probes(engine):
    """When Q0.3_equal='no', claimant is prompted for Part 1 length Q0.4, then Q0.5."""
    answers = {
        "Q0.1": 251,
        "Q0.2": 149,
        "Q0.3": "yes",
        "Q0.3_count": 2,
        "Q0.3_equal": "no",
    }
    eligible = engine.get_eligible_questions(answers=answers, workflow="secured_design_encoding")
    eligible_ids = [q.id for q in eligible]

    assert "Q0.4" in eligible_ids
    assert "Q0.5" not in eligible_ids

    # Answering Q0.4 enables Q0.5
    answers["Q0.4"] = 143
    eligible2 = engine.get_eligible_questions(answers=answers, workflow="secured_design_encoding")
    assert "Q0.5" in [q.id for q in eligible2]


# ============================================================================
# 4. UNITS STRUCTURE & UNSUPPORTED BRANCHES
# ============================================================================

def test_units_structure_unknown_results_in_incomplete(engine):
    """Q0.6_has_units='unknown' halts with INCOMPLETE."""
    answers = {
        "Q0.1": 251,
        "Q0.2": 149,
        "Q0.3": "yes",
        "Q0.3_count": 2,
        "Q0.3_equal": "no",
        "Q0.4": 143,
        "Q0.5": 76,
        "Q0.6_has_units": "unknown",
    }
    result = engine.evaluate_state(answers=answers, workflow="secured_design_encoding")

    assert result["outcome"].startswith("INCOMPLETE")
    assert "incomplete_reason" in result
    assert "unit" in result["incomplete_reason"].lower()
    assert engine.get_next_question(answers=answers, workflow="secured_design_encoding") is None


def test_unequal_unit_lengths_results_in_unsupported_branch(engine):
    """Non-uniform unit lengths (Q0.7='no') must yield UNSUPPORTED_BRANCH, NOT contradiction."""
    answers = {
        "Q0.1": 251,
        "Q0.2": 149,
        "Q0.3": "yes",
        "Q0.3_count": 2,
        "Q0.3_equal": "no",
        "Q0.4": 143,
        "Q0.5": 76,
        "Q0.6_has_units": "yes",
        "Q0.6": 13,
        "Q0.7": "no",
    }
    result = engine.evaluate_state(answers=answers, workflow="secured_design_encoding")

    assert result["outcome"].startswith("UNSUPPORTED_BRANCH")
    assert len(result["contradictions"]) == 0  # NOT a contradiction!
    assert "unsupported_branch_reason" in result
    assert "unit" in result["unsupported_branch_reason"].lower()
    assert result["reconstruction_state"]["stage"] == ReconstructionStage.STAGE_UNSUPPORTED
    assert engine.get_next_question(answers=answers, workflow="secured_design_encoding") is None


# ============================================================================
# 5. FIELDS STRUCTURE & WIDTH SUM CONSTRAINTS
# ============================================================================

def test_field_width_sum_mismatch_contradiction(engine):
    """Field widths summing to != unit length (11) triggers contradiction H0.11."""
    answers = {
        "Q0.1": 251,
        "Q0.2": 149,
        "Q0.3": "yes",
        "Q0.3_count": 2,
        "Q0.3_equal": "no",
        "Q0.4": 143,
        "Q0.5": 76,
        "Q0.6_has_units": "yes",
        "Q0.6": 13,
        "Q0.7": "yes",
        "Q0.8": 11,
        "Q0.9_has_fields": "yes",
        "Q0.9": 4,
        "Q0.10": "yes",
        "Q0.10b": "no",
        "Q0.11": 3,
        "Q0.12": 3,
        "Q0.13": 3,
        "Q0.14": 5,  # Sum = 14 != 11
    }
    result = engine.evaluate_state(answers=answers, workflow="secured_design_encoding")

    assert result["outcome"] == "CONTRADICTION"
    assert any("H0.11" in c or "Sum of field widths" in c for c in result["contradictions"])


def test_field_width_sum_match_accepted(engine):
    """Field widths A=3, B=3, C=3, D=2 sum to 11 and match the unit length."""
    answers = {
        "Q0.1": 251,
        "Q0.2": 149,
        "Q0.3": "yes",
        "Q0.3_count": 2,
        "Q0.3_equal": "no",
        "Q0.4": 143,
        "Q0.5": 76,
        "Q0.6_has_units": "yes",
        "Q0.6": 13,
        "Q0.7": "yes",
        "Q0.8": 11,
        "Q0.9_has_fields": "yes",
        "Q0.9": 4,
        "Q0.10": "yes",
        "Q0.10b": "no",
        "Q0.11": 3,
        "Q0.12": 3,
        "Q0.13": 3,
        "Q0.14": 2,  # Sum = 11 == 11
    }
    result = engine.evaluate_state(answers=answers, workflow="secured_design_encoding")

    assert result["outcome"] != "CONTRADICTION"
    recon = result["reconstruction_state"]
    assert recon["field_widths"] == {"A": 3, "B": 3, "C": 3, "D": 2}


# ============================================================================
# 6. RULE 5 BRANCHING (Q8.0 APPLICABILITY)
# ============================================================================

def test_rule5_applicability_no_clean_completion(engine):
    """When Part 1 is done and Q8.0='no', interrogation completes cleanly without Rule 5."""
    answers = get_canonical_143_answers()
    answers["Q8.0"] = "no"

    result = engine.evaluate_state(answers=answers, workflow="secured_design_encoding")

    assert result["outcome"].startswith("COMPLETE (Four-Rule Only")
    assert result["is_complete_143"] is True
    # Rule 5 register parity bits must NOT be fabricated
    recon = result["reconstruction_state"]
    assert len(recon["part2_cells"]) == 0 or all(not c["is_fixed"] for c in recon["part2_cells"])
    assert engine.get_next_question(answers=answers, workflow="secured_design_encoding") is None


# ============================================================================
# 7. NON-DESTRUCTIVE CORRECTION & DOWNSTREAM PRUNING
# ============================================================================

def test_manager_correction_prunes_downstream_invalidated_answers(manager):
    """Correcting Q0.3 from 'yes' to 'no' prunes part length probes while preserving history."""
    session = manager.create_session("TX-BRANCH-TEST", workflow="secured_design_encoding")

    # Step 1: Submit Q0.1, Q0.2, Q0.3='yes'
    manager.submit_answer(session.session_id, "Q0.1", 251)
    manager.submit_answer(session.session_id, "Q0.2", 149)
    manager.submit_answer(session.session_id, "Q0.3", "yes")
    manager.submit_answer(session.session_id, "Q0.3_count", 2)
    manager.submit_answer(session.session_id, "Q0.3_equal", "no")
    manager.submit_answer(session.session_id, "Q0.4", 143)
    manager.submit_answer(session.session_id, "Q0.5", 76)

    view1 = manager.get_session_view(session.session_id)
    assert view1["answers"]["Q0.4"] == 143
    assert len(view1["history_ledger"]) == 7

    # Step 2: Claimant submits correction to Q0.3 -> 'no' (monolithic)
    view2 = manager.submit_correction(session.session_id, "Q0.3", "no")

    # Audit history preserved
    assert len(view2["history_ledger"]) == 8
    assert view2["history_ledger"][-1]["is_correction"] is True
    assert view2["history_ledger"][-1]["corrected_entry_id"] is not None

    # Effective answers must have pruned downstream part probes
    assert view2["answers"]["Q0.3"] == "no"
    assert "Q0.4" not in view2["answers"]
    assert "Q0.5" not in view2["answers"]
    assert "Q0.3_count" not in view2["answers"]
    assert "Q0.3_equal" not in view2["answers"]


def test_manager_correction_resolves_contradiction(manager):
    """Correcting an indivisible equal-parts answer resolves the contradiction."""
    session = manager.create_session("TX-CONTRA-REPAIR", workflow="secured_design_encoding")

    manager.submit_answer(session.session_id, "Q0.1", 251)
    manager.submit_answer(session.session_id, "Q0.2", 149)
    manager.submit_answer(session.session_id, "Q0.3", "yes")
    manager.submit_answer(session.session_id, "Q0.3_count", 2)
    view_contra = manager.submit_answer(session.session_id, "Q0.3_equal", "yes")

    assert view_contra["status"] == "CONTRADICTION"
    assert view_contra["current_question"] is None

    # Claimant corrects Q0.3_equal to 'no'
    view_fixed = manager.submit_correction(session.session_id, "Q0.3_equal", "no")

    assert view_fixed["status"] != "CONTRADICTION"
    assert view_fixed["current_question"] is not None
    assert view_fixed["current_question"]["id"] == "Q0.4"


# ============================================================================
# 8. BACKWARD COMPATIBILITY WITH CANONICAL BUTTERWORTH
# ============================================================================

def test_canonical_butterworth_composite_answers_backward_compatible(engine):
    """Legacy integer answers (Q0.3=2, Q0.6=13, Q0.9=4) still evaluate without modification."""
    legacy_answers = get_canonical_143_answers()
    result = engine.evaluate_state(answers=legacy_answers, workflow="unsecured_structural_encoding")

    assert result["outcome"] != "CONTRADICTION"
    assert result["is_complete_143"] is True
    recon = result["reconstruction_state"]
    assert recon["branch_info"]["parts_divided"] == "yes"
    assert recon["branch_info"]["parts_count"] == 2
    assert recon["branch_info"]["has_units"] == "yes"
    assert recon["branch_info"]["num_units"] == 13
    assert recon["branch_info"]["has_fields"] == "yes"
    assert recon["branch_info"]["fields_per_unit"] == 4
    # 143 total reconstructed cells (131 observed+derived, 12 inferred)
    reconstructed_p1 = [c for c in recon["part1_cells"] if c["value"] is not None]
    assert len(reconstructed_p1) == 143
    fixed_p1 = [c for c in recon["part1_cells"] if c["is_fixed"]]
    assert len(fixed_p1) == 131
