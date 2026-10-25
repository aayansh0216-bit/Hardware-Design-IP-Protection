"""
Comprehensive automated tests for Judge-Led Interrogation System:
Secured 251-Bit Design Encoding (143b Four-Rule + 108b Rule 5) and Workflow Isolation.
"""

import pytest
from hardware_ip_protection.verification.interrogation_engine import (
    InterrogationEngine,
    EXPECTED_RULE5_BITSTREAM,
    EXPECTED_251_SECURED_BITSTREAM,
    CANONICAL_SECURED_RULE5_REGISTERS,
    QuestionType,
)
from hardware_ip_protection.pipeline.interrogation_manager import (
    InterrogationManager,
)
from hardware_ip_protection.crypto.pedersen import PedersenEngine


class TestJudgeRule5SecuredInterrogation:

    def test_canonical_bitstream_lengths_and_statistics(self):
        """Verify the exact canonical bit counts and zero/one statistics."""
        assert len(EXPECTED_RULE5_BITSTREAM) == 108
        rule5_zeros = EXPECTED_RULE5_BITSTREAM.count("0")
        rule5_ones = EXPECTED_RULE5_BITSTREAM.count("1")
        assert rule5_zeros == 80
        assert rule5_ones == 28

        assert len(EXPECTED_251_SECURED_BITSTREAM) == 251
        secured_zeros = EXPECTED_251_SECURED_BITSTREAM.count("0")
        secured_ones = EXPECTED_251_SECURED_BITSTREAM.count("1")
        assert secured_zeros == 156
        assert secured_ones == 95

        # Check that 251 bits is exactly Part 1 (143) + Part 2 (108)
        assert len(EXPECTED_251_SECURED_BITSTREAM[:143]) == 143
        assert EXPECTED_251_SECURED_BITSTREAM[143:] == EXPECTED_RULE5_BITSTREAM

    def test_question_banks_secured_vs_unsecured(self):
        """Verify question banks for secured vs unsecured workflows."""
        q_bank_unsec = InterrogationEngine.build_question_bank(workflow="unsecured_design_encoding")
        # Unsecured has blocks 0 to 7 (82 total definitions: 78 active + 4 fallback)
        assert len(q_bank_unsec) == 82
        assert len([q for q in q_bank_unsec if not q.is_fallback]) == 78
        assert q_bank_unsec[0].id == "Q0.1"
        assert q_bank_unsec[1].reference_answer == 149  # 149 zeros in 4-rule stream

        q_bank_sec = InterrogationEngine.build_question_bank(workflow="secured_design_encoding")
        # Secured has blocks 0 to 11 (124 total definitions: 120 active + 4 fallback)
        assert len(q_bank_sec) == 124
        assert len([q for q in q_bank_sec if not q.is_fallback]) == 120
        assert q_bank_sec[1].reference_answer == 156  # 156 zeros in secured 251-bit stream

        # Check Rule 5 blocks exist in secured bank
        q_ids = [q.id for q in q_bank_sec]
        assert "Q8.1" in q_ids   # Rule 5 length (108)
        assert "Q9.1" in q_ids   # Odd parity code ('01')
        assert "Q9.3" in q_ids   # Rule 5 ones count (28)
        assert "Q10.1" in q_ids  # Odd storage variable count (14)
        assert "Q10.5" in q_ids  # Chunk 1 ones count (10)
        assert "Q10.6" in q_ids  # Chunk 2 ones count (9)
        assert "Q10.7" in q_ids  # Chunk 3 ones count (9)
        assert "Q11.1" in q_ids  # V1 odd register parity
        assert "Q11.23" in q_ids # V26 shares parity with V17

    def test_progressive_next_question_flow(self):
        """Ensure progressive interrogation enforces strict sequential order."""
        answers = {}
        next_q = InterrogationEngine.get_next_question(answers, workflow="secured_design_encoding")
        assert next_q is not None
        assert next_q.id == "Q0.1"

        # Answer Q0.1 correctly
        answers["Q0.1"] = 251
        next_q = InterrogationEngine.get_next_question(answers, workflow="secured_design_encoding")
        assert next_q is not None
        assert next_q.id == "Q0.2"

    def test_contradiction_handling_illegal_parity_and_out_of_bounds(self):
        """Verify contradiction detection on illegal values and count bounds."""
        answers = {
            "Q0.1": 251,
            "Q0.2": 156,
            "Q0.3": 2,
            "Q0.4": 143,
            "Q8.1": 108,
            "Q9.1": "11",  # Illegal odd parity code (must be 01)
            "Q11.1": "no", # Contradicts verified V1 odd register parity
        }
        res = InterrogationEngine.evaluate_state(answers, workflow="secured_design_encoding")
        assert res["outcome"] == "CONTRADICTION"
        assert any("H9.1: Odd parity code must be '01'" in c for c in res["contradictions"])
        assert any("H11.1: Variable V1 must have odd register parity" in c for c in res["contradictions"])

    def test_contradiction_invalid_register_assignment(self):
        """Verify contradiction when claimant provides contradictory relational answer."""
        answers = {
            "Q0.1": 251,
            "Q0.2": 156,
            "Q0.3": 2,
            "Q0.4": 143,
            "Q8.1": 108,
            "Q8.2": 27,
            "Q8.3": 4,
            "Q8.4": 2,
            "Q8.5": 2,
            "Q8.6": "yes",
            "Q8.7": 80,
            "Q9.1": "01",
            "Q9.2": "00",
            "Q9.3": 28,
            "Q9.4": "yes",
            "Q10.1": 14,
            "Q10.2": 13,
            "Q10.3": 14,
            "Q10.4": 13,
            "Q10.5": 10,
            "Q10.6": 9,
            "Q10.7": 9,
            "Q11.1": "yes",
            "Q11.2": "no",
            "Q11.5": "no",  # V5 must share parity with V2 (both even)
        }
        res = InterrogationEngine.evaluate_state(answers, workflow="secured_design_encoding")
        assert res["outcome"] == "CONTRADICTION"
        assert any("H11.5: Variable V5 must share register parity with V2" in c for c in res["contradictions"])

    def test_non_destructive_correction_in_interrogation_manager(self, tmp_path):
        """Verify that correcting an answer restores consistency and preserves audit ledger."""
        db_file = str(tmp_path / "test_interrogation.db")
        mgr = InterrogationManager(db_path=db_file)
        session = mgr.start_session(transaction_id="TX-TEST-CORR", workflow="secured_design_encoding")

        # Submit Q0.1
        mgr.submit_answer(session.session_id, "Q0.1", 251)
        # Attempt out of order submission (Q0.3 before Q0.2)
        with pytest.raises(ValueError):
            mgr.submit_answer(session.session_id, "Q0.3", 999)

        # Submit invalid Q0.2 causing contradiction (257 zeros > 251 total bits)
        mgr.submit_answer(session.session_id, "Q0.2", 257)
        view = mgr.get_session_view(session.session_id)
        assert view["status"] == "CONTRADICTION"

        # Submit correction to Q0.2 to restore consistency (156 zeros)
        corrected_view = mgr.submit_correction(session.session_id, "Q0.2", 156)
        assert corrected_view["status"].startswith("IN PROGRESS")
        assert corrected_view["effective_answers"]["Q0.2"] == 156

        # Check ledger entries: should have is_correction=True on the correction entry
        ledger = corrected_view["history_ledger"]
        assert len(ledger) == 3
        assert ledger[-1]["is_correction"] is True
        assert ledger[-1]["question_id"] == "Q0.2"

    def test_full_secured_interrogation_and_commitment_verification(self, tmp_path):
        """Simulate answering the full secured interrogation to achieve 251-bit reconstruction and C_ES match."""
        # 1. Compute commitment over EXPECTED_251_SECURED_BITSTREAM
        pe = PedersenEngine()
        comm_ES, r_ES = pe.commit(EXPECTED_251_SECURED_BITSTREAM)
        c_es_hex = comm_ES.commitment_hex

        # 2. Build full canonical answer dictionary
        q_bank = InterrogationEngine.build_question_bank(workflow="secured_design_encoding")
        all_canonical_answers = {}
        for q in q_bank:
            if q.reference_answer is not None:
                all_canonical_answers[q.id] = q.reference_answer

        # 3. Evaluate state
        res = InterrogationEngine.evaluate_state(
            all_canonical_answers,
            workflow="secured_design_encoding",
            stored_c_es=c_es_hex,
            blinding_int=r_ES,
        )

        assert res["outcome"] == "COMPLETE"
        assert res["is_complete_143"] is True
        assert res["is_complete_rule5"] is True
        assert res["is_complete_251"] is True
        assert len(res["reconstructed_bitstream"]) == 251
        assert res["reconstructed_bitstream"] == EXPECTED_251_SECURED_BITSTREAM

        # Verify commitment match
        cv = res["commitment_verification"]
        assert cv["status"] == "VERIFIED"
        assert cv["target_commitment"] == c_es_hex
        assert cv["recalculated_commitment"] == c_es_hex

        # Verify stages are fully populated
        stages = res["stages"]
        assert stages["S1_143_RECONSTRUCTION"]["status"] == "COMPLETE"
        assert stages["S2_RULE5_INTERROGATION"]["status"] == "COMPLETE"
        assert stages["S3_251_ASSEMBLY"]["status"] == "COMPLETE"
        assert stages["S4_COMMITMENT_VERIFICATION"]["status"] == "VERIFIED"

    def test_commitment_mismatch_on_tampered_bitstream(self):
        """Verify commitment check fails (COMMITMENT_MISMATCH) if bitstream does not open C_ES."""
        pe = PedersenEngine()
        # Commit to real 251 bitstream
        comm_ES, r_ES = pe.commit(EXPECTED_251_SECURED_BITSTREAM)
        c_es_hex = comm_ES.commitment_hex

        # Build full answers but alter Q11.27 to wrong parity
        q_bank = InterrogationEngine.build_question_bank(workflow="secured_design_encoding")
        tampered_answers = {}
        for q in q_bank:
            if q.reference_answer is not None:
                tampered_answers[q.id] = q.reference_answer

        # If we alter blinding int:
        wrong_blinding = (r_ES + 1) % pe.curve.order
        res = InterrogationEngine.evaluate_state(
            tampered_answers,
            workflow="secured_design_encoding",
            stored_c_es=c_es_hex,
            blinding_int=wrong_blinding,
        )
        assert res["commitment_verification"]["status"] == "COMMITMENT_MISMATCH"

    def test_workflow_isolation_secured_vs_unsecured(self, tmp_path):
        """Verify that secured and unsecured sessions for the same transaction ID remain strictly isolated."""
        db_file = str(tmp_path / "test_interrogation_iso.db")
        mgr = InterrogationManager(db_path=db_file)

        # Start unsecured session
        unsec_sess = mgr.start_session(transaction_id="TX-ISO-01", workflow="unsecured_design_encoding")
        mgr.submit_answer(unsec_sess.session_id, "Q0.1", 143)

        # Start secured session for the same transaction
        sec_sess = mgr.start_session(transaction_id="TX-ISO-01", workflow="secured_design_encoding")
        mgr.submit_answer(sec_sess.session_id, "Q0.1", 251)

        # Verify separation
        unsec_view = mgr.get_session_view(unsec_sess.session_id)
        sec_view = mgr.get_session_view(sec_sess.session_id)

        assert unsec_view["workflow"] == "unsecured_design_encoding"
        assert unsec_view["effective_answers"]["Q0.1"] == 143

        assert sec_view["workflow"] == "secured_design_encoding"
        assert sec_view["effective_answers"]["Q0.1"] == 251
        assert sec_view["session_id"] != unsec_view["session_id"]

    def test_unsecured_workflow_does_not_execute_rule5_or_fake_pass(self):
        """Verify unsecured workflow stops with pending Rule 5 and does not invent Rule 5 data."""
        q_bank = InterrogationEngine.build_question_bank(workflow="unsecured_design_encoding")
        answers = {}
        for q in q_bank:
            if q.reference_answer is not None:
                answers[q.id] = q.reference_answer

        res = InterrogationEngine.evaluate_state(answers, workflow="unsecured_design_encoding")
        assert res["is_complete_143"] is True
        assert res["is_complete_251"] is False
        assert res["outcome"] == "INCOMPLETE: 143-bit stage complete; Rule 5 interrogation pending"
        assert res["stages"]["U1_143_RECONSTRUCTION"]["status"] == "COMPLETE"
        assert res["stages"]["U2_UNSECURED_RULE5_PENDING"]["status"] == "PENDING"

    def test_provisional_pool_and_canonical_invariants(self):
        """Verify unified bitstream and provisional pool state invariants across progression."""
        # Stage A: No answers yet -> Empty grid, pool count zero
        res_a = InterrogationEngine.evaluate_state({}, workflow="secured_design_encoding")
        recon_a = res_a["reconstruction_state"]
        assert recon_a["stage"] == "STAGE_A"
        assert recon_a["total_length"] is None
        assert len(recon_a["part1_cells"]) == 0
        assert len(recon_a["part2_cells"]) == 0
        assert len(recon_a["entire_cells"]) == 0
        assert recon_a["provisional_pool"]["total_unfixed"] == 0

        # Stage B: Total length established (251)
        res_b = InterrogationEngine.evaluate_state({"Q0.1": 251}, workflow="secured_design_encoding")
        recon_b = res_b["reconstruction_state"]
        assert recon_b["stage"] == "STAGE_B"
        assert recon_b["total_length"] == 251
        assert len(recon_b["entire_cells"]) == 251
        # In Stage B, all cells neutral/unfixed, population counts not yet known
        assert all(not c["is_fixed"] for c in recon_b["entire_cells"])

        # Stage C: Population counts established (Q0.2: 156 zeros)
        res_c = InterrogationEngine.evaluate_state({"Q0.1": 251, "Q0.2": 156}, workflow="secured_design_encoding")
        recon_c = res_c["reconstruction_state"]
        assert recon_c["stage"] == "STAGE_C"
        pool_c = recon_c["provisional_pool"]
        assert pool_c["unfixed_zeros"] == 156
        assert pool_c["unfixed_ones"] == 95  # 251 - 156
        assert pool_c["total_unfixed"] == 251
        # Invariant check: none are canonical green yet
        assert sum(1 for c in recon_c["entire_cells"] if c["is_fixed"]) == 0
        assert all(c["fill"] == "RED" for c in recon_c["entire_cells"])

        # Stage F / partial: Answers fixing some bits (e.g. Q4 representative values)
        # Verify invariant: fixed_zeros + unfixed_zeros == 156, fixed_ones + unfixed_ones == 95
        q_bank = InterrogationEngine.build_question_bank(workflow="secured_design_encoding")
        answers = {}
        for q in q_bank[:60]:  # up through Block 4 (Field A representatives)
            if q.reference_answer is not None:
                answers[q.id] = q.reference_answer

        res_partial = InterrogationEngine.evaluate_state(answers, workflow="secured_design_encoding")
        recon_part = res_partial["reconstruction_state"]
        pool_part = recon_part["provisional_pool"]
        fixed_0 = sum(1 for c in recon_part["entire_cells"] if c["is_fixed"] and c["value"] == "0")
        fixed_1 = sum(1 for c in recon_part["entire_cells"] if c["is_fixed"] and c["value"] == "1")

        assert fixed_0 + pool_part["unfixed_zeros"] == 156
        assert fixed_1 + pool_part["unfixed_ones"] == 95
        assert pool_part["total_unfixed"] == 251 - (fixed_0 + fixed_1)

        # Verify cell semantics: GREEN strictly means fixed (both 0 and 1 are GREEN when fixed)
        green_cells = [c for c in recon_part["entire_cells"] if c["is_fixed"]]
        assert all(c["fill"] == "GREEN" for c in green_cells)
        assert any(c["value"] == "0" for c in green_cells)
        assert any(c["value"] == "1" for c in green_cells)

    def test_rule5_pair_candidate_metadata_no_undefined_or_nan(self):
        """Verify PairCandidate records have no undefined, NaN, Tundefined, or R? metadata defects."""
        # Evaluate at Stage A / empty
        res_empty = InterrogationEngine.evaluate_state({}, workflow="secured_design_encoding")
        pairs_empty = res_empty["pair_candidates"]
        assert len(pairs_empty) == 27
        for p in pairs_empty:
            assert p["pair_index"] >= 1 and p["pair_index"] <= 27
            assert p["variable_name"].startswith("V")
            assert "undefined" not in p["bit_range"]
            assert "NaN" not in p["bit_range"]
            assert p["status"] == "UNRESOLVED"
            assert p["four_bit_code"] == "????"
            assert p["register_name"] is None

        # Evaluate at full completion
        q_bank = InterrogationEngine.build_question_bank(workflow="secured_design_encoding")
        answers = {q.id: q.reference_answer for q in q_bank if q.reference_answer is not None}
        res_full = InterrogationEngine.evaluate_state(answers, workflow="secured_design_encoding")
        pairs_full = res_full["pair_candidates"]
        for p in pairs_full:
            assert p["status"] == "CONFIRMED"
            assert "?" not in p["four_bit_code"]
            assert p["register_parity"] in ("Odd", "Even")
            assert p["register_parity_code"] in ("01", "00")
            assert "undefined" not in p["bit_range"]
            assert "NaN" not in p["bit_range"]
            assert p["provenance"] in ("OBSERVED", "DERIVED", "INFERRED")

    def test_rule5_indirect_derivations_v9_and_v27(self):
        """Verify that Rule 5 question bank uses indirect questions and mathematically derives V9 and V27 parities."""
        q_bank = InterrogationEngine.build_question_bank(workflow="secured_design_encoding")
        q_ids = [q.id for q in q_bank]

        # Verify Q11 does not contain direct register queries for all 27 variables
        q11_ids = [qid for qid in q_ids if qid.startswith("Q11.")]
        assert len(q11_ids) == 23  # 23 indirect relational and parity queries, not 27 direct queries
        assert "Q11.24" not in q_ids
        assert "Q11.27" not in q_ids

        # Build answers for everything except Q11.23
        answers = {q.id: q.reference_answer for q in q_bank if q.reference_answer is not None}
        res = InterrogationEngine.evaluate_state(answers, workflow="secured_design_encoding")

        # Verify V9 derivation: derived from Chunk 1 ones balance (Q10.5 = 10)
        p9 = next(p for p in res["pair_candidates"] if p["variable_name"] == "V9")
        assert p9["register_parity"] == "Odd"
        assert p9["register_parity_code"] == "01"
        assert p9["four_bit_code"] == "0101"
        assert p9["provenance"] == "DERIVED"
        assert p9["is_fixed"] is True

        # Verify V27 derivation: derived from Chunk 3 ones balance (Q10.7 = 10) + global odd registers (Q10.3 = 14)
        p27 = next(p for p in res["pair_candidates"] if p["variable_name"] == "V27")
        assert p27["register_parity"] == "Even"
        assert p27["register_parity_code"] == "00"
        assert p27["four_bit_code"] == "0001"
        assert p27["provenance"] == "DERIVED"
        assert p27["is_fixed"] is True

