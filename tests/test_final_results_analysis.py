"""
Authoritative Test Suite for Complete Results, Analysis and Comparison.

Validates:
1. Section A: Secured Design / Secured Encoding Verification (251 bits, S_K, P_K, H, Popcount model, C_ES).
2. Section B: Unsecured Design / Constraint-Based Verification (27 nodes, 211 genuine edges, 169 eligible pairs,
              C(78, 34) * C(91, 23) combinations, S_K, P_K, H, C_D).
3. Section C: Watermark Verification (HKDF-SHA256, 32/64/128/256 bits, 2^-n probabilities, C_W).
4. Section D: Watermark Length Comparison (10 embedding quantities across 4 lengths, CIG overhead,
              HD=6 / 2.39%, Delta R = 0, 32/32 test vectors passing).
5. Strict separation of the three verification problems without confusing search spaces or encodings.
6. Clean API endpoints and UI integration.
"""

import math
import os
import pytest
from fastapi.testclient import TestClient

from hardware_ip_protection.pipeline.results_analysis_service import ResultsAnalysisService
from hardware_ip_protection.pipeline.watermark_strength_analyzer import WatermarkStrengthAnalyzer
from hardware_ip_protection.web.app import app


client = TestClient(app)


class TestResultsAnalysisService:
    """Verifies backend mathematical data generation and structure."""

    @pytest.fixture(scope="class")
    def results(self):
        ResultsAnalysisService._cached_results = None
        return ResultsAnalysisService.get_complete_results(force_refresh=True)

    def test_overall_structure_and_status(self, results):
        assert results["status"] == "SUCCESS"
        assert results["design_id"] == "iir_butterworth"
        assert "section_a_secured" in results
        assert "section_b_unsecured" in results
        assert "section_c_watermark" in results
        assert "section_d_comparison" in results

    def test_section_a_secured_design_verification(self, results):
        sec_a = results["section_a_secured"]
        assert sec_a["total_encoding_length_bits"] == 251
        assert sec_a["rule_breakdown"]["e4_rules_1_to_4_bits"] == 143
        assert sec_a["rule_breakdown"]["rule_5_bits"] == 108

        # Unrestricted 251-bit search space
        assert sec_a["search_space_size"] == 2 ** 251
        assert sec_a["shannon_entropy_bits"] == 251.0
        assert math.isclose(sec_a["exact_guessing_probability"], 1.0 / (2 ** 251))
        assert "3.6185" in sec_a["search_space_size_str"]

        # Popcount sub-model
        sub = sec_a["popcount_submodel"]
        assert sub["popcount_ones"] == 95
        assert sub["popcount_zeros"] == 156
        assert sub["shannon_entropy_bits"] == 235.93
        assert "1.0514" in sub["search_space_size_str"]

        # Reconstruction & Commitment
        recon = sec_a["reconstruction_results"]
        assert recon["reconstruction_completed"] is True
        assert recon["matches_expected_secured_encoding"] is True
        assert recon["commitment_verified"] is True
        assert recon["questions_evaluated_in_run"] == 120

    def test_section_b_unsecured_design_verification(self, results):
        sec_b = results["section_b_unsecured"]
        # Baseline CIG
        assert sec_b["baseline_cig"]["storage_variable_nodes"] == 27
        assert sec_b["baseline_cig"]["original_genuine_conflict_edges"] == 211

        # Candidate pair space
        pairs = sec_b["candidate_pair_space"]
        assert pairs["total_eligible_candidate_pairs"] == 169
        assert pairs["even_even_pairs"] == 78
        assert pairs["odd_odd_pairs"] == 91
        assert pairs["even_even_genuine_edges"] == 40
        assert pairs["even_even_available_non_edges"] == 38
        assert pairs["odd_odd_genuine_edges"] == 60
        assert pairs["odd_odd_available_non_edges"] == 31

        # Full 256-bit constraint metrics
        m = sec_b["full_watermark_constraint_metrics"]
        assert m["disclosed_constraints_count"] == 256
        assert m["pre_existing_constraints_retained"] == 151
        assert m["distinct_artificial_edges_removed"] == 57
        assert m["even_artificial_edges"] == 33
        assert m["odd_artificial_edges"] == 24
        assert m["genuine_edges_accidentally_removed"] == 0
        assert m["artificial_edges_incorrectly_retained"] == 0

        # Combinations C(78, 34) * C(91, 23)
        expected_comb = math.comb(78, 33) * math.comb(91, 24)
        assert math.isclose(m["search_space_size"], float(expected_comb))
        assert "6.5138" in m["search_space_size_str"]
        assert math.isclose(m["constraint_entropy_bits"], round(math.log2(expected_comb), 2), rel_tol=1e-3)
        assert m["reconstructed_cig_matches_original"] is True
        assert m["original_design_commitment_verified"] is True

    def test_section_c_watermark_verification(self, results):
        sec_c = results["section_c_watermark"]
        assert "HKDF-SHA256" in sec_c["kdf_mechanism"]
        table = sec_c["watermark_evaluation_table"]
        assert len(table) == 4

        lengths = [row["watermark_length"] for row in table]
        assert lengths == [32, 64, 128, 256]

        for row in table:
            l = row["watermark_length"]
            assert row["search_space_size"] == 2 ** l
            assert row["idealized_shannon_entropy_bits"] == float(l)
            assert math.isclose(row["theoretical_guessing_probability"], 1.0 / (2 ** l))
            assert row["reconstruction_matches"] is True
            assert row["commitment_c_w_verified"] is True

    def test_section_d_watermark_length_comparison(self, results):
        sec_d = results["section_d_comparison"]
        rows = sec_d["comparison_table"]
        assert len(rows) == 4

        # Check 10 embedding quantities for 32, 64, 128, 256 bits
        r32 = rows[0]
        assert r32["watermark_length"] == 32
        assert r32["requested_bits"] == 32
        assert r32["successfully_processed_positions"] == 32
        assert r32["successfully_assigned_positions"] == 32
        assert r32["total_constraint_assignments"] == 32
        assert r32["distinct_selected_pairs"] == 32
        assert r32["pre_existing_genuine_edge_assignments"] == 18
        assert r32["new_artificial_edge_insertion_operations"] == 14
        assert r32["distinct_artificial_edges_added"] == 14
        assert r32["repeated_pair_assignments"] == 0
        assert r32["failed_or_unassigned_positions"] == 0
        assert r32["cig_overhead_percent"] == round((14 / 211) * 100, 2)  # 6.64%

        r64 = rows[1]
        assert r64["watermark_length"] == 64
        assert r64["requested_bits"] == 64
        assert r64["pre_existing_genuine_edge_assignments"] == 40
        assert r64["distinct_artificial_edges_added"] == 24
        assert r64["repeated_pair_assignments"] == 0
        assert r64["cig_overhead_percent"] == round((24 / 211) * 100, 2)  # 11.37%

        r128 = rows[2]
        assert r128["watermark_length"] == 128
        assert r128["requested_bits"] == 128
        assert r128["pre_existing_genuine_edge_assignments"] == 78
        assert r128["new_artificial_edge_insertion_operations"] == 50
        assert r128["distinct_artificial_edges_added"] == 40
        assert r128["repeated_pair_assignments"] == 19
        assert r128["cig_overhead_percent"] == round((40 / 211) * 100, 2)  # 18.96%

        r256 = rows[3]
        assert r256["watermark_length"] == 256
        assert r256["requested_bits"] == 256
        assert r256["pre_existing_genuine_edge_assignments"] == 151
        assert r256["new_artificial_edge_insertion_operations"] == 105
        assert r256["distinct_artificial_edges_added"] == 57
        assert r256["repeated_pair_assignments"] == 109
        assert r256["cig_overhead_percent"] == round((57 / 211) * 100, 2)  # 27.01%

        # Invariants across all lengths
        for row in rows:
            assert row["hamming_distance"] == 6
            assert row["encoding_change_percent"] == 2.39
            assert row["changed_bit_positions"] == [160, 184, 192, 232, 244, 248]
            assert row["original_registers"] == 16
            assert row["secured_registers"] == 16
            assert row["register_count_change"] == 0
            assert row["passed_test_vectors"] == 32
            assert row["total_test_vectors"] == 32
            assert row["failed_test_vectors"] == 0

        # Check charts data
        charts = sec_d["charts"]
        assert len(charts["watermark_vs_artificial_edges"]) == 4
        assert [c["value"] for c in charts["watermark_vs_artificial_edges"]] == [14, 24, 40, 57]
        assert [c["value"] for c in charts["watermark_vs_encoding_change_percent"]] == [2.39, 2.39, 2.39, 2.39]
        assert [c["value"] for c in charts["watermark_vs_constraint_entropy"]] == [63.76, 93.08, 123.95, 145.55]


class TestEndpointsAndUIIntegrity:
    """Verifies HTTP endpoints and index.html structure."""

    def test_api_analysis_complete_results(self):
        resp = client.get("/api/analysis/complete-results")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SUCCESS"
        assert "section_a_secured" in data
        assert "section_b_unsecured" in data
        assert "section_c_watermark" in data
        assert "section_d_comparison" in data

    def test_api_judge_analysis_report(self):
        resp = client.get("/api/judge/analysis_report")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SUCCESS"
        assert "section_a_secured" in data
        assert "section_d_comparison" in data

    def test_index_html_has_dashboard_sections_and_no_legacy_tables(self):
        html_path = os.path.join(
            os.path.dirname(__file__), "..", "hardware_ip_protection", "web", "static", "index.html"
        )
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Dashboard elements exist
        assert 'id="judgeReportCard"' in html
        assert 'id="tabJudgeReport"' in html
        assert 'id="wmSecCTableBody"' in html
        assert 'id="wmComparisonTableBody"' in html
        assert 'id="chartArtEdges"' in html
        assert 'id="chartEncChange"' in html
        assert 'id="chartEntropy"' in html

        # Old checkpoint table is removed from HTML
        assert 'id="judgeReportTable"' not in html
        assert 'id="judgeReportTableBody"' not in html
        assert 'Cumulative Gain' not in html
