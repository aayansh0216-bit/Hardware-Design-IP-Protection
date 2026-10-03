"""
Verification of live web server endpoints and UI assets for:
1. Scenario selection not running verification.
2. Explicit commitment verification buttons.
3. Top summary cards with [Check] links.
4. Renamed behavioral output metrics.
5. Report header layout with Download Evidence button.
"""

import urllib.request
import json
import re
import pytest


def test_live_web_assets_and_endpoints():
    base_url = "http://127.0.0.1:8000"

    # 1. Fetch index.html
    with urllib.request.urlopen(f"{base_url}/") as response:
        html = response.read().decode("utf-8")

    assert "FORENSIC VERIFICATION REPORT" in html
    assert "Exact Output Matches" in html
    assert "Exact Output Mismatches" in html
    assert "Exact Output Match Rate" in html
    assert "For each shared test input, the complete reference and suspicious output vectors are compared bit-for-bit." in html
    assert 'id="downloadEvidenceBtn"' in html
    assert 'id="dispDesignLabel"' in html
    assert 'id="dispScenarioBadge"' in html
    assert "[Check]" in html
    assert 'id="cardWmCommitCheck"' in html
    assert 'id="cardTvCommitCheck"' in html
    assert 'id="btnVerifyWmComm"' in html
    assert 'id="btnVerifyTvComm"' in html

    # 2. Fetch app.js
    with urllib.request.urlopen(f"{base_url}/app.js") as response:
        js = response.read().decode("utf-8")

    assert "resetDisputePendingState" in js
    # Preset selection must not call executeDisputeVerification
    preset_match = re.search(r"function initAttackPresets\(\)\s*\{([\s\S]*?)\n\}", js)
    assert preset_match is not None
    assert "executeDisputeVerification" not in preset_match.group(1)

    # 3. Test API /api/benchmarks
    with urllib.request.urlopen(f"{base_url}/api/benchmarks") as response:
        bm = json.loads(response.read().decode("utf-8"))
    assert len(bm["benchmarks"]) > 0

    # 4. Test API /api/protect
    protect_payload = {
        "benchmark_id": "4point_dct",
        "transaction_id": "TX-LIVE-2026",
        "seller_id": "SELLER-01",
        "buyer_id": "BUYER-01",
        "license_type": "exclusive",
        "k_tx": "secret-key-live-123",
        "watermark_length": 8,
    }
    req_prot = urllib.request.Request(
        f"{base_url}/api/protect",
        data=json.dumps(protect_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req_prot) as response:
        prot_data = json.loads(response.read().decode("utf-8"))
    prot_id = prot_data["protection_id"]

    # 5. Test API /api/attack_preset
    preset_payload = {
        "protection_id": prot_id,
        "preset_type": "partial_tamper",
    }
    req_preset = urllib.request.Request(
        f"{base_url}/api/attack_preset",
        data=json.dumps(preset_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req_preset) as response:
        preset_res = json.loads(response.read().decode("utf-8"))
    assert len(preset_res["suspicious_verilog"]) > 50

    # 6. Test API /api/dispute (Untouched)
    dispute_payload = {
        "protection_id": prot_id,
        "suspicious_verilog": prot_data["protected_verilog"],
        "scenario": "Untouched Design",
    }
    req_disp = urllib.request.Request(
        f"{base_url}/api/dispute",
        data=json.dumps(dispute_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req_disp) as response:
        disp_data = json.loads(response.read().decode("utf-8"))

    # Verification of Consolidated Refinement Pass UI Requirements
    # 1. Header cleanup (Requirements 16, 17, 42)
    assert "CIG Register Watermarking &bull; NIST P-256 Pedersen Commitments" not in html
    assert "SPEC V1.0" not in html
    assert "P-256 LIVE" not in html

    # 2. Top Summary Cards (Requirements 1, 3)
    assert 'id="dispMetricBehavior"' in html
    assert 'id="dispMetricExtraction"' in html
    assert 'id="dispMetricSimilarity"' in html
    assert "Forensic Similarity" in html
    assert 'id="dispMetricWmComm"' in html
    assert 'id="dispMetricTvComm"' in html

    # 3. Behavioral Verification & Correlation Heatmaps (Requirements 6, 7, 8, 37)
    assert "Correlation L1 Distance" in html
    assert 'id="repL1Dist"' in html
    assert 'id="refHeatmapCanvas"' in html
    assert 'id="susHeatmapCanvas"' in html
    assert 'id="diffHeatmapCanvas"' not in html
    assert 'id="heatmapTooltip"' in html

    # 4. Top Report Header JSON Viewer (Requirements 10, 11, 12, 13)
    assert 'id="rawJsonDetails"' in html
    assert 'id="evidenceJsonBox"' in html
    assert 'id="downloadEvidenceBtn"' in html

    # 5. Cryptographic Commitment UI (Requirements 18, 22, 23, 24)
    assert "Reference Commitment Check" in html
    assert "Test-Vector Commitment Check" in html
    assert "Suspicious vs Stored Commitment" not in html
    assert "Commitment C:" in html
    assert "Generator G:" in html
    assert "Generator H:" in html

    # Verify app.js draws heatmaps
    assert "drawHeatmap" in js
    assert "clearHeatmap" in js

    # Verify dispute behavioral verification results
    bv = disp_data["dispute_result"]["behavioral_verification"]
    assert bv["exact_output_matches"] == bv["total_test_vectors"]
    assert bv["exact_output_mismatches"] == 0
    assert bv["exact_output_match_rate"] == 1.0
    assert bv["hamming_distance"] == 0
    assert bv["hamming_similarity"] == 1.0

    # Verify Correlation L1 Distance in Untouched Design (Requirement 1, 17)
    ca = bv["correlation_analysis"]
    assert ca is not None
    assert "signals" in ca
    assert "reference_correlation_matrix" in ca
    assert "suspicious_correlation_matrix" in ca
    assert "correlation_difference_matrix" in ca
    assert ca["l1_distance"] == 0.0
    assert ca["normalized_l1_distance"] == 0.0

    comp = disp_data["comparison"]
    assert comp["l1_distance"] == 0.0
    assert comp["normalized_l1_distance"] == 0.0

    # 7. Test API /api/dispute with Independent Design (Requirement 1)
    indep_payload = {
        "protection_id": prot_id,
        "suspicious_verilog": "module independent_module(input clk, rst, a, b, output reg [31:0] out); always @(posedge clk) out <= a ^ b; endmodule",
        "scenario": "Independent Design",
    }
    req_indep = urllib.request.Request(
        f"{base_url}/api/dispute",
        data=json.dumps(indep_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req_indep) as response:
        indep_data = json.loads(response.read().decode("utf-8"))

    indep_ca = indep_data["dispute_result"]["behavioral_verification"]["correlation_analysis"]
    assert indep_ca is not None
    assert indep_ca["l1_distance"] >= 0.0
    assert indep_data["comparison"]["normalized_l1_distance"] >= 0.0

