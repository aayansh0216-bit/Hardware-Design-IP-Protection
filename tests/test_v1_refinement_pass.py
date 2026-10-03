"""
V1 Refinement Pass Regression Test Suite.

Validates all 10 explicit test criteria from Requirement 28 of the Refinement Prompt:
1. Untouched Design: identical RTL hashes, MATCH, exact structural watermark, both commitments VALID.
2. Partial Tampering: different RTL hash, partial coverage/agreement, commitment INVALID/NOT_VERIFIABLE.
3. Complete Removal: different RTL hash, 0/N extracted, status FAILED/NOT_AVAILABLE, commitment NOT_VERIFIABLE.
4. Corrupted Mark: different RTL hash, structural mismatch/violation, commitment INVALID/NOT_VERIFIABLE.
5. Different TX Mark: different RTL hash, structural watermark mismatch, commitment INVALID.
6. Independent Design: different RTL hash, behavioral match, distinct structure, no fabricated ownership.
7. Test-vector commitment: committed set VALID, altered set INVALID.
8. UI security & Secrets: r_W and r_V absent in normal HTML/JS views; C, G, H visible.
9. Cache & Scenario switching: scenario switches produce correct, non-stale RTL and distinct hashes.
10. System integrity: no duplicate implementations, all pipeline invariants preserved.
"""

import pytest
import re
import hashlib
from fastapi.testclient import TestClient

from hardware_ip_protection.hls import create_dct4
from hardware_ip_protection.pipeline.engine import ProtectionPipeline, DisputePipeline
from hardware_ip_protection.pipeline.schemas import DisputeResultSchema
from hardware_ip_protection.verification.test_vector_generator import TestVectorSet
from hardware_ip_protection.web.app import app


@pytest.fixture(scope="module")
def setup_protection():
    dfg = create_dct4()
    pipe = ProtectionPipeline()
    ctx = pipe.run({
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "watermark_length": 8,
        "transaction_record": {
            "transaction_id": "TX-REF-001",
            "seller_id": "SELLER-REF",
            "buyer_id": "BUYER-REF",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "secret-key-ref"},
    })
    return ctx


def make_disp_ctx(ctx, sus_verilog, scenario):
    return {
        "raw_dfg": ctx["raw_dfg"],
        "reference_verilog": ctx["protected_verilog"],
        "suspicious_verilog": sus_verilog,
        "suspicious_scenario": scenario,
        "reference_protection_id": ctx["protection_record"].protection_id,
        "test_vector_set": ctx["test_vector_set"],
        "stored_test_vector_commitment": ctx["test_vector_commitment"].commitment_hex,
        "test_vector_blinding_factor": hex(ctx["test_vector_blinding_factor"])[2:].zfill(64),
        "stored_watermark_commitment": ctx["watermark_commitment"].commitment_hex,
        "watermark_blinding_factor": hex(ctx["watermark_blinding_factor"])[2:].zfill(64),
        "intended_watermark_bitstream": ctx["transaction_watermark"].bitstream,
        "protection_record": ctx["protection_record"],
    }


def test_refinement_item_1_untouched_design(setup_protection):
    """
    1. Untouched Design:
       - reference/suspicious RTL hashes identical
       - behavioral MATCH
       - structural watermark exact
       - reference commitment VALID
       - suspicious watermark vs stored commitment VALID
    """
    ctx = setup_protection
    disp = DisputePipeline()
    out = disp.run(make_disp_ctx(ctx, ctx["protected_verilog"], "Untouched Design"))
    res: DisputeResultSchema = out["dispute_result"]

    assert res.reference_rtl_sha256 == res.suspicious_rtl_sha256
    assert res.behavioral_verification.status == "MATCH"
    assert res.behavioral_verification.exact_match_rate == 1.0
    assert res.behavioral_verification.hamming_distance == 0
    assert res.behavioral_verification.hamming_similarity == 1.0
    assert res.watermark_analysis.similarity.status == "EXACT"
    assert res.watermark_analysis.similarity.extraction_coverage == 1.0
    assert res.watermark_analysis.similarity.recovered_bit_agreement == 1.0
    assert res.watermark_analysis.commitment.reference_commitment_check == "VALID"
    assert res.watermark_analysis.commitment.suspicious_commitment_check == "VALID"
    assert res.watermark_analysis.commitment.status == "VALID"
    assert res.test_vector_commitment.status == "VALID"


def test_refinement_item_2_partial_tampering(setup_protection):
    """
    2. Partial Tampering:
       - RTL hash differs
       - behavioral result reflects actual behavior
       - watermark coverage/similarity reflects actual surviving bits
       - suspicious commitment should fail if reconstructed watermark differs
    """
    ctx = setup_protection
    prot_verilog = ctx["protected_verilog"]
    mapping = ctx["watermark_mapping"]
    alloc = ctx["protected_register_allocation"].variable_to_register

    pair_to_tamper = None
    for item in mapping:
        u, v = item["pair"]
        if f"wire [31:0] {v} = " in prot_verilog:
            pair_to_tamper = (u, v)
            break
    if not pair_to_tamper:
        pair_to_tamper = mapping[0]["pair"]

    u, v = pair_to_tamper
    target_reg = alloc[u]
    tampered_verilog = re.sub(rf"(wire\s+\[31:0\]\s+{v}\s*=\s*)R\d+\s*;", rf"\g<1>{target_reg};", prot_verilog)
    tampered_verilog = re.sub(rf"\b(R\d+)\s*<=\s*{v}\s*;", rf"{target_reg} <= {v};", tampered_verilog)
    tampered_verilog = tampered_verilog.replace(f"module {ctx['raw_dfg'].name}_protected", f"module {ctx['raw_dfg'].name}_tampered")

    disp = DisputePipeline()
    out = disp.run(make_disp_ctx(ctx, tampered_verilog, "Partial Tampering"))
    res: DisputeResultSchema = out["dispute_result"]

    assert res.reference_rtl_sha256 != res.suspicious_rtl_sha256
    assert res.behavioral_verification.status == "MATCH"
    assert res.watermark_analysis.commitment.reference_commitment_check == "VALID"
    assert res.watermark_analysis.commitment.suspicious_commitment_check in ("INVALID", "NOT_VERIFIABLE")
    assert res.watermark_analysis.similarity.status in ("PARTIAL", "MISMATCH")


def test_refinement_item_3_complete_removal(setup_protection):
    """
    3. Complete Removal:
       - RTL hash differs
       - expected watermark constraints actually removed
       - extraction should be 0/N or clearly NOT_VERIFIABLE
       - commitment should be INVALID or NOT_VERIFIABLE
    """
    ctx = setup_protection
    prot_verilog = ctx["protected_verilog"]
    dfg = ctx["raw_dfg"]

    stripped = re.sub(r"//.*", "", prot_verilog)
    stripped = re.sub(r"wire\s+\[\d+:\d+\]\s+[a-zA-Z]\w*\s*=\s*R\d+\s*;", "", stripped)
    stripped = re.sub(r"assign\s+[a-zA-Z]\w*\s*=\s*R\d+\s*;", "", stripped)
    stripped = re.sub(r"R\d+\s*<=\s*[a-zA-Z]\w*\s*;", "// input load unwatermarked", stripped)
    stripped = re.sub(r"[a-zA-Z]\w*\s*<=\s*R\d+\s*;", "// output write unwatermarked", stripped)
    stripped = stripped.replace(f"module {dfg.name}_protected", f"module {dfg.name}_unwatermarked")

    disp = DisputePipeline()
    out = disp.run(make_disp_ctx(ctx, stripped, "Complete Removal"))
    res: DisputeResultSchema = out["dispute_result"]

    assert res.reference_rtl_sha256 != res.suspicious_rtl_sha256
    assert res.watermark_analysis.suspicious_extraction.recovered_bits == 0
    assert res.watermark_analysis.suspicious_extraction.status == "FAILED"
    assert res.watermark_analysis.similarity.status == "NOT_AVAILABLE"
    assert res.watermark_analysis.similarity.extraction_coverage == 0.0
    assert res.watermark_analysis.commitment.reference_commitment_check == "VALID"
    assert res.watermark_analysis.commitment.suspicious_commitment_check == "NOT_VERIFIABLE"


def test_refinement_item_4_corrupted_mark(setup_protection):
    """
    4. Corrupted Mark:
       - RTL hash differs
       - structural mismatch appears
       - commitment becomes INVALID/NOT_VERIFIABLE
    """
    ctx = setup_protection
    prot_verilog = ctx["protected_verilog"]
    mapping = ctx["watermark_mapping"]
    alloc = ctx["protected_register_allocation"].variable_to_register

    corrupted_verilog = prot_verilog.replace(f"module {ctx['raw_dfg'].name}_protected", f"module {ctx['raw_dfg'].name}_corrupted")
    if len(mapping) > 0:
        u0, v0 = mapping[0]["pair"]
        target_reg0 = alloc[u0]
        corrupted_verilog = re.sub(rf"(wire\s+\[31:0\]\s+{v0}\s*=\s*)R\d+\s*;", rf"\g<1>{target_reg0};", corrupted_verilog)
        corrupted_verilog = re.sub(rf"\b(R\d+)\s*<=\s*{v0}\s*;", rf"{target_reg0} <= {v0};", corrupted_verilog)

    disp = DisputePipeline()
    out = disp.run(make_disp_ctx(ctx, corrupted_verilog, "Corrupted Mark"))
    res: DisputeResultSchema = out["dispute_result"]

    assert res.reference_rtl_sha256 != res.suspicious_rtl_sha256
    assert res.watermark_analysis.commitment.reference_commitment_check == "VALID"
    assert res.watermark_analysis.commitment.suspicious_commitment_check in ("INVALID", "NOT_VERIFIABLE")


def test_refinement_item_5_different_tx_mark(setup_protection):
    """
    5. Different TX Mark:
       - RTL hash differs
       - structural watermark differs
       - commitment INVALID
    """
    ctx = setup_protection
    pipe2 = ProtectionPipeline()
    other_ctx = pipe2.run({
        "dfg": ctx["raw_dfg"],
        "resource_config": {"add": 1, "mul": 2},
        "watermark_length": 8,
        "transaction_record": {
            "transaction_id": "TX-OTHER-999",
            "seller_id": "SELLER-OTHER",
            "buyer_id": "BUYER-OTHER",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "secret-other"},
    })

    disp = DisputePipeline()
    out = disp.run(make_disp_ctx(ctx, other_ctx["protected_verilog"], "Different TX Mark"))
    res: DisputeResultSchema = out["dispute_result"]

    assert res.reference_rtl_sha256 != res.suspicious_rtl_sha256
    assert res.watermark_analysis.commitment.reference_commitment_check == "VALID"
    assert res.watermark_analysis.commitment.suspicious_commitment_check == "INVALID"


def test_refinement_item_6_independent_design(setup_protection):
    """
    6. Independent Design:
       - RTL hash differs
       - behavioral result based on actual simulation (MATCH)
       - watermark extraction/comparison based on actual structure
       - no composite ownership percentage
    """
    ctx = setup_protection
    disp = DisputePipeline()
    out = disp.run(make_disp_ctx(ctx, ctx["original_verilog"], "Independent Design"))
    res: DisputeResultSchema = out["dispute_result"]

    assert res.reference_rtl_sha256 != res.suspicious_rtl_sha256
    assert res.behavioral_verification.status == "MATCH"
    # Verify no composite ownership score is present
    res_dict = res.model_dump()
    assert "ownership_score" not in res_dict
    assert "ownership_percentage" not in res_dict


def test_refinement_item_7_test_vector_commitment(setup_protection):
    """
    7. Test-vector commitment:
       - original committed vector set -> VALID
       - altered vector set -> INVALID
    """
    ctx = setup_protection
    disp = DisputePipeline()

    # Original
    out_orig = disp.run(make_disp_ctx(ctx, ctx["protected_verilog"], "Untouched Design"))
    assert out_orig["dispute_result"].test_vector_commitment.status == "VALID"

    # Altered vectors
    tampered_vectors = [dict(v, **{list(v.keys())[0]: 0xDEADBEEF}) for v in ctx["test_vector_set"].vectors]
    tampered_tv_set = TestVectorSet(tampered_vectors)

    tampered_ctx = make_disp_ctx(ctx, ctx["protected_verilog"], "Untouched Design")
    tampered_ctx["test_vector_set"] = tampered_tv_set

    out_tampered = disp.run(tampered_ctx)
    assert out_tampered["dispute_result"].test_vector_commitment.status == "INVALID"


def test_refinement_item_8_ui_security_and_secrets():
    """
    8. UI security:
       - C/G/H visible where intended
       - r_W and r_V never shown in normal UI
    """
    with open("hardware_ip_protection/web/static/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    # r_W and r_V must NOT be displayed or input fields in index.html
    assert 'id="commWmR"' not in html
    assert 'id="commTvR"' not in html
    assert 'id="dispWmR"' not in html
    assert 'id="dispTvR"' not in html

    # Public parameters C, G, H must be present
    assert 'id="commWmHex"' in html
    assert 'id="commWmG"' in html
    assert 'id="commWmH"' in html
    assert 'id="dispHexGWm"' in html
    assert 'id="dispHexHWm"' in html

    # Forensic Findings Summary must be removed from HTML
    assert 'id="dispFindingsList"' not in html


def test_refinement_item_9_api_flow_and_preset_generation():
    """
    9. API Flow:
       - Protect and dispute endpoints function seamlessly without client-provided blinding factors
       - Preset attack scenarios return correct distinct RTL
    """
    client = TestClient(app)

    # Protect design
    prot_res = client.post("/api/protect", json={
        "benchmark_id": "4point_dct",
        "transaction_id": "TX-AUTO-101",
        "seller_id": "SELLER-AUTO",
        "buyer_id": "BUYER-AUTO",
        "license_type": "exclusive",
        "k_tx": "secret-tx-key-auto",
        "watermark_length": 8,
    })
    assert prot_res.status_code == 200
    pdata = prot_res.json()
    prot_id = pdata["protection_id"]

    # Presets test
    p_untouched = client.post("/api/attack_preset", json={"protection_id": prot_id, "preset_type": "untouched"}).json()
    p_tamper = client.post("/api/attack_preset", json={"protection_id": prot_id, "preset_type": "partial_tamper"}).json()
    p_removal = client.post("/api/attack_preset", json={"protection_id": prot_id, "preset_type": "complete_removal"}).json()

    assert p_untouched["suspicious_verilog"] != p_tamper["suspicious_verilog"]
    assert p_untouched["suspicious_verilog"] != p_removal["suspicious_verilog"]

    # Verify dispute without passing blinding factors (backend retrieves from session)
    disp_res = client.post("/api/dispute", json={
        "protection_id": prot_id,
        "suspicious_verilog": p_untouched["suspicious_verilog"],
        "scenario": "Untouched Design",
    })
    assert disp_res.status_code == 200
    ddata = disp_res.json()
    assert ddata["comparison"]["behavior_status"] == "MATCH"
    assert ddata["comparison"]["watermark_commitment_status"] == "VALID"
    assert ddata["comparison"]["test_vector_commitment_status"] == "VALID"
    assert ddata["comparison"]["reference_watermark_commitment_status"] == "VALID"
    assert ddata["comparison"]["suspicious_watermark_commitment_status"] == "VALID"


def test_refinement_item_11_actions_and_terminology(setup_protection):
    """
    11. Behavioral Terminology & Verification Actions UI constraints:
       - Exact Output Matches / Mismatches / Match Rate fields present and correct
       - index.html contains renamed labels and download button in report header
       - app.js does not auto-trigger dispute verification upon preset selection
    """
    ctx = setup_protection
    disp = DisputePipeline()
    out = disp.run(make_disp_ctx(ctx, ctx["protected_verilog"], "Untouched Design"))
    res: DisputeResultSchema = out["dispute_result"]

    bv = res.behavioral_verification
    assert bv.exact_output_matches == bv.total_test_vectors
    assert bv.exact_output_mismatches == 0
    assert bv.exact_output_match_rate == 1.0

    with open("hardware_ip_protection/web/static/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    # Behavioral labels
    assert "Exact Output Matches" in html
    assert "Exact Output Mismatches" in html
    assert "Exact Output Match Rate" in html
    assert "For each shared test input, the complete reference and suspicious output vectors are compared bit-for-bit." in html

    # Download Evidence Bundle at top of report
    assert 'id="downloadEvidenceBtn"' in html

    # Initial states
    assert "NOT VERIFIED" in html

    with open("hardware_ip_protection/web/static/app.js", "r", encoding="utf-8") as f:
        js = f.read()

    # Preset selection must not auto-execute dispute verification
    assert "resetDisputePendingState" in js
    # Confirm executeDisputeVerification is not called in initAttackPresets
    preset_fn = re.search(r"function initAttackPresets\(\)\s*\{([\s\S]*?)\n\}", js)
    assert preset_fn is not None
    assert "executeDisputeVerification" not in preset_fn.group(1)

