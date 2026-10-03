"""
Dedicated Backend Dispute Scenarios Test Suite.

Verifies and proves all 6 dispute verification scenarios:
A. Untouched
B. Partial Tampering
C. Complete Removal
D. Corrupted Mark
E. Different Transaction Mark
F. Independent Design

And verifies regression distinctness, provenance assertions, and cache correctness.
"""

import pytest
import re
import hashlib
from hardware_ip_protection.hls import create_dct4
from hardware_ip_protection.pipeline.engine import ProtectionPipeline, DisputePipeline
from hardware_ip_protection.pipeline.schemas import DisputeResultSchema
from hardware_ip_protection.crypto import CommitmentVerificationStatus
from hardware_ip_protection.forensics import ExtractionStatus, SimilarityStatus


@pytest.fixture(scope="module")
def setup_protection():
    dfg = create_dct4()
    pipe = ProtectionPipeline()
    ctx = pipe.run({
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "watermark_length": 8,
        "transaction_record": {
            "transaction_id": "TX-ALPHA-001",
            "seller_id": "SELLER-ALPHA",
            "buyer_id": "BUYER-BETA",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "credential-secret-alpha"},
    })
    return ctx


def make_disp_ctx(prot_ctx, suspicious_verilog, scenario_name):
    return {
        "raw_dfg": prot_ctx["raw_dfg"],
        "reference_verilog": prot_ctx["protected_verilog"],
        "suspicious_verilog": suspicious_verilog,
        "suspicious_scenario": scenario_name,
        "reference_protection_id": prot_ctx["protection_record"].protection_id,
        "test_vector_set": prot_ctx["test_vector_set"],
        "stored_test_vector_commitment": prot_ctx["test_vector_commitment"].commitment_hex,
        "test_vector_blinding_factor": prot_ctx["test_vector_blinding_factor"],
        "stored_watermark_commitment": prot_ctx["watermark_commitment"].commitment_hex,
        "watermark_blinding_factor": prot_ctx["watermark_blinding_factor"],
        "intended_watermark_bitstream": prot_ctx["transaction_watermark"].bitstream,
        "protection_record": prot_ctx["protection_record"],
    }


def test_scenario_a_untouched(setup_protection):
    """
    Scenario A: Untouched
    - suspicious RTL = exact protected RTL
    - content identical
    - behavioral match
    - extracted watermark match
    - commitment verification succeeds
    - reference_rtl_sha256 == suspicious_rtl_sha256
    """
    ctx = setup_protection
    prot_verilog = ctx["protected_verilog"]

    disp = DisputePipeline()
    out = disp.run(make_disp_ctx(ctx, prot_verilog, "Untouched"))
    res: DisputeResultSchema = out["dispute_result"]

    assert res.suspicious_scenario == "Untouched"
    assert res.reference_rtl_sha256 == res.suspicious_rtl_sha256
    assert res.behavioral_verification.status == "MATCH"
    assert res.watermark_analysis.reference_extraction.status == "SUCCESS"
    assert res.watermark_analysis.suspicious_extraction.status == "SUCCESS"
    assert res.watermark_analysis.similarity.status == "EXACT"
    assert res.watermark_analysis.similarity.similarity_ratio == 1.0
    assert res.watermark_analysis.similarity.matching_bits == res.watermark_analysis.similarity.compared_bits
    assert res.watermark_analysis.similarity.mismatching_bits == 0
    assert res.watermark_analysis.commitment.status == "VALID"
    assert res.test_vector_commitment.status == "VALID"


def test_scenario_b_partial_tampering(setup_protection):
    """
    Scenario B: Partial Tampering
    - modify/remove subset of structural constraints
    - functional behavior preserved
    - suspicious RTL/hash differs from reference
    - extracted watermark contains fewer recovered/matching bits than Untouched
    - commitment NOT valid
    """
    ctx = setup_protection
    prot_verilog = ctx["protected_verilog"]
    mapping = ctx["watermark_mapping"]
    alloc = ctx["protected_register_allocation"].variable_to_register

    u, v = mapping[0]["pair"]
    target_reg = alloc[u]
    old_reg = alloc[v]

    # Tamper with structural wire net taps, sequential input loading, and comments
    tampered_verilog = re.sub(rf"(wire\s+\[31:0\]\s+{v}\s*=\s*)R\d+\s*;", rf"\g<1>{target_reg};", prot_verilog)
    tampered_verilog = re.sub(rf"\b(R\d+)\s*<=\s*{v}\s*;", rf"{target_reg} <= {v};", tampered_verilog)
    tampered_verilog = tampered_verilog.replace(f"// REG_BINDING: {v} -> {old_reg}", f"// REG_BINDING: {v} -> {target_reg}")

    disp = DisputePipeline()
    out = disp.run(make_disp_ctx(ctx, tampered_verilog, "Partial Tampering"))
    res: DisputeResultSchema = out["dispute_result"]

    assert res.suspicious_scenario == "Partial Tampering"
    assert res.reference_rtl_sha256 != res.suspicious_rtl_sha256
    assert res.behavioral_verification.status == "MATCH"
    assert res.watermark_analysis.suspicious_extraction.recovered_bits < res.watermark_analysis.reference_extraction.recovered_bits
    assert res.watermark_analysis.similarity.matching_bits < res.watermark_analysis.similarity.compared_bits
    assert res.watermark_analysis.similarity.mismatching_bits >= 1
    assert res.watermark_analysis.similarity.similarity_ratio is not None
    assert res.watermark_analysis.similarity.similarity_ratio < 1.0
    assert res.watermark_analysis.commitment.status in ("INVALID", "NOT_VERIFIABLE")


def test_scenario_c_complete_removal(setup_protection):
    """
    Scenario C: Complete Removal
    - remove watermark structural constraints
    - preserve ordinary functional design
    - suspicious RTL/hash differs
    - extraction reports FAILED or PARTIAL (fewer bits recovered)
    - Pedersen commitment verification does NOT report VALID
    """
    ctx = setup_protection
    prot_verilog = ctx["protected_verilog"]
    dfg = ctx["raw_dfg"]

    # Strip structural wire net taps, comments, and watermark metadata
    stripped = re.sub(r"//.*", "", prot_verilog)
    stripped = re.sub(r"wire\s+\[\d+:\d+\]\s+[a-zA-Z]\w*\s*=\s*R\d+\s*;", "", stripped)
    stripped = re.sub(r"assign\s+[a-zA-Z]\w*\s*=\s*R\d+\s*;", "", stripped)
    stripped = re.sub(r"R\d+\s*<=\s*[a-zA-Z]\w*\s*;", "// input load unwatermarked", stripped)
    stripped = re.sub(r"[a-zA-Z]\w*\s*<=\s*R\d+\s*;", "// output write unwatermarked", stripped)
    stripped = stripped.replace(f"module {dfg.name}_protected", f"module {dfg.name}_unwatermarked")

    disp = DisputePipeline()
    out = disp.run(make_disp_ctx(ctx, stripped, "Complete Removal"))
    res: DisputeResultSchema = out["dispute_result"]

    assert res.suspicious_scenario == "Complete Removal"
    assert res.reference_rtl_sha256 != res.suspicious_rtl_sha256
    assert res.behavioral_verification.status == "MATCH"
    assert res.watermark_analysis.suspicious_extraction.recovered_bits == 0
    assert res.watermark_analysis.suspicious_extraction.status == "FAILED"
    assert res.watermark_analysis.similarity.status == "NOT_AVAILABLE"
    assert res.watermark_analysis.commitment.status in ("NOT_VERIFIABLE", "INVALID")
    assert res.watermark_analysis.commitment.status != "VALID"


def test_scenario_d_corrupted_mark(setup_protection):
    """
    Scenario D: Corrupted Mark
    - alter watermark bits and variable mappings
    - suspicious RTL/hash differs
    - similarity shows matching and mismatching/unavailable bits
    - commitment INVALID or NOT_VERIFIABLE
    """
    ctx = setup_protection
    prot_verilog = ctx["protected_verilog"]
    mapping = ctx["watermark_mapping"]
    alloc = ctx["protected_register_allocation"].variable_to_register

    corrupted_verilog = prot_verilog
    u0, v0 = mapping[0]["pair"]
    target_reg0 = alloc[u0]
    corrupted_verilog = re.sub(rf"(wire\s+\[31:0\]\s+{v0}\s*=\s*)R\d+\s*;", rf"\g<1>{target_reg0};", corrupted_verilog)
    corrupted_verilog = re.sub(rf"\b(R\d+)\s*<=\s*{v0}\s*;", rf"{target_reg0} <= {v0};", corrupted_verilog)
    corrupted_verilog = corrupted_verilog.replace(f"// REG_BINDING: {v0} -> {alloc[v0]}", f"// REG_BINDING: {v0} -> {target_reg0}")

    if len(mapping) > 1:
        u1, v1 = mapping[1]["pair"]
        corrupted_verilog = re.sub(rf"\bwire\s+\[31:0\]\s+{v1}\b", f"wire [31:0] corrupted_{v1}", corrupted_verilog)
        corrupted_verilog = re.sub(rf"\b(R\d+)\s*<=\s*{v1}\s*;", rf"\g<1> <= corrupted_{v1};", corrupted_verilog)

    disp = DisputePipeline()
    out = disp.run(make_disp_ctx(ctx, corrupted_verilog, "Corrupted Mark"))
    res: DisputeResultSchema = out["dispute_result"]

    assert res.suspicious_scenario == "Corrupted Mark"
    assert res.reference_rtl_sha256 != res.suspicious_rtl_sha256
    assert res.watermark_analysis.similarity.similarity_ratio is not None
    assert res.watermark_analysis.similarity.similarity_ratio < 1.0
    assert res.watermark_analysis.commitment.status in ("INVALID", "NOT_VERIFIABLE")


def test_scenario_e_different_transaction(setup_protection):
    """
    Scenario E: Different Transaction Mark
    - structurally valid watermark from a different transaction
    - hashes differ
    - commitment verification against reference transaction must be INVALID
    """
    ctx = setup_protection
    dfg = ctx["raw_dfg"]

    pipe2 = ProtectionPipeline()
    other_ctx = pipe2.run({
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "watermark_length": 8,
        "transaction_record": {
            "transaction_id": "TX-OTHER-999",
            "seller_id": "SELLER-GAMMA",
            "buyer_id": "BUYER-PIRATE",
            "license_type": "non_exclusive",
        },
        "transaction_credentials": {"k_tx": "totally-different-credential-key"},
    })
    other_verilog = other_ctx["protected_verilog"]

    disp = DisputePipeline()
    out = disp.run(make_disp_ctx(ctx, other_verilog, "Different Transaction"))
    res: DisputeResultSchema = out["dispute_result"]

    assert res.suspicious_scenario == "Different Transaction"
    assert res.reference_rtl_sha256 != res.suspicious_rtl_sha256
    assert res.behavioral_verification.status == "MATCH"
    assert res.watermark_analysis.similarity.status != "EXACT"
    assert res.watermark_analysis.commitment.status == "INVALID"


def test_scenario_f_independent_design(setup_protection):
    """
    Scenario F: Independent Design
    - unwatermarked baseline design
    - computed independently
    - commitment INVALID or NOT_VERIFIABLE
    """
    ctx = setup_protection
    orig_verilog = ctx["original_verilog"]

    disp = DisputePipeline()
    out = disp.run(make_disp_ctx(ctx, orig_verilog, "Independent Design"))
    res: DisputeResultSchema = out["dispute_result"]

    assert res.suspicious_scenario == "Independent Design"
    assert res.reference_rtl_sha256 != res.suspicious_rtl_sha256
    assert res.behavioral_verification.status == "MATCH"
    assert res.watermark_analysis.commitment.status in ("INVALID", "NOT_VERIFIABLE")


def test_regression_all_scenarios_produce_distinct_results(setup_protection):
    """
    Regression Test:
    run(Untouched)
    run(Partial Tampering)
    run(Complete Removal)
    run(Corrupted Mark)
    run(Different Transaction)
    run(Independent Design)
    MUST NOT all return the same result object!
    """
    ctx = setup_protection
    prot_verilog = ctx["protected_verilog"]
    mapping = ctx["watermark_mapping"]
    alloc = ctx["protected_register_allocation"].variable_to_register
    dfg = ctx["raw_dfg"]

    # Generate the 6 distinct designs
    designs = {}

    # A: Untouched
    designs["Untouched"] = prot_verilog

    # B: Partial Tampering
    u, v = mapping[0]["pair"]
    t_reg = alloc[u]
    b_rtl = re.sub(rf"(wire\s+\[31:0\]\s+{v}\s*=\s*)R\d+\s*;", rf"\g<1>{t_reg};", prot_verilog)
    b_rtl = re.sub(rf"\b(R\d+)\s*<=\s*{v}\s*;", rf"{t_reg} <= {v};", b_rtl)
    b_rtl = b_rtl.replace(f"// REG_BINDING: {v} -> {alloc[v]}", f"// REG_BINDING: {v} -> {t_reg}")
    designs["Partial Tampering"] = b_rtl

    # C: Complete Removal
    c_rtl = re.sub(r"^\s*wire\s+\[31:0\]\s+\w+\s*=\s*R\d+\s*;\s*\n", "", prot_verilog, flags=re.MULTILINE)
    c_rtl = re.sub(r"^\s*//\s*REG_BINDING:.*?\n", "", c_rtl, flags=re.MULTILINE)
    c_rtl = re.sub(r"\s*//\s*node\s+\d+\s*\([\w_]+\)", "", c_rtl)
    designs["Complete Removal"] = c_rtl

    # D: Corrupted Mark
    d_rtl = re.sub(rf"(wire\s+\[31:0\]\s+{v}\s*=\s*)R\d+\s*;", rf"\g<1>{t_reg};", prot_verilog)
    d_rtl = re.sub(rf"\b(R\d+)\s*<=\s*{v}\s*;", rf"{t_reg} <= {v};", d_rtl)
    d_rtl = d_rtl.replace(f"// REG_BINDING: {v} -> {alloc[v]}", f"// REG_BINDING: {v} -> {t_reg}")
    if len(mapping) > 1:
        u1, v1 = mapping[1]["pair"]
        d_rtl = re.sub(rf"\bwire\s+\[31:0\]\s+{v1}\b", f"wire [31:0] corrupted_{v1}", d_rtl)
        d_rtl = re.sub(rf"\b(R\d+)\s*<=\s*{v1}\s*;", rf"\g<1> <= corrupted_{v1};", d_rtl)
    designs["Corrupted Mark"] = d_rtl

    # E: Different Transaction
    pipe2 = ProtectionPipeline()
    other_ctx = pipe2.run({
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "watermark_length": 8,
        "transaction_record": {
            "transaction_id": "TX-OTHER-999",
            "seller_id": "SELLER-GAMMA",
            "buyer_id": "BUYER-PIRATE",
            "license_type": "non_exclusive",
        },
        "transaction_credentials": {"k_tx": "totally-different-credential-key"},
    })
    designs["Different Transaction"] = other_ctx["protected_verilog"]

    # F: Independent Design
    designs["Independent Design"] = ctx["original_verilog"]

    # Run Dispute Pipeline for all 6
    disp = DisputePipeline()
    results = {}
    for scenario_name, verilog_code in designs.items():
        out = disp.run(make_disp_ctx(ctx, verilog_code, scenario_name))
        results[scenario_name] = out["dispute_result"]

    # 1. Assert suspicious RTL hashes are not all identical
    sus_hashes = set(r.suspicious_rtl_sha256 for r in results.values())
    assert len(sus_hashes) > 1, "All 6 scenarios produced identical suspicious RTL hashes!"

    # 2. Assert Untouched is the ONLY one whose suspicious hash matches reference hash
    ref_hash = results["Untouched"].reference_rtl_sha256
    for s_name, res in results.items():
        if s_name == "Untouched":
            assert res.suspicious_rtl_sha256 == ref_hash
        else:
            assert res.suspicious_rtl_sha256 != ref_hash, f"Scenario '{s_name}' had identical hash to reference protected RTL!"

    # 3. Assert extraction recovered bits are not all identical
    rec_bits = set(r.watermark_analysis.suspicious_extraction.recovered_bits for r in results.values())
    assert len(rec_bits) > 1, "All 6 scenarios produced identical recovered bit counts!"

    # 4. Assert similarity statuses / ratios vary appropriately
    sim_ratios = set(r.watermark_analysis.similarity.similarity_ratio for r in results.values())
    assert len(sim_ratios) > 1, "All 6 scenarios produced identical similarity ratios!"

    # 5. Assert commitment status is VALID ONLY for Untouched
    assert results["Untouched"].watermark_analysis.commitment.status == "VALID"
    for s_name in ["Partial Tampering", "Complete Removal", "Corrupted Mark", "Different Transaction", "Independent Design"]:
        assert results[s_name].watermark_analysis.commitment.status in ("INVALID", "NOT_VERIFIABLE"), (
            f"Scenario '{s_name}' unexpectedly reported VALID commitment!"
        )


def test_cache_correctness_scenarios(setup_protection):
    """
    Proves cache correctness:
    Cached dispute result must distinguish reference protection, scenario, and suspicious RTL hash.
    It must be impossible for Untouched result to be returned for Partial Tampering.
    """
    ctx = setup_protection
    prot_verilog = ctx["protected_verilog"]
    mapping = ctx["watermark_mapping"]
    alloc = ctx["protected_register_allocation"].variable_to_register

    u, v = mapping[0]["pair"]
    t_reg = alloc[u]
    tampered_verilog = re.sub(rf"(wire\s+\[31:0\]\s+{v}\s*=\s*)R\d+\s*;", rf"\g<1>{t_reg};", prot_verilog)
    tampered_verilog = re.sub(rf"\b(R\d+)\s*<=\s*{v}\s*;", rf"{t_reg} <= {v};", tampered_verilog)
    tampered_verilog = tampered_verilog.replace(f"// REG_BINDING: {v} -> {alloc[v]}", f"// REG_BINDING: {v} -> {t_reg}")

    cached_disp = DisputePipeline(cache_enabled=True)

    # 1. Run Untouched
    out1 = cached_disp.run(make_disp_ctx(ctx, prot_verilog, "Untouched"))
    res1: DisputeResultSchema = out1["dispute_result"]
    assert res1.suspicious_scenario == "Untouched"
    assert res1.watermark_analysis.similarity.similarity_ratio == 1.0

    # 2. Run Partial Tampering on same reference protection
    out2 = cached_disp.run(make_disp_ctx(ctx, tampered_verilog, "Partial Tampering"))
    res2: DisputeResultSchema = out2["dispute_result"]

    # Must NOT return the cached Untouched result
    assert res2.suspicious_scenario == "Partial Tampering"
    assert res2.watermark_analysis.similarity.similarity_ratio is not None
    assert res2.watermark_analysis.similarity.similarity_ratio < 1.0
    assert res2.watermark_analysis.commitment.status in ("INVALID", "NOT_VERIFIABLE")
    assert res1.suspicious_rtl_sha256 != res2.suspicious_rtl_sha256
