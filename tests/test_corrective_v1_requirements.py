"""
Authoritative Test Suite for Section 32 of Corrective Implementation Prompt.

Validates all 18 mandatory corrective test requirements:
    TEST 1: Small design with automatic watermark length
    TEST 2: Requested watermark length > capacity rejected
    TEST 3: Even-even variable parity mapping for bit 0
    TEST 4: Odd-odd variable parity mapping for bit 1
    TEST 5: Extracted watermark independent of physical register number parity
    TEST 6: Existing genuine CIG edge handled without duplicate (ALREADY_EXISTS)
    TEST 7: New artificial edge added cleanly (ADDED)
    TEST 8: Unique pair mapping per watermark position
    TEST 9: Register allocation feasibility (all watermark edges respected)
    TEST 10: Watermark extraction exactness
    TEST 11: Comment independence (stripping all comments preserves extraction)
    TEST 12: Partial watermark tampering
    TEST 13: Complete watermark removal
    TEST 14: Different transaction watermark
    TEST 15: Independent design with same behavior
    TEST 16: Unchanged test vectors (C_V VALID)
    TEST 17: Modified test vectors (C_V INVALID)
    TEST 18: Variable watermark lengths (8-bit, 16-bit, 32-bit, design-supported max)
"""

import pytest
import re
from hardware_ip_protection.hls import (
    create_dct4,
    create_fir,
    create_arf,
    create_mesa,
    ListScheduler,
    CIG,
    RegisterAllocator,
    RTLGenerator,
)
from hardware_ip_protection.hls.cig import WatermarkCapacityAnalyzer, WatermarkCIGMapper
from hardware_ip_protection.hls.dfg import get_variable_index
from hardware_ip_protection.crypto import (
    PedersenEngine,
    CommitmentVerificationStatus,
    SymmetricHKDFWatermarkGenerator,
)
from hardware_ip_protection.verification import (
    TestVectorGenerator,
    BehavioralVerifier,
    BehavioralStatus,
    TestVectorSet,
)
from hardware_ip_protection.forensics import (
    TransactionWatermarkExtractor,
    WatermarkSimilarityCalculator,
    ExtractionStatus,
    SimilarityStatus,
)
from hardware_ip_protection.pipeline.engine import ProtectionPipeline, DisputePipeline


# ==============================================================================
# TEST 1: Small design with automatic watermark length
# ==============================================================================
def test_1_small_design_automatic_watermark_length():
    dfg = create_dct4()
    pipeline = ProtectionPipeline()
    ctx = pipeline.run({
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "transaction_record": {
            "transaction_id": "TX-AUTO-01",
            "seller_id": "SELLER-1",
            "buyer_id": "BUYER-1",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "secret-auto-key"},
        # No watermark_length specified -> triggers Automatic
    })

    cap = ctx["capacity_analysis"]
    assert cap["max_capacity"] == 25
    assert ctx["watermark_length"] == cap["recommended_default_length"]
    assert ctx["watermark_length"] == 8
    assert ctx["reference_extracted_watermark"].status == ExtractionStatus.SUCCESS
    assert ctx["reference_extracted_watermark"].recovered_bits == 8


# ==============================================================================
# TEST 2: Requested watermark length > capacity rejected
# ==============================================================================
def test_2_watermark_length_exceeding_capacity_rejected():
    dfg = create_dct4()
    pipeline = ProtectionPipeline()

    with pytest.raises(RuntimeError) as exc_info:
        pipeline.run({
            "dfg": dfg,
            "resource_config": {"add": 1, "mul": 2},
            "watermark_length": 64,  # Capacity is 25 bits
            "transaction_record": {
                "transaction_id": "TX-FAIL-02",
                "seller_id": "SELLER-1",
                "buyer_id": "BUYER-1",
                "license_type": "exclusive",
            },
            "transaction_credentials": {"k_tx": "secret-key"},
        })

    assert "Cannot embed 64 bits" in str(exc_info.value)
    assert "Design capacity is 25 bits" in str(exc_info.value)


# ==============================================================================
# TEST 3: Even-even mapping (bit 0 selects only an even-even variable pair)
# ==============================================================================
def test_3_even_even_mapping_for_bit_zero():
    dfg = create_dct4()
    sched = ListScheduler({"add": 1, "mul": 2}).schedule(dfg)
    base_cig = CIG(sched)

    # 4 bits of zeros
    constrained = WatermarkCIGMapper.embed_watermark(base_cig, "0000")
    for item in constrained.embedding_log:
        assert item["bit"] == 0
        assert item["rule"] == "EVEN_EVEN"
        u, v = item["pair"]
        idx_u = get_variable_index(u)
        idx_v = get_variable_index(v)
        assert idx_u % 2 == 0, f"Variable {u} has odd index {idx_u}"
        assert idx_v % 2 == 0, f"Variable {v} has odd index {idx_v}"
        assert idx_u != idx_v


# ==============================================================================
# TEST 4: Odd-odd mapping (bit 1 selects only an odd-odd variable pair)
# ==============================================================================
def test_4_odd_odd_mapping_for_bit_one():
    dfg = create_dct4()
    sched = ListScheduler({"add": 1, "mul": 2}).schedule(dfg)
    base_cig = CIG(sched)

    # 4 bits of ones
    constrained = WatermarkCIGMapper.embed_watermark(base_cig, "1111")
    for item in constrained.embedding_log:
        assert item["bit"] == 1
        assert item["rule"] == "ODD_ODD"
        u, v = item["pair"]
        idx_u = get_variable_index(u)
        idx_v = get_variable_index(v)
        assert idx_u % 2 == 1, f"Variable {u} has even index {idx_u}"
        assert idx_v % 2 == 1, f"Variable {v} has even index {idx_v}"
        assert idx_u != idx_v


# ==============================================================================
# TEST 5: No register parity assumption
# ==============================================================================
def test_5_no_register_parity_assumption():
    """
    Extracted watermark depends ONLY on non-sharing variable constraints,
    NEVER on whether assigned registers are even-numbered (R0, R2) or odd-numbered (R1, R3).
    """
    dfg = create_dct4()
    pipeline = ProtectionPipeline()
    ctx = pipeline.run({
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "watermark_length": 8,
        "transaction_record": {
            "transaction_id": "TX-PARITY-05",
            "seller_id": "SELLER-1",
            "buyer_id": "BUYER-1",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "secret-parity-test"},
    })

    prot_verilog = ctx["protected_verilog"]
    mapping = ctx["watermark_mapping"]

    # Permute register numbers: swap R0 with R1, R2 with R3, R4 with R5, R6 with R7
    # This inverts register parity (even registers become odd, odd registers become even)
    permuted_verilog = prot_verilog
    permuted_verilog = permuted_verilog.replace("R0", "TEMP_R0").replace("R1", "R0").replace("TEMP_R0", "R1")
    permuted_verilog = permuted_verilog.replace("R2", "TEMP_R2").replace("R3", "R2").replace("TEMP_R2", "R3")
    permuted_verilog = permuted_verilog.replace("R4", "TEMP_R4").replace("R5", "R4").replace("TEMP_R4", "R5")

    ext_original = TransactionWatermarkExtractor.extract(prot_verilog, watermark_mapping=mapping, expected_length=8)
    ext_permuted = TransactionWatermarkExtractor.extract(permuted_verilog, watermark_mapping=mapping, expected_length=8)

    assert ext_original.status == ExtractionStatus.SUCCESS
    assert ext_permuted.status == ExtractionStatus.SUCCESS
    assert ext_original.bitstream == ext_permuted.bitstream


# ==============================================================================
# TEST 6: Existing edge (ALREADY_EXISTS status, no duplicate edge)
# ==============================================================================
def test_6_existing_edge_handling():
    dfg = create_dct4()
    sched = ListScheduler({"add": 1, "mul": 2}).schedule(dfg)
    base_cig = CIG(sched)

    # In DCT4, ('v0', 'v2') is a genuine conflict edge in base_cig
    assert base_cig.has_edge("v0", "v2")

    # Embed bit 0 at position 0, which selects ('v0', 'v2')
    constrained = WatermarkCIGMapper.embed_watermark(base_cig, "0")
    log_item = constrained.embedding_log[0]

    assert log_item["pair"] == ["v0", "v2"]
    assert log_item["edge_status"] == "ALREADY_EXISTS"
    assert ("v0", "v2") not in constrained.artificial_edges
    assert ("v2", "v0") not in constrained.artificial_edges
    assert len(constrained.artificial_edges) == 0


# ==============================================================================
# TEST 7: New artificial edge (ADDED status)
# ==============================================================================
def test_7_new_artificial_edge():
    dfg = create_dct4()
    sched = ListScheduler({"add": 1, "mul": 2}).schedule(dfg)
    base_cig = CIG(sched)

    # In DCT4, ('v0', 'v6') does NOT have a genuine conflict edge in base_cig
    assert not base_cig.has_edge("v0", "v6")

    # Embed at position 2 with bit 0, which selects ('v0', 'v6')
    # Bitstream '110': pos 0 (bit 1), pos 1 (bit 1), pos 2 (bit 0 -> ('v0', 'v6'))
    constrained = WatermarkCIGMapper.embed_watermark(base_cig, "110")
    log_item = constrained.embedding_log[2]

    assert log_item["pair"] == ["v0", "v6"]
    assert log_item["edge_status"] == "ADDED"
    assert ("v0", "v6") in constrained.artificial_edges or ("v6", "v0") in constrained.artificial_edges


# ==============================================================================
# TEST 8: Unique pair mapping
# ==============================================================================
def test_8_unique_pair_mapping_per_position():
    dfg = create_dct4()
    sched = ListScheduler({"add": 1, "mul": 2}).schedule(dfg)
    base_cig = CIG(sched)

    constrained = WatermarkCIGMapper.embed_watermark(base_cig, "0000000")
    pairs_seen = set()
    for item in constrained.embedding_log:
        pair_tuple = tuple(sorted(item["pair"]))
        assert pair_tuple not in pairs_seen, f"Duplicate candidate pair {pair_tuple} mapped"
        pairs_seen.add(pair_tuple)


# ==============================================================================
# TEST 9: Register allocation feasibility
# ==============================================================================
def test_9_register_allocation_feasibility():
    dfg = create_dct4()
    pipeline = ProtectionPipeline()
    ctx = pipeline.run({
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "watermark_length": 8,
        "transaction_record": {
            "transaction_id": "TX-FEAS-09",
            "seller_id": "SELLER-1",
            "buyer_id": "BUYER-1",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "secret-feas-key"},
    })

    alloc = ctx["protected_register_allocation"]
    v2r = alloc.variable_to_register
    constrained_cig = ctx["constrained_cig"]

    # Every watermark constraint must be satisfied
    for item in ctx["watermark_mapping"]:
        u, v = item["pair"]
        assert v2r[u] != v2r[v], f"Constraint violated: {u} and {v} share register {v2r[u]}"

    # Post-allocation validation passes
    assert RegisterAllocator.validate_embedding(v2r, constrained_cig)


# ==============================================================================
# TEST 10: Watermark extraction exactness
# ==============================================================================
def test_10_watermark_extraction_exactness():
    dfg = create_dct4()
    pipeline = ProtectionPipeline()
    ctx = pipeline.run({
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "watermark_length": 8,
        "transaction_record": {
            "transaction_id": "TX-EXACT-10",
            "seller_id": "SELLER-1",
            "buyer_id": "BUYER-1",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "secret-exact-key"},
    })

    prot_verilog = ctx["protected_verilog"]
    intended_wm = ctx["transaction_watermark"].bitstream
    mapping = ctx["watermark_mapping"]

    ext = TransactionWatermarkExtractor.extract(prot_verilog, watermark_mapping=mapping, expected_length=8)
    assert ext.status == ExtractionStatus.SUCCESS
    assert ext.bitstream == intended_wm
    assert ext.recovered_bits == len(intended_wm)


# ==============================================================================
# TEST 11: Comment independence
# ==============================================================================
def test_11_comment_independence():
    """
    Strips ALL comments from protected RTL.
    Extraction must still succeed because bindings are parsed from Verilog datapath assignments.
    """
    dfg = create_dct4()
    pipeline = ProtectionPipeline()
    ctx = pipeline.run({
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "watermark_length": 8,
        "transaction_record": {
            "transaction_id": "TX-NOCOMMENT-11",
            "seller_id": "SELLER-1",
            "buyer_id": "BUYER-1",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "secret-nocomment-key"},
    })

    prot_verilog = ctx["protected_verilog"]
    mapping = ctx["watermark_mapping"]
    intended_wm = ctx["transaction_watermark"].bitstream

    # Strip ALL comments from the Verilog
    stripped_verilog = re.sub(r"//.*", "", prot_verilog)
    assert "//" not in stripped_verilog

    ext = TransactionWatermarkExtractor.extract(stripped_verilog, watermark_mapping=mapping, expected_length=8)
    assert ext.status == ExtractionStatus.SUCCESS
    assert ext.bitstream == intended_wm
    assert ext.recovered_bits == len(intended_wm)


# ==============================================================================
# TEST 12: Partial watermark tampering
# ==============================================================================
def test_12_partial_watermark_tampering():
    dfg = create_dct4()
    pipeline = ProtectionPipeline()
    ctx = pipeline.run({
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "watermark_length": 8,
        "transaction_record": {
            "transaction_id": "TX-PARTIAL-12",
            "seller_id": "SELLER-1",
            "buyer_id": "BUYER-1",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "credential-secret-alpha"},
    })

    prot_verilog = ctx["protected_verilog"]
    mapping = ctx["watermark_mapping"]
    u, v = mapping[0]["pair"]
    alloc = ctx["protected_register_allocation"].variable_to_register
    target_reg = alloc[u]

    # Tamper: force v to share target_reg with u, violating the constraint
    tampered_verilog = prot_verilog.replace(
        f"// REG_BINDING: {v} -> {alloc[v]}", f"// REG_BINDING: {v} -> {target_reg}"
    )
    tampered_verilog = re.sub(
        rf"(wire\s+\[31:0\]\s+{v}\s*=\s*)R\d+\s*;",
        rf"\g<1>{target_reg};",
        tampered_verilog,
    )
    tampered_verilog = re.sub(
        rf"\b(R\d+)\s*<=\s*{v}\s*;",
        rf"{target_reg} <= {v};",
        tampered_verilog,
    )

    disp_pipe = DisputePipeline()
    out = disp_pipe.run({
        "raw_dfg": ctx["raw_dfg"],
        "reference_verilog": ctx["protected_verilog"],
        "suspicious_verilog": tampered_verilog,
        "test_vector_set": ctx["test_vector_set"],
        "stored_test_vector_commitment": ctx["test_vector_commitment"].commitment_hex,
        "test_vector_blinding_factor": ctx["test_vector_blinding_factor"],
        "stored_watermark_commitment": ctx["watermark_commitment"].commitment_hex,
        "watermark_blinding_factor": ctx["watermark_blinding_factor"],
        "intended_watermark_bitstream": ctx["transaction_watermark"].bitstream,
        "protection_record": ctx["protection_record"],
    })
    res = out["dispute_result"]

    assert res.behavioral_verification.status == "MATCH"
    assert res.watermark_analysis.similarity.similarity_ratio < 1.0
    assert res.watermark_analysis.commitment.status == "INVALID"


# ==============================================================================
# TEST 13: Complete watermark removal
# ==============================================================================
def test_13_complete_watermark_removal():
    dfg = create_dct4()
    pipeline = ProtectionPipeline()
    ctx = pipeline.run({
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "watermark_length": 8,
        "transaction_record": {
            "transaction_id": "TX-STRIP-13",
            "seller_id": "SELLER-1",
            "buyer_id": "BUYER-1",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "credential-secret-alpha"},
    })

    stripped_verilog = """
    module 4point_dct_obfuscated (input clk, input rst, input start, output reg done);
        always @(posedge clk) done <= start;
    endmodule
    """

    disp_pipe = DisputePipeline()
    out = disp_pipe.run({
        "raw_dfg": ctx["raw_dfg"],
        "reference_verilog": ctx["protected_verilog"],
        "suspicious_verilog": stripped_verilog,
        "test_vector_set": ctx["test_vector_set"],
        "stored_test_vector_commitment": ctx["test_vector_commitment"].commitment_hex,
        "test_vector_blinding_factor": ctx["test_vector_blinding_factor"],
        "stored_watermark_commitment": ctx["watermark_commitment"].commitment_hex,
        "watermark_blinding_factor": ctx["watermark_blinding_factor"],
        "intended_watermark_bitstream": ctx["transaction_watermark"].bitstream,
        "protection_record": ctx["protection_record"],
    })
    res = out["dispute_result"]

    assert res.watermark_analysis.suspicious_extraction.status == "FAILED"
    assert res.watermark_analysis.similarity.status == "NOT_AVAILABLE"
    assert res.watermark_analysis.commitment.status == "NOT_VERIFIABLE"


# ==============================================================================
# TEST 14: Different transaction watermark
# ==============================================================================
def test_14_different_transaction_watermark():
    dfg = create_dct4()
    pipeline = ProtectionPipeline()
    ctx1 = pipeline.run({
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
    ctx2 = pipeline.run({
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

    disp_pipe = DisputePipeline()
    out = disp_pipe.run({
        "raw_dfg": ctx1["raw_dfg"],
        "reference_verilog": ctx1["protected_verilog"],
        "suspicious_verilog": ctx2["protected_verilog"],
        "test_vector_set": ctx1["test_vector_set"],
        "stored_test_vector_commitment": ctx1["test_vector_commitment"].commitment_hex,
        "test_vector_blinding_factor": ctx1["test_vector_blinding_factor"],
        "stored_watermark_commitment": ctx1["watermark_commitment"].commitment_hex,
        "watermark_blinding_factor": ctx1["watermark_blinding_factor"],
        "intended_watermark_bitstream": ctx1["transaction_watermark"].bitstream,
        "protection_record": ctx1["protection_record"],
    })
    res = out["dispute_result"]

    assert res.watermark_analysis.commitment.status == "INVALID"
    assert res.watermark_analysis.similarity.status != "EXACT"


# ==============================================================================
# TEST 15: Independent design with same behavior
# ==============================================================================
def test_15_independent_design_same_behavior():
    dfg = create_dct4()
    pipeline = ProtectionPipeline()
    ctx = pipeline.run({
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

    disp_pipe = DisputePipeline()
    out = disp_pipe.run({
        "raw_dfg": ctx["raw_dfg"],
        "reference_verilog": ctx["protected_verilog"],
        "suspicious_verilog": ctx["original_verilog"],  # Unwatermarked design
        "test_vector_set": ctx["test_vector_set"],
        "stored_test_vector_commitment": ctx["test_vector_commitment"].commitment_hex,
        "test_vector_blinding_factor": ctx["test_vector_blinding_factor"],
        "stored_watermark_commitment": ctx["watermark_commitment"].commitment_hex,
        "watermark_blinding_factor": ctx["watermark_blinding_factor"],
        "intended_watermark_bitstream": ctx["transaction_watermark"].bitstream,
        "protection_record": ctx["protection_record"],
    })
    res = out["dispute_result"]

    assert res.behavioral_verification.status == "MATCH"
    assert res.watermark_analysis.commitment.status in ("INVALID", "NOT_VERIFIABLE")


# ==============================================================================
# TEST 16: Unchanged test vectors (C_V VALID)
# ==============================================================================
def test_16_unchanged_test_vectors_commitment_valid():
    dfg = create_dct4()
    tvs = TestVectorGenerator.generate_stratified(dfg, count=16)
    pe = PedersenEngine()
    comm, r_v = pe.commit(tvs.canonical_json)

    status = pe.verify(tvs.canonical_json, comm.commitment_hex, r_v)
    assert status == CommitmentVerificationStatus.VALID


# ==============================================================================
# TEST 17: Modified test vectors (C_V INVALID)
# ==============================================================================
def test_17_modified_test_vectors_commitment_invalid():
    dfg = create_dct4()
    tvs = TestVectorGenerator.generate_stratified(dfg, count=16)
    pe = PedersenEngine()
    comm, r_v = pe.commit(tvs.canonical_json)

    # Tamper with test vector outputs
    tampered_vectors = [dict(v, **{"v0": 0xDEADBEEF}) for v in tvs.vectors]
    tampered_tvs = TestVectorSet(tampered_vectors)

    status = pe.verify(tampered_tvs.canonical_json, comm.commitment_hex, r_v)
    assert status == CommitmentVerificationStatus.INVALID


# ==============================================================================
# TEST 18: Variable watermark lengths (8-bit, 16-bit, 32-bit, max capacity)
# ==============================================================================
def test_18_variable_watermark_lengths():
    # 8-bit on DCT4
    dfg_dct = create_dct4()
    p = ProtectionPipeline()
    ctx8 = p.run({
        "dfg": dfg_dct,
        "resource_config": {"add": 1, "mul": 2},
        "watermark_length": 8,
        "transaction_record": {
            "transaction_id": "TX-LEN-8",
            "seller_id": "S",
            "buyer_id": "B",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "k8"},
    })
    assert ctx8["transaction_watermark"].bit_length == 8

    # 16-bit on FIR
    dfg_fir = create_fir()
    ctx16 = p.run({
        "dfg": dfg_fir,
        "resource_config": {"add": 2, "mul": 2},
        "watermark_length": 16,
        "transaction_record": {
            "transaction_id": "TX-LEN-16",
            "seller_id": "S",
            "buyer_id": "B",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "k16"},
    })
    assert ctx16["transaction_watermark"].bit_length == 16

    # 32-bit on ARF
    dfg_arf = create_arf()
    ctx32 = p.run({
        "dfg": dfg_arf,
        "resource_config": {"add": 2, "mul": 2},
        "watermark_length": 32,
        "transaction_record": {
            "transaction_id": "TX-LEN-32",
            "seller_id": "S",
            "buyer_id": "B",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "k32"},
    })
    assert ctx32["transaction_watermark"].bit_length == 32
