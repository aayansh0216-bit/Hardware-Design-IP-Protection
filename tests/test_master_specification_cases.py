"""
Authoritative Test Cases from Section 44 of the Master Specification.

Implements and validates:
    Case 1: Untouched protected design
    Case 2: Partial watermark modification
    Case 3: Complete watermark removal
    Case 4: Corrupted watermark
    Case 5: Different transaction watermark
    Case 6: Same behavioral function, independently generated design
    Case 7: Modified test-vector set after commitment
    Case 8: Same test vectors as committed
"""

import pytest
import re
from hardware_ip_protection.hls import (
    create_dct4,
    ListScheduler,
    CIG,
    RegisterAllocator,
    RTLGenerator,
)
from hardware_ip_protection.crypto import (
    PedersenEngine,
    CommitmentVerificationStatus,
    SymmetricHKDFWatermarkGenerator,
)
from hardware_ip_protection.verification import (
    TestVectorGenerator,
    BehavioralVerifier,
    BehavioralStatus,
)
from hardware_ip_protection.forensics import (
    TransactionWatermarkExtractor,
    WatermarkSimilarityCalculator,
    ExtractionStatus,
    SimilarityStatus,
)
from hardware_ip_protection.pipeline.engine import ProtectionPipeline, DisputePipeline


@pytest.fixture(scope="module")
def setup_protection():
    """
    Sets up a standard protected design baseline for test cases.
    """
    dfg = create_dct4()
    pipeline = ProtectionPipeline()
    init_ctx = {
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "transaction_record": {
            "transaction_id": "TX-ALPHA-001",
            "seller_id": "SELLER-ALPHA",
            "buyer_id": "BUYER-BETA",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "credential-secret-alpha"},
    }
    prot_ctx = pipeline.run(init_ctx)
    return prot_ctx


def test_case_1_untouched_protected_design(setup_protection):
    """
    Case 1: Untouched protected design.
    Expected:
        - Behavior matches
        - Watermark extraction succeeds
        - Watermark similarity = exact
        - Watermark commitment = valid
    """
    ctx = setup_protection
    disp_pipe = DisputePipeline()
    disp_ctx = {
        "raw_dfg": ctx["raw_dfg"],
        "reference_verilog": ctx["protected_verilog"],
        "suspicious_verilog": ctx["protected_verilog"],  # Untouched
        "test_vector_set": ctx["test_vector_set"],
        "stored_test_vector_commitment": ctx["test_vector_commitment"].commitment_hex,
        "test_vector_blinding_factor": ctx["test_vector_blinding_factor"],
        "stored_watermark_commitment": ctx["watermark_commitment"].commitment_hex,
        "watermark_blinding_factor": ctx["watermark_blinding_factor"],
        "intended_watermark_bitstream": ctx["transaction_watermark"].bitstream,
        "protection_record": ctx["protection_record"],
    }
    out = disp_pipe.run(disp_ctx)
    res = out["dispute_result"]

    assert res.behavioral_verification.status == "MATCH"
    assert res.watermark_analysis.reference_extraction.status == "SUCCESS"
    assert res.watermark_analysis.suspicious_extraction.status == "SUCCESS"
    assert res.watermark_analysis.similarity.status == "EXACT"
    assert res.watermark_analysis.similarity.similarity_ratio == 1.0
    assert res.watermark_analysis.commitment.status == "VALID"
    assert res.test_vector_commitment.status == "VALID"


def test_case_2_partial_watermark_modification(setup_protection):
    """
    Case 2: Partial watermark modification.
    Expected:
        - Behavior may still match
        - Watermark similarity < 100%
        - Watermark commitment = invalid
    """
    ctx = setup_protection
    prot_verilog = ctx["protected_verilog"]

    # Tamper with register bindings to simulate structural constraint modification
    # Merge two constrained variables into the same physical register (violating non-sharing constraint)
    mapping = ctx["watermark_mapping"]
    u, v = mapping[0]["pair"]
    alloc = ctx["protected_register_allocation"].variable_to_register
    target_reg = alloc[u]
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
    disp_ctx = {
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
    }
    out = disp_pipe.run(disp_ctx)
    res = out["dispute_result"]

    assert res.behavioral_verification.status == "MATCH"
    # Similarity must be strictly less than 1.0
    assert res.watermark_analysis.similarity.similarity_ratio is not None
    assert res.watermark_analysis.similarity.similarity_ratio < 1.0
    # Commitment check is exact; must fail on tampered watermark
    assert res.watermark_analysis.commitment.status == "INVALID"


def test_case_3_complete_watermark_removal(setup_protection):
    """
    Case 3: Complete watermark removal.
    Expected:
        - Watermark extraction may fail
        - Similarity = unavailable if no positions can be recovered
        - Commitment = not verifiable/invalid depending on available evidence
    """
    ctx = setup_protection
    # Attacker strips all register binding annotations and flattens into arbitrary code
    stripped_verilog = """
    module 4point_dct_obfuscated (input clk, input rst, input start, output reg done,
        input [31:0] v0, v1, v2, v3, c0, c1, c2, c3, output reg [31:0] v10);
        always @(posedge clk) begin
            done <= start;
            v10 <= (v0*c0 + v1*c1) + (v2*c2 + v3*c3);
        end
    endmodule
    """

    disp_pipe = DisputePipeline()
    disp_ctx = {
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
    }
    out = disp_pipe.run(disp_ctx)
    res = out["dispute_result"]

    # Extraction must fail
    assert res.watermark_analysis.suspicious_extraction.status == "FAILED"
    # Invariant 9: Extraction failure => similarity is NOT_AVAILABLE, not 0%
    assert res.watermark_analysis.similarity.status == "NOT_AVAILABLE"
    assert res.watermark_analysis.similarity.similarity_ratio is None
    # Commitment is NOT_VERIFIABLE
    assert res.watermark_analysis.commitment.status == "NOT_VERIFIABLE"


def test_case_4_corrupted_watermark(setup_protection):
    """
    Case 4: Corrupted watermark.
    Expected:
        - Partial extraction or extraction failure
        - Non-perfect similarity
        - Commitment invalid
    """
    ctx = setup_protection
    prot_verilog = ctx["protected_verilog"]

    # Corrupt a variable binding in RTL so its structural identity is unrecoverable
    mapping = ctx["watermark_mapping"]
    u = mapping[0]["pair"][0]
    corrupted_verilog = prot_verilog.replace(u, f"corrupted_{u}")

    disp_pipe = DisputePipeline()
    disp_ctx = {
        "raw_dfg": ctx["raw_dfg"],
        "reference_verilog": ctx["protected_verilog"],
        "suspicious_verilog": corrupted_verilog,
        "test_vector_set": ctx["test_vector_set"],
        "stored_test_vector_commitment": ctx["test_vector_commitment"].commitment_hex,
        "test_vector_blinding_factor": ctx["test_vector_blinding_factor"],
        "stored_watermark_commitment": ctx["watermark_commitment"].commitment_hex,
        "watermark_blinding_factor": ctx["watermark_blinding_factor"],
        "intended_watermark_bitstream": ctx["transaction_watermark"].bitstream,
        "protection_record": ctx["protection_record"],
    }
    out = disp_pipe.run(disp_ctx)
    res = out["dispute_result"]

    assert res.watermark_analysis.suspicious_extraction.status in ("PARTIAL", "FAILED")
    assert res.watermark_analysis.similarity.status != "EXACT"
    assert res.watermark_analysis.commitment.status in ("INVALID", "NOT_VERIFIABLE")


def test_case_5_different_transaction_watermark(setup_protection):
    """
    Case 5: Different transaction watermark (e.g. issued to different buyer/transaction).
    Expected:
        - Watermark similarity low or mismatch
        - Commitment invalid
    """
    ctx = setup_protection

    # Generate a legitimate protected design for a DIFFERENT transaction
    pipe2 = ProtectionPipeline()
    init_ctx_2 = {
        "dfg": ctx["raw_dfg"],
        "resource_config": {"add": 1, "mul": 2},
        "transaction_record": {
            "transaction_id": "TX-OTHER-999",
            "seller_id": "SELLER-GAMMA",
            "buyer_id": "BUYER-PIRATE",
            "license_type": "non_exclusive",
        },
        "transaction_credentials": {"k_tx": "totally-different-credential-key"},
    }
    other_ctx = pipe2.run(init_ctx_2)

    disp_pipe = DisputePipeline()
    disp_ctx = {
        "raw_dfg": ctx["raw_dfg"],
        "reference_verilog": ctx["protected_verilog"],
        "suspicious_verilog": other_ctx["protected_verilog"],  # Design from different transaction
        "test_vector_set": ctx["test_vector_set"],
        "stored_test_vector_commitment": ctx["test_vector_commitment"].commitment_hex,
        "test_vector_blinding_factor": ctx["test_vector_blinding_factor"],
        "stored_watermark_commitment": ctx["watermark_commitment"].commitment_hex,
        "watermark_blinding_factor": ctx["watermark_blinding_factor"],
        "intended_watermark_bitstream": ctx["transaction_watermark"].bitstream,
        "protection_record": ctx["protection_record"],
    }
    out = disp_pipe.run(disp_ctx)
    res = out["dispute_result"]

    assert res.watermark_analysis.commitment.status == "INVALID"
    # Even if behavior matches, watermark similarity cannot be exact
    assert res.watermark_analysis.similarity.status != "EXACT"


def test_case_6_same_behavior_independently_generated_design(setup_protection):
    """
    Case 6: Same behavioral function, independently generated design.
    Expected:
        - Behavior matches
        - Transaction watermark does NOT match
        - Demonstrates why behavioral and structural evidence are distinct
    """
    ctx = setup_protection
    # Original unwatermarked design computes the exact same functional behavior!
    orig_verilog = ctx["original_verilog"]

    disp_pipe = DisputePipeline()
    disp_ctx = {
        "raw_dfg": ctx["raw_dfg"],
        "reference_verilog": ctx["protected_verilog"],
        "suspicious_verilog": orig_verilog,
        "test_vector_set": ctx["test_vector_set"],
        "stored_test_vector_commitment": ctx["test_vector_commitment"].commitment_hex,
        "test_vector_blinding_factor": ctx["test_vector_blinding_factor"],
        "stored_watermark_commitment": ctx["watermark_commitment"].commitment_hex,
        "watermark_blinding_factor": ctx["watermark_blinding_factor"],
        "intended_watermark_bitstream": ctx["transaction_watermark"].bitstream,
        "protection_record": ctx["protection_record"],
    }
    out = disp_pipe.run(disp_ctx)
    res = out["dispute_result"]

    # Invariant 8 & Invariant 12: Behavior matches, but watermark commitment is not valid/not verifiable!
    assert res.behavioral_verification.status == "MATCH"
    assert res.watermark_analysis.commitment.status in ("INVALID", "NOT_VERIFIABLE")
    assert res.watermark_analysis.similarity.status != "EXACT"


def test_case_7_modified_test_vector_set_after_commitment(setup_protection):
    """
    Case 7: Modified test-vector set after commitment.
    Expected:
        - Test-vector commitment verification fails (INVALID)
    """
    ctx = setup_protection
    pe = PedersenEngine()

    stored_comm = ctx["test_vector_commitment"].commitment_hex
    r_v = ctx["test_vector_blinding_factor"]

    # Tamper with test vectors by adding an extra vector or modifying inputs
    tampered_vectors = list(ctx["test_vector_set"].vectors)
    tampered_vectors[0] = dict(tampered_vectors[0], v0=0x12345678)
    from hardware_ip_protection.verification import TestVectorSet
    tampered_tvs = TestVectorSet(tampered_vectors)

    status = pe.verify(tampered_tvs.canonical_json, stored_comm, r_v)
    assert status == CommitmentVerificationStatus.INVALID


def test_case_8_same_test_vectors_as_committed(setup_protection):
    """
    Case 8: Same test vectors as committed.
    Expected:
        - Test-vector commitment verification succeeds (VALID)
    """
    ctx = setup_protection
    pe = PedersenEngine()

    stored_comm = ctx["test_vector_commitment"].commitment_hex
    r_v = ctx["test_vector_blinding_factor"]
    tvs = ctx["test_vector_set"]

    status = pe.verify(tvs.canonical_json, stored_comm, r_v)
    assert status == CommitmentVerificationStatus.VALID
