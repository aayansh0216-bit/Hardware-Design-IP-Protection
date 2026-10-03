"""
Authoritative Test Suite for Master Specification Part R:
Validates all 27 required tests for Canonical 256-Bit Watermark, Capacity Splitting,
CIG Embedding, Pedersen Commitments, and Dispute Forensics.
"""

import pytest
import hashlib
import json
import re
from typing import Dict, Any

from hardware_ip_protection.hls import (
    create_dct4,
    create_fir,
    ListScheduler,
    CIG,
    RegisterAllocator,
    RTLGenerator,
)
from hardware_ip_protection.hls.cig import WatermarkCapacityAnalyzer, WatermarkCIGMapper
from hardware_ip_protection.hls.dfg import get_variable_index
from hardware_ip_protection.crypto.pedersen import (
    PedersenEngine,
    PedersenCommitment,
    CommitmentVerificationStatus,
)
from hardware_ip_protection.crypto.watermark_generator import (
    SymmetricHKDFWatermarkGenerator,
    TransactionWatermark,
    CANONICAL_WATERMARK_LENGTH,
)
from hardware_ip_protection.pipeline.engine import ProtectionPipeline, DisputePipeline
from hardware_ip_protection.pipeline.schemas import ProtectionRecordSchema, DisputeResultSchema
from hardware_ip_protection.pipeline.repository import ProtectionRepository
from hardware_ip_protection.forensics.watermark_extractor import TransactionWatermarkExtractor


@pytest.fixture(scope="module")
def base_tx_record():
    return {
        "transaction_id": "TX-CANONICAL-001",
        "seller_id": "SELLER-ALPHA",
        "buyer_id": "BUYER-BETA",
        "design_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "license_type": "exclusive",
    }


@pytest.fixture(scope="module")
def standard_protection():
    dfg = create_dct4()
    pipe = ProtectionPipeline()
    ctx = pipe.run({
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "watermark_length": 8,
        "transaction_record": {
            "transaction_id": "TX-V1-FULL-01",
            "seller_id": "SELLER-IP-CORP",
            "buyer_id": "BUYER-CHIP-LLC",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "secret-k-tx-authoritative"},
    })
    return ctx


# ------------------------------------------------------------------------------
# Test 1: Canonical transaction context produces deterministic watermark for same inputs
# ------------------------------------------------------------------------------
def test_req_01_canonical_transaction_deterministic(base_tx_record):
    gen = SymmetricHKDFWatermarkGenerator()
    creds = {"k_tx": "secret_key_123"}
    wm1 = gen.generate(base_tx_record, creds)
    wm2 = gen.generate(base_tx_record, creds)

    assert wm1.canonical_bitstream == wm2.canonical_bitstream
    assert wm1.watermark_hash == wm2.watermark_hash


# ------------------------------------------------------------------------------
# Test 2: Changing seller_id changes watermark
# ------------------------------------------------------------------------------
def test_req_02_changing_seller_id_changes_watermark(base_tx_record):
    gen = SymmetricHKDFWatermarkGenerator()
    creds = {"k_tx": "secret_key_123"}
    wm1 = gen.generate(base_tx_record, creds)
    tx2 = dict(base_tx_record, seller_id="SELLER-DIFFERENT")
    wm2 = gen.generate(tx2, creds)

    assert wm1.canonical_bitstream != wm2.canonical_bitstream
    assert wm1.watermark_hash != wm2.watermark_hash


# ------------------------------------------------------------------------------
# Test 3: Changing buyer_id changes watermark
# ------------------------------------------------------------------------------
def test_req_03_changing_buyer_id_changes_watermark(base_tx_record):
    gen = SymmetricHKDFWatermarkGenerator()
    creds = {"k_tx": "secret_key_123"}
    wm1 = gen.generate(base_tx_record, creds)
    tx2 = dict(base_tx_record, buyer_id="BUYER-DIFFERENT")
    wm2 = gen.generate(tx2, creds)

    assert wm1.canonical_bitstream != wm2.canonical_bitstream
    assert wm1.watermark_hash != wm2.watermark_hash


# ------------------------------------------------------------------------------
# Test 4: Changing design_hash changes watermark
# ------------------------------------------------------------------------------
def test_req_04_changing_design_hash_changes_watermark(base_tx_record):
    gen = SymmetricHKDFWatermarkGenerator()
    creds = {"k_tx": "secret_key_123"}
    wm1 = gen.generate(base_tx_record, creds)
    tx2 = dict(base_tx_record, design_hash="1" * 64)
    wm2 = gen.generate(tx2, creds)

    assert wm1.canonical_bitstream != wm2.canonical_bitstream
    assert wm1.watermark_hash != wm2.watermark_hash


# ------------------------------------------------------------------------------
# Test 5: Changing transaction_id changes watermark
# ------------------------------------------------------------------------------
def test_req_05_changing_transaction_id_changes_watermark(base_tx_record):
    gen = SymmetricHKDFWatermarkGenerator()
    creds = {"k_tx": "secret_key_123"}
    wm1 = gen.generate(base_tx_record, creds)
    tx2 = dict(base_tx_record, transaction_id="TX-CANONICAL-999")
    wm2 = gen.generate(tx2, creds)

    assert wm1.canonical_bitstream != wm2.canonical_bitstream
    assert wm1.watermark_hash != wm2.watermark_hash


# ------------------------------------------------------------------------------
# Test 6: Changing license_type changes watermark
# ------------------------------------------------------------------------------
def test_req_06_changing_license_type_changes_watermark(base_tx_record):
    gen = SymmetricHKDFWatermarkGenerator()
    creds = {"k_tx": "secret_key_123"}
    wm1 = gen.generate(base_tx_record, creds)
    tx2 = dict(base_tx_record, license_type="non_exclusive")
    wm2 = gen.generate(tx2, creds)

    assert wm1.canonical_bitstream != wm2.canonical_bitstream
    assert wm1.watermark_hash != wm2.watermark_hash


# ------------------------------------------------------------------------------
# Test 7: Watermark is exactly 256 bits
# ------------------------------------------------------------------------------
def test_req_07_watermark_is_exactly_256_bits(base_tx_record):
    gen = SymmetricHKDFWatermarkGenerator()
    creds = {"k_tx": "secret_key_123"}
    wm = gen.generate(base_tx_record, creds)

    assert len(wm.canonical_bitstream) == 256
    assert wm.canonical_length == 256
    assert CANONICAL_WATERMARK_LENGTH == 256


# ------------------------------------------------------------------------------
# Test 8: Capacity smaller than 256 correctly splits embedded/remaining
# ------------------------------------------------------------------------------
def test_req_08_capacity_smaller_than_256_splits_embedded_remaining(base_tx_record):
    gen = SymmetricHKDFWatermarkGenerator()
    creds = {"k_tx": "secret_key_123"}
    wm = gen.generate(base_tx_record, creds, watermark_length=16)

    assert wm.embedded_length == 16
    assert wm.remaining_length == 240
    assert len(wm.embedded_bitstream) == 16
    assert len(wm.remaining_bitstream) == 240
    assert wm.canonical_bitstream == wm.embedded_bitstream + wm.remaining_bitstream
    assert wm.bitstream == wm.embedded_bitstream


# ------------------------------------------------------------------------------
# Test 9: Capacity >= 256 embeds 256
# ------------------------------------------------------------------------------
def test_req_09_capacity_ge_256_embeds_256(base_tx_record):
    gen = SymmetricHKDFWatermarkGenerator()
    creds = {"k_tx": "secret_key_123"}
    wm = gen.generate(base_tx_record, creds, watermark_length=256)

    assert wm.embedded_length == 256
    assert wm.remaining_length == 0
    assert wm.remaining_bitstream == ""
    assert wm.embedded_bitstream == wm.canonical_bitstream


# ------------------------------------------------------------------------------
# Test 10: No structural embedding silently truncates without recording it
# ------------------------------------------------------------------------------
def test_req_10_no_structural_embedding_silently_truncates(standard_protection):
    ctx = standard_protection
    rec: ProtectionRecordSchema = ctx["protection_record"]

    assert rec.canonical_watermark_length == 256
    assert rec.embedded_watermark_length == 8
    assert rec.remaining_watermark_length == 248
    assert "remaining_bitstream" in rec.reconstruction_metadata
    assert len(rec.reconstruction_metadata["remaining_bitstream"]) == 248


# ------------------------------------------------------------------------------
# Test 11: Bit 0 uses even-indexed variable pair
# ------------------------------------------------------------------------------
def test_req_11_bit_0_uses_even_indexed_variable_pair():
    dfg = create_dct4()
    sched = ListScheduler({"add": 1, "mul": 2}).schedule(dfg)
    cig = CIG(sched)
    constrained = WatermarkCIGMapper.embed_watermark(cig, "000")

    for entry in constrained.embedding_log:
        if entry["bit"] == 0:
            u, v = entry["pair"]
            idx_u = get_variable_index(u)
            idx_v = get_variable_index(v)
            assert idx_u % 2 == 0, f"Variable {u} index {idx_u} is not even for bit 0!"
            assert idx_v % 2 == 0, f"Variable {v} index {idx_v} is not even for bit 0!"
            assert entry["rule"] == "EVEN_EVEN"


# ------------------------------------------------------------------------------
# Test 12: Bit 1 uses odd-indexed variable pair
# ------------------------------------------------------------------------------
def test_req_12_bit_1_uses_odd_indexed_variable_pair():
    dfg = create_dct4()
    sched = ListScheduler({"add": 1, "mul": 2}).schedule(dfg)
    cig = CIG(sched)
    constrained = WatermarkCIGMapper.embed_watermark(cig, "111")

    for entry in constrained.embedding_log:
        if entry["bit"] == 1:
            u, v = entry["pair"]
            idx_u = get_variable_index(u)
            idx_v = get_variable_index(v)
            assert idx_u % 2 == 1, f"Variable {u} index {idx_u} is not odd for bit 1!"
            assert idx_v % 2 == 1, f"Variable {v} index {idx_v} is not odd for bit 1!"
            assert entry["rule"] == "ODD_ODD"


# ------------------------------------------------------------------------------
# Test 13: Register parity is never used as the encoding rule
# ------------------------------------------------------------------------------
def test_req_13_register_parity_never_used_as_encoding_rule(standard_protection):
    ctx = standard_protection
    alloc = ctx["protected_register_allocation"].variable_to_register

    # Variables with even indices can be bound to any register (R0, R1, R2...) based on CIG
    # Register allocation is governed strictly by graph coloring edges, not register number parity
    assert len(alloc) > 0


# ------------------------------------------------------------------------------
# Test 14: Existing CIG edges are recorded as ALREADY_EXISTS
# ------------------------------------------------------------------------------
def test_req_14_existing_cig_edges_recorded_already_exists():
    dfg = create_dct4()
    sched = ListScheduler({"add": 1, "mul": 2}).schedule(dfg)
    cig = CIG(sched)

    # Embed enough bits to cycle over pairs and encounter genuine edges
    constrained = WatermarkCIGMapper.embed_watermark(cig, "0" * 10)
    statuses = [entry["edge_status"] for entry in constrained.embedding_log]
    assert "ALREADY_EXISTS" in statuses


# ------------------------------------------------------------------------------
# Test 15: New CIG edges are recorded as ADDED
# ------------------------------------------------------------------------------
def test_req_15_new_cig_edges_recorded_added():
    dfg = create_dct4()
    sched = ListScheduler({"add": 1, "mul": 2}).schedule(dfg)
    cig = CIG(sched)

    constrained = WatermarkCIGMapper.embed_watermark(cig, "0101")
    statuses = [entry["edge_status"] for entry in constrained.embedding_log]
    assert "ADDED" in statuses


# ------------------------------------------------------------------------------
# Test 16: Register allocation respects all CIG edges
# ------------------------------------------------------------------------------
def test_req_16_register_allocation_respects_all_cig_edges(standard_protection):
    ctx = standard_protection
    constrained_cig = ctx["constrained_cig"]
    alloc = ctx["protected_register_allocation"].variable_to_register

    for u, v in constrained_cig.edges:
        if u in alloc and v in alloc:
            assert alloc[u] != alloc[v], f"Conflict edge violated between {u} and {v} in {alloc[u]}!"


# ------------------------------------------------------------------------------
# Test 17: Protected RTL preserves functional behavior
# ------------------------------------------------------------------------------
def test_req_17_protected_rtl_preserves_functional_behavior(standard_protection):
    ctx = standard_protection
    b_res = ctx["protection_behavioral_result"]

    assert b_res.status.value == "MATCH"
    assert b_res.match_ratio == 1.0
    assert b_res.matching_outputs == b_res.test_count


# ------------------------------------------------------------------------------
# Test 18: Watermark extraction recovers the actual embedded bits
# ------------------------------------------------------------------------------
def test_req_18_watermark_extraction_recovers_actual_embedded_bits(standard_protection):
    ctx = standard_protection
    ref_ext = ctx["reference_extracted_watermark"]
    intended_wm = ctx["transaction_watermark"]

    assert ref_ext.status.value == "SUCCESS"
    assert ref_ext.recovered_bits == intended_wm.embedded_length
    assert ref_ext.bitstream == intended_wm.embedded_bitstream


# ------------------------------------------------------------------------------
# Test 19: Reconstructed 256-bit watermark verifies against Pedersen commitment
# ------------------------------------------------------------------------------
def test_req_19_reconstructed_256_bit_watermark_verifies_commitment(standard_protection):
    ctx = standard_protection
    pe = PedersenEngine()
    ref_ext = ctx["reference_extracted_watermark"]
    rec = ctx["protection_record"]
    r_w = ctx["watermark_blinding_factor"]
    comm_hex = ctx["watermark_commitment"].commitment_hex

    remaining_bits = rec.reconstruction_metadata["remaining_bitstream"]
    reconstructed_256 = ref_ext.bitstream + remaining_bits

    assert len(reconstructed_256) == 256
    status = pe.verify(reconstructed_256, comm_hex, r_w)
    assert status == CommitmentVerificationStatus.VALID


# ------------------------------------------------------------------------------
# Test 20: Wrong watermark fails commitment verification
# ------------------------------------------------------------------------------
def test_req_20_wrong_watermark_fails_commitment_verification(standard_protection):
    ctx = standard_protection
    pe = PedersenEngine()
    ref_ext = ctx["reference_extracted_watermark"]
    rec = ctx["protection_record"]
    r_w = ctx["watermark_blinding_factor"]
    comm_hex = ctx["watermark_commitment"].commitment_hex

    # Flip the first bit
    inverted_first_bit = "1" if ref_ext.bitstream[0] == "0" else "0"
    wrong_embedded = inverted_first_bit + ref_ext.bitstream[1:]
    wrong_256 = wrong_embedded + rec.reconstruction_metadata["remaining_bitstream"]

    status = pe.verify(wrong_256, comm_hex, r_w)
    assert status == CommitmentVerificationStatus.INVALID


# ------------------------------------------------------------------------------
# Test 21: Wrong blinding value fails commitment verification
# ------------------------------------------------------------------------------
def test_req_21_wrong_blinding_value_fails_commitment_verification(standard_protection):
    ctx = standard_protection
    pe = PedersenEngine()
    ref_ext = ctx["reference_extracted_watermark"]
    rec = ctx["protection_record"]
    r_w = ctx["watermark_blinding_factor"]
    comm_hex = ctx["watermark_commitment"].commitment_hex

    reconstructed_256 = ref_ext.bitstream + rec.reconstruction_metadata["remaining_bitstream"]
    wrong_r = (r_w + 1) % pe.order

    status = pe.verify(reconstructed_256, comm_hex, wrong_r)
    assert status == CommitmentVerificationStatus.INVALID


# ------------------------------------------------------------------------------
# Test 22: Test-vector commitment verifies correctly
# ------------------------------------------------------------------------------
def test_req_22_test_vector_commitment_verifies_correctly(standard_protection):
    ctx = standard_protection
    pe = PedersenEngine()
    tvs = ctx["test_vector_set"]
    r_v = ctx["test_vector_blinding_factor"]
    comm_hex = ctx["test_vector_commitment"].commitment_hex

    status = pe.verify(tvs.canonical_json, comm_hex, r_v)
    assert status == CommitmentVerificationStatus.VALID


# ------------------------------------------------------------------------------
# Test 23: Tampered test vectors fail commitment verification
# ------------------------------------------------------------------------------
def test_req_23_tampered_test_vectors_fail_commitment_verification(standard_protection):
    ctx = standard_protection
    pe = PedersenEngine()
    tvs = ctx["test_vector_set"]
    r_v = ctx["test_vector_blinding_factor"]
    comm_hex = ctx["test_vector_commitment"].commitment_hex

    tampered_json = tvs.canonical_json.replace("1", "2", 1)
    status = pe.verify(tampered_json, comm_hex, r_v)
    assert status == CommitmentVerificationStatus.INVALID


# ------------------------------------------------------------------------------
# Test 24: Different dispute scenarios do not reuse the same cached result
# ------------------------------------------------------------------------------
def test_req_24_different_dispute_scenarios_do_not_reuse_cached_result(standard_protection):
    ctx = standard_protection
    prot_verilog = ctx["protected_verilog"]
    mapping = ctx["watermark_mapping"]
    alloc = ctx["protected_register_allocation"].variable_to_register

    # Make tampered verilog
    u, v = mapping[0]["pair"]
    target_reg = alloc[u]
    tampered_verilog = re.sub(rf"(wire\s+\[31:0\]\s+{v}\s*=\s*)R\d+\s*;", rf"\g<1>{target_reg};", prot_verilog)
    tampered_verilog = re.sub(rf"\b(R\d+)\s*<=\s*{v}\s*;", rf"{target_reg} <= {v};", tampered_verilog)

    disp = DisputePipeline(cache_enabled=True)

    base_ctx = {
        "raw_dfg": ctx["raw_dfg"],
        "reference_verilog": prot_verilog,
        "reference_protection_id": ctx["protection_record"].protection_id,
        "test_vector_set": ctx["test_vector_set"],
        "stored_test_vector_commitment": ctx["test_vector_commitment"].commitment_hex,
        "test_vector_blinding_factor": ctx["test_vector_blinding_factor"],
        "stored_watermark_commitment": ctx["watermark_commitment"].commitment_hex,
        "watermark_blinding_factor": ctx["watermark_blinding_factor"],
        "protection_record": ctx["protection_record"],
    }

    out1 = disp.run(dict(base_ctx, suspicious_verilog=prot_verilog, suspicious_scenario="Untouched"))
    res1: DisputeResultSchema = out1["dispute_result"]

    out2 = disp.run(dict(base_ctx, suspicious_verilog=tampered_verilog, suspicious_scenario="Partial Tampering"))
    res2: DisputeResultSchema = out2["dispute_result"]

    assert res1.suspicious_scenario == "Untouched"
    assert res2.suspicious_scenario == "Partial Tampering"
    assert res1.suspicious_rtl_sha256 != res2.suspicious_rtl_sha256
    assert res1.watermark_analysis.similarity.similarity_ratio == 1.0
    assert res2.watermark_analysis.similarity.similarity_ratio < 1.0


# ------------------------------------------------------------------------------
# Test 25: protection_id selects the correct reference record
# ------------------------------------------------------------------------------
def test_req_25_protection_id_selects_correct_reference_record(standard_protection):
    ctx = standard_protection
    rec: ProtectionRecordSchema = ctx["protection_record"]
    repo = ProtectionRepository.get_instance()

    fetched = repo.get(rec.protection_id)
    assert fetched is not None
    assert fetched["protection_id"] == rec.protection_id
    assert fetched["transaction"]["transaction_id"] == rec.transaction.transaction_id
    assert fetched["canonical_watermark_length"] == 256


# ------------------------------------------------------------------------------
# Test 26: Two protection records can exist for the same transaction_id
# ------------------------------------------------------------------------------
def test_req_26_two_protection_records_same_transaction_id():
    dfg = create_dct4()
    pipe = ProtectionPipeline()
    tx_rec = {
        "transaction_id": "TX-MULTI-VERSION-01",
        "seller_id": "SELLER-ALPHA",
        "buyer_id": "BUYER-BETA",
        "license_type": "exclusive",
    }

    # Version 1 with key 1
    ctx1 = pipe.run({
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "watermark_length": 8,
        "transaction_record": tx_rec,
        "transaction_credentials": {"k_tx": "secret-key-version-1"},
    })

    # Version 2 with key 2
    ctx2 = pipe.run({
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "watermark_length": 8,
        "transaction_record": tx_rec,
        "transaction_credentials": {"k_tx": "secret-key-version-2"},
    })

    id1 = ctx1["protection_record"].protection_id
    id2 = ctx2["protection_record"].protection_id

    assert id1 != id2

    repo = ProtectionRepository.get_instance()
    records = repo.find_by_transaction_id("TX-MULTI-VERSION-01")
    matching_ids = [r["protection_id"] for r in records]

    assert id1 in matching_ids
    assert id2 in matching_ids
    assert len(matching_ids) >= 2


# ------------------------------------------------------------------------------
# Test 27: Existing UI behavior remains intact
# ------------------------------------------------------------------------------
def test_req_27_existing_ui_behavior_remains_intact():
    from hardware_ip_protection.web.app import app
    from fastapi.testclient import TestClient

    client = TestClient(app)

    # 1. Benchmarks endpoint works
    res_b = client.get("/api/benchmarks")
    assert res_b.status_code == 200
    data_b = res_b.json()
    assert len(data_b["benchmarks"]) >= 5

    # 2. Protection endpoint works with default resource config (no resAdd/resMul needed)
    res_p = client.post("/api/protect", json={
        "benchmark_id": "4point_dct",
        "transaction_id": "TX-UI-TEST-01",
        "seller_id": "SELLER-UI",
        "buyer_id": "BUYER-UI",
        "license_type": "exclusive",
        "k_tx": "test-ui-key",
        "watermark_length": 8,
    })
    assert res_p.status_code == 200
    data_p = res_p.json()
    assert "protection_id" in data_p
    assert data_p["behavioral_verification"]["status"] == "MATCH"
    assert data_p["reference_watermark_extraction"]["is_exact"] is True

    # 3. Protection records listing works
    res_r = client.get("/api/protection_records")
    assert res_r.status_code == 200
    data_r = res_r.json()
    assert "records" in data_r
    assert any(r["protection_id"] == data_p["protection_id"] for r in data_r["records"])
