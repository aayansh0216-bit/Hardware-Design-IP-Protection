"""
Automated tests for Five-Rule Encoding Mode Persistence and Secured Rule 5 Allocation Comparison.
Verifies:
1. Mode selection lifecycle & persistence across simulated profile navigation.
2. Rule 5 schema integrity, absence of 'undefined', and deterministic canonical ordering.
3. Accurate Rule 5 comparison status ('Changed' vs 'Unchanged') based on actual original vs secured allocations.
4. Rejection of incomplete allocation metadata (no false 251-bit bitstreams).
5. Canonical serialization E_S = E4_secured || R5_secured (143b + 108b = 251b).
6. End-to-end consistency with commitments and verifier steps.
"""

import pytest
from fastapi.testclient import TestClient

from hardware_ip_protection.web.app import app
from hardware_ip_protection.pipeline.transaction_manager import TransactionManager, AVAILABLE_ENCODING_RULES
from hardware_ip_protection.hls.structural_encoder import (
    DesignStructuralEncoder,
    BUTTERWORTH_PRE_EMBEDDING_REGISTERS,
    BUTTERWORTH_POST_EMBEDDING_REGISTERS,
)


@pytest.fixture(autouse=True)
def reset_transaction():
    mgr = TransactionManager.get_instance()
    mgr.reset()
    yield
    mgr.reset()


def test_mode_persistence_across_simulated_profile_navigation():
    """
    1. Select 5-rule mode and calculate encoding D.
    2. Verify persisted mode is canonical 'iir_butterworth_5rule_v1'.
    3. Simulate navigation away (e.g. Buyer Profile, Verifier Profile) via API calls.
    4. Re-fetch transaction state as happens on returning to Seller Profile.
    5. Verify restored mode remains 5-rule and encoding D remains 251 bits with unchanged bitstream.
    6. Verify explicitly selecting four-rule mode switches state to 4-rule mode.
    """
    client = TestClient(app)

    # 1. Select 5-rule mode
    res = client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_5rule_v1"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["state"]["encoding_rule_id"] == "iir_butterworth_5rule_v1"
    assert data["state"]["encoding_transform_required"] is True

    # 2. Calculate encoding D
    enc_res = client.post("/api/transaction/encode_design", json={
        "rule_id": "iir_butterworth_5rule_v1",
        "design_id": "iir_butterworth",
        "use_table_quirks": False
    })
    assert enc_res.status_code == 200
    st_enc = enc_res.json()["state"]
    d_bits_orig = st_enc["design_encoding_D"]
    assert len(d_bits_orig) == 251
    assert st_enc["design_encoding_details"]["four_rule_bit_length"] == 143
    assert st_enc["design_encoding_details"]["rule5_bit_length"] == 108

    # 3. Simulate navigation:
    # User navigates to Buyer Profile (triggers /api/transaction/state)
    buyer_nav_res = client.get("/api/transaction/state")
    assert buyer_nav_res.status_code == 200
    buyer_st = buyer_nav_res.json()["state"]
    assert buyer_st["encoding_rule_id"] == "iir_butterworth_5rule_v1"
    assert buyer_st["design_encoding_D"] == d_bits_orig

    # Seller requests buyer contribution and buyer approves
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")

    # User navigates to Verifier Profile
    verifier_nav_res = client.get("/api/transaction/state")
    assert verifier_nav_res.status_code == 200
    ver_st = verifier_nav_res.json()["state"]
    assert ver_st["encoding_rule_id"] == "iir_butterworth_5rule_v1"

    # User returns to Seller Profile: re-fetch state
    seller_nav_res = client.get("/api/transaction/state")
    assert seller_nav_res.status_code == 200
    seller_st = seller_nav_res.json()["state"]

    # 4. Mode and components match original generated values
    assert seller_st["encoding_rule_id"] == "iir_butterworth_5rule_v1"
    assert seller_st["design_encoding_D"] == d_bits_orig
    assert seller_st["design_encoding_details"]["canonical_bitstream"] == d_bits_orig
    assert len(seller_st["design_encoding_details"]["rule5_records"]) == 27

    # 5. Explicitly select four-rule mode
    switch_res = client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_rule_v1"
    })
    assert switch_res.status_code == 200
    assert switch_res.json()["state"]["encoding_rule_id"] == "iir_butterworth_rule_v1"
    assert switch_res.json()["state"]["encoding_transform_required"] is False


def test_rule5_data_integrity_and_real_comparison():
    """
    Verify:
    1. All 27 expected pairs have valid 1-based indices and valid V<n> / R<m> names.
    2. No pair contains undefined values or string 'undefined'.
    3. Each 4-bit block is computed as reg_code + var_code from actual registers.
    4. Deterministic sequential ordering from pair 1 (V1) to pair 27 (V27).
    5. Comparison status accurately reflects original vs post-embedding:
       - Exactly 6 pairs changed: V5, V11, V13, V23, V26, V27.
       - Exactly 21 pairs unchanged.
    """
    enc_res = DesignStructuralEncoder.encode_golden_butterworth(
        mode="five_rule",
        is_secured=True,
    )
    records = enc_res.rule5_records
    assert len(records) == 27

    changed_vars = set()
    unchanged_vars = set()

    for idx, rec in enumerate(records, start=1):
        # 1. Valid indices & identifiers
        assert rec["pair_index"] == idx
        assert rec["variable_index"] == idx
        assert rec["variable_name"] == f"V{idx}"
        assert rec["variable"] == f"V{idx}"
        assert rec["variable_number"] == idx
        assert "undefined" not in str(rec["variable_name"])
        assert "undefined" not in str(rec["register_name"])
        assert rec["register_name"].startswith("R")
        assert rec["register_number"] > 0

        # 2. Parities
        assert rec["register_parity"] in ("Odd", "Even")
        assert rec["variable_parity"] in ("Odd", "Even")
        assert rec["register_parity_code"] in ("01", "00")
        assert rec["variable_parity_code"] in ("01", "00")

        # 3. 4-bit assembled block
        expected_block = f"{rec['register_parity_code']}{rec['variable_parity_code']}"
        assert rec["assembled_block"] == expected_block
        assert rec["encoding"] == expected_block

        # 4. Comparison status
        status = rec["comparison_status"]
        assert status in ("Changed", "Unchanged")
        if status == "Changed":
            changed_vars.add(rec["variable_number"])
            assert rec["original_encoding"] != rec["assembled_block"]
        else:
            unchanged_vars.add(rec["variable_number"])
            assert rec["original_encoding"] == rec["assembled_block"]

    # Known Butterworth CIG transformation: exactly 6 variables modified
    expected_changed = {5, 11, 13, 23, 26, 27}
    assert changed_vars == expected_changed
    assert len(unchanged_vars) == 21
    assert changed_vars.union(unchanged_vars) == set(range(1, 28))


def test_incomplete_allocation_metadata_fails_explicitly():
    """
    Verify incomplete register-variable allocation metadata raises an explicit ValueError
    instead of fabricating or silently generating an incomplete 251-bit bitstream.
    """
    incomplete_alloc = dict(BUTTERWORTH_POST_EMBEDDING_REGISTERS)
    del incomplete_alloc["V7"]

    with pytest.raises(ValueError) as excinfo:
        DesignStructuralEncoder.encode_golden_butterworth(
            mode="five_rule",
            is_secured=True,
            var_to_reg=incomplete_alloc,
        )
    assert "Missing register assignment for variable V7" in str(excinfo.value)


def test_canonical_bitstream_concatenation_and_lengths():
    """
    Verify:
    1. Four-rule component is exactly 143 bits (13 nodes).
    2. Rule 5 component is exactly 108 bits (27 pairs * 4 bits).
    3. Final bitstream is exactly E4 || R5.
    4. Total length is 251 bits.
    """
    res = DesignStructuralEncoder.encode_golden_butterworth(
        mode="five_rule",
        is_secured=True,
    )
    e4 = res.four_rule_bitstream
    r5 = res.rule5_bitstream
    es = res.canonical_bitstream

    assert len(e4) == 143
    assert len(r5) == 108
    assert len(es) == 251
    assert es == f"{e4}{r5}"
    assert es[:143] == e4
    assert es[143:] == r5


def test_end_to_end_pipeline_and_secured_encoding_recalculation():
    """
    Verify full lifecycle through TransactionManager:
    1. Select 5-rule mode.
    2. Encode design D (251 bits).
    3. Execute watermark embedding in RTL.
    4. Recalculate secured encoding E_S (251 bits).
    5. Compare encodings: confirms E_S != D because 6 variables changed.
    6. Verify transform E_S -> E_U restores D.
    """
    mgr = TransactionManager.get_instance()
    mgr.select_design_and_rule("iir_butterworth", "iir_butterworth_5rule_v1")
    mgr.generate_original_encoding()
    mgr.request_buyer_contribution()
    mgr.approve_buyer_request()
    mgr.generate_buyer_commitment()
    mgr.generate_transaction_watermark()
    mgr.commit_original_watermark()

    # Embed watermark
    mgr.embed_watermark_in_rtl()
    assert mgr.state.watermarked_RTL is not None

    # Recalculate secured encoding E_S
    mgr.calculate_secured_encoding()
    assert mgr.state.stage4_es_calculated is True
    es_dict = mgr.state.secured_encoding_E_S
    assert es_dict is not None
    assert len(es_dict["canonical_bitstream"]) == 251
    assert es_dict["four_rule_bit_length"] == 143
    assert es_dict["rule5_bit_length"] == 108
    assert len(es_dict["rule5_records"]) == 27

    # Verify records have comparison status
    changed_count = sum(1 for r in es_dict["rule5_records"] if r["comparison_status"] == "Changed")
    unchanged_count = sum(1 for r in es_dict["rule5_records"] if r["comparison_status"] == "Unchanged")
    assert changed_count == 6
    assert unchanged_count == 21

    # Compare encodings
    mgr.compare_encodings()
    assert mgr.state.stage4_encodings_compared is True
    assert mgr.state.encoding_transform_required is True

    # Transform E_S -> E_U and verify equivalence with D
    transformed = DesignStructuralEncoder.transform_butterworth_es_to_eu(
        es_dict["canonical_bitstream"],
        mode="five_rule"
    )
    assert transformed == mgr.state.design_encoding_D
