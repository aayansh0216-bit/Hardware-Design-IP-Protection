"""
Targeted Verification Test Suite for:
1. Seller Profile Privacy (Buyer Commitment C_B removed from Seller UI, preserved in backend)
2. Commitment Metadata in Private Evidence (G and H displayed consistently for C_D, C_W, C_W1)
3. Guided Verifier UI for Seller <-> Buyer Conflict (4 Sections, 13 steps preserved, Ref vs Susp intact)
"""

import pytest
import re
from fastapi.testclient import TestClient

from hardware_ip_protection.web.app import app
from hardware_ip_protection.pipeline.transaction_manager import TransactionManager
from hardware_ip_protection.pipeline.verifier_engine import VerifierEngine
from hardware_ip_protection.crypto.pedersen import PedersenEngine

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_all_state():
    tm = TransactionManager.get_instance()
    tm.reset()
    ve = VerifierEngine.get_instance()
    ve.reset_session()
    yield
    tm.reset()
    ve.reset_session()


def setup_complete_transaction():
    """Sets up a complete transaction ready for verification."""
    client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_rule_v1",
    })
    client.post("/api/transaction/encode_design", json={"use_table_quirks": False})
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")
    res = client.post("/api/transaction/continue_watermark", json={
        "transaction_id": "TX-2026-TEST01",
        "seller_id": "SELLER-001",
        "buyer_id": "BUYER-001",
        "license_type": "exclusive",
        "k_tx": "secret_key_12345",
        "watermark_length": "auto",
    })
    assert res.status_code == 200
    return res.json()["state"]


# ==============================================================================
# Part A: Seller Profile Privacy (C_B Removal)
# ==============================================================================
def test_seller_profile_cb_hidden():
    """Verify C_B is NOT rendered in Seller Substage 2A, but request/contribution status remain."""
    with open("hardware_ip_protection/web/static/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    # Seller substage 2A result box must exist
    assert 'id="sellerBuyerApprovedBox"' in html

    # C_B element must NOT be inside the seller substage 2A result box
    assert 'id="sellerCommitmentCB"' not in html
    assert 'Buyer Commitment C_B:' not in html

    # Request and contribution status must remain
    assert "Buyer Contribution Request:" in html
    assert "Buyer Contribution (B):" in html


def test_cb_remains_available_to_authorized_verifier():
    """Verify C_B is preserved in transaction state and verified in Verifier Step 10."""
    st = setup_complete_transaction()

    # C_B must be present in transaction state
    assert st["C_B"] is not None
    assert len(st["C_B"]) == 66  # Compressed NIST P-256 curve point hex

    # Configure verifier dispute
    cfg_res = client.post("/api/verifier/configure_dispute", json={
        "transaction_id": "TX-2026-TEST01",
        "dispute_type": "Seller ↔ Buyer Conflict",
        "dispute_subcategory": "Buyer claims ownership; recorded transaction may grant only a license.",
    })
    assert cfg_res.status_code == 200

    # Execute steps 1 through 10
    for s in range(1, 11):
        step_res = client.post("/api/verifier/execute_step", json={"step_number": s})
        assert step_res.status_code == 200
        step_data = step_res.json()
        assert step_data["step_result"]["step_number"] == s

    # Verify Step 10 specific outcome
    step10 = step_data["session"]["step_results"]["step_10"]
    assert step10["status"] == "MATCH"
    assert step10["stage2_verification"]["stored_commitment_C_B"] == st["C_B"]
    assert step10["stage2_verification"]["recalculated_commitment_C_B"] == st["C_B"]


# ==============================================================================
# Part B: Correct Commitment Metadata in Private Evidence (G and H)
# ==============================================================================
def test_private_evidence_generator_points():
    """Verify G and H elements exist for C_D, C_W, and C_W1 and match PedersenEngine."""
    with open("hardware_ip_protection/web/static/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    # Elements for C_D
    assert 'id="sellerPrivGenGD"' in html
    assert 'id="sellerPrivGenHD"' in html

    # Elements for C_W
    assert 'id="sellerPrivGenGW"' in html
    assert 'id="sellerPrivGenHW"' in html

    # Elements for C_W1
    assert 'id="sellerPrivGenGW1"' in html
    assert 'id="sellerPrivGenHW1"' in html

    # Check state endpoint returns actual generator points
    st = setup_complete_transaction()
    priv = st.get("seller_private_info")
    assert priv is not None

    pe = PedersenEngine()
    g_hex = pe.point_to_hex(pe.G)
    h_hex = pe.point_to_hex(pe.H)

    cd_comm = priv["C_D_evidence"]["commitment_verification"]
    assert cd_comm["generator_g"] == g_hex
    assert cd_comm["generator_h"] == h_hex

    cw_comm = priv["C_W_evidence"]["commitment_verification"]
    assert cw_comm["generator_g"] == g_hex
    assert cw_comm["generator_h"] == h_hex

    cw1_comm = priv["C_W1_evidence"]["commitment_verification"]
    assert cw1_comm["generator_g"] == g_hex
    assert cw1_comm["generator_h"] == h_hex


# ==============================================================================
# Part C: Guided Verifier UI for Seller <-> Buyer Conflict
# ==============================================================================
def test_guided_verifier_4_sections_structure():
    """Verify the 4 guided sections and their substructures exist in index.html."""
    with open("hardware_ip_protection/web/static/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    # 4 Section Navigation Cards
    assert 'id="vSecNav1"' in html
    assert 'id="vSecNav2"' in html
    assert 'id="vSecNav3"' in html
    assert 'id="vSecNav4"' in html

    # 4 Section Views
    assert 'id="vSecView1"' in html
    assert 'id="vSecView2"' in html
    assert 'id="vSecView3"' in html
    assert 'id="vSecView4"' in html

    # Section 1 Subsections: Encoding Verification & Watermark Verification
    assert 'id="vSubSecEncoding"' in html
    assert 'Subsection 1.1: Encoding Verification' in html
    assert 'id="vSubSecWatermark"' in html
    assert 'Subsection 1.2: Watermark Verification' in html

    # Active Step compatibility element preserved
    assert 'id="vActiveStepBox"' in html

    # Oversized stepper removed, replaced with compact progress indicator
    assert 'id="verifierStepper"' not in html
    assert 'id="vOverallProgressBadge"' in html
    assert 'id="vCompletedStepsCount"' in html

    # All 13 inline execution buttons and expandable cards exist
    for i in range(1, 14):
        assert f'id="vStepBox_{i}"' in html
        assert f'id="btnVerifierExecStep_{i}"' in html
        assert f'id="vStepBadge_{i}"' in html

    # Final Report Card
    assert 'id="verifierFinalReportCard"' in html


def test_reference_suspicious_workflow_unchanged():
    """Verify that the Reference <-> Suspicious Design workflow container is intact."""
    with open("hardware_ip_protection/web/static/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    # Reference vs Suspicious workspace container
    assert 'id="verifierRefSusWorkspace"' in html
    assert 'Reference Design ↔ Suspicious Design Audit Mode' in html
    assert 'id="tabDispute"' in html
    assert 'id="dispSusVerilog"' in html
    assert 'id="dispRefVerilog"' in html


def test_full_13_step_verification_flow():
    """Verify complete 13-step execution and final report consistency."""
    setup_complete_transaction()

    # Configure verifier dispute
    cfg_res = client.post("/api/verifier/configure_dispute", json={
        "transaction_id": "TX-2026-TEST01",
        "dispute_type": "Seller ↔ Buyer Conflict",
        "dispute_subcategory": "Buyer claims ownership; recorded transaction may grant only a license.",
    })
    assert cfg_res.status_code == 200

    # Run steps 1 through 13
    for s in range(1, 14):
        res = client.post("/api/verifier/execute_step", json={"step_number": s})
        assert res.status_code == 200

    final_session = res.json()["session"]
    report = final_session.get("final_report")
    assert report is not None
    assert report["overall_evidence_status"] == "CONSISTENT"
    assert report["design_encoding"] == "MATCH"
    assert report["secured_encoding"] == "NOT REQUIRED"  # Invariant E_S = D preserved
    assert report["embedded_watermark"] == "MATCH"
    assert report["complete_watermark"] == "MATCH"
    assert report["buyer_contribution"] == "MATCH"
    assert report["watermark_generation_relationship"] == "MATCH"
    assert report["transaction_record"] == "MATCH"


def test_unified_cards_and_disclosures_structure():
    """Verify that split Stage 1 / Stage 2 grid panels are replaced with unified expandable cards."""
    with open("hardware_ip_protection/web/static/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    # Split grid classes must NOT be used for verifier steps
    assert "v-stages-grid" not in html
    assert "STAGE 1: ARTIFACT INGESTION" not in html
    assert "STAGE 2: COMMITMENT STATUS" not in html
    assert "STAGE 1: RECONSTRUCTION" not in html

    # Unified result containers must be present across steps
    assert "v-unified-result" in html
    assert "v-disclosure-details" in html

    # Dropdowns / details exist for long encodings and bitstreams
    assert 'id="vDisputedVerilogRTL_inline"' in html
    assert 'id="vStepVal_2"' in html
    assert 'id="vStepVal_4"' in html
    assert 'id="vStepVal_5"' in html
    assert 'id="vStepVal_7"' in html
    assert 'id="vStepVal_9"' in html
    assert 'id="vStepVal_11"' in html

    # Rerun container wrappers exist for all 13 steps
    for i in range(1, 14):
        assert f'id="vStepRerunContainer_{i}"' in html

    # Progress string container in header
    assert 'id="vCompletedStepsCount"' in html


def test_verifier_step_data_payload_completeness():
    """Verify that all 13 verifier step execution responses contain actual data rather than empty fields."""
    setup_complete_transaction()
    client.post("/api/verifier/configure_dispute", json={
        "transaction_id": "TX-2026-TEST01",
        "dispute_type": "Seller ↔ Buyer Conflict",
    })

    # Step 1: RTL Ingestion
    s1_res = client.post("/api/verifier/execute_step", json={"step_number": 1}).json()
    st1 = s1_res["step_result"]["stage1_reconstruction"]
    assert st1["sha256_digest"] is not None and len(st1["sha256_digest"]) == 64
    assert st1["lines_of_code"] > 0
    assert "module " in (st1.get("synthesizable_verilog_code") or st1.get("preview"))

    # Step 2: Calculate Secured Design Encoding E_S
    s2_res = client.post("/api/verifier/execute_step", json={"step_number": 2}).json()
    st2 = s2_res["step_result"]["stage1_reconstruction"]
    assert st2["extracted_bitstream"] is not None
    assert len(st2["extracted_bitstream"]) == 143
    assert st2["total_nodes_recovered"] == 13

    # Step 3: Invariance & Conditional C_ES
    s3_res = client.post("/api/verifier/execute_step", json={"step_number": 3}).json()
    st3_1 = s3_res["step_result"]["stage1_reconstruction"]
    st3_2 = s3_res["step_result"]["stage2_verification"]
    assert "identical to original design encoding D" in st3_1["comparison"]
    assert "not required" in st3_2["stored_c_es"].lower()
    assert s3_res["step_result"]["status"] == "NOT REQUIRED"

    # Step 4: Verify C_D
    s4_res = client.post("/api/verifier/execute_step", json={"step_number": 4}).json()
    st4_1 = s4_res["step_result"]["stage1_reconstruction"]
    st4_2 = s4_res["step_result"]["stage2_verification"]
    assert len(st4_1["calculated_value_D"]) == 143
    assert st4_2["opening_factor_r_D"] is not None
    assert st4_2["stored_commitment_C_D"] is not None
    assert st4_2["recalculated_commitment_C_D"] == st4_2["stored_commitment_C_D"]
    assert s4_res["step_result"]["status"] == "MATCH"

    # Step 5: Extract W1'
    s5_res = client.post("/api/verifier/execute_step", json={"step_number": 5}).json()
    st5 = s5_res["step_result"]["stage1_reconstruction"]
    assert len(st5["extracted_bitstream_W1"]) == 32

    # Step 6: Verify C_W1
    s6_res = client.post("/api/verifier/execute_step", json={"step_number": 6}).json()
    st6_2 = s6_res["step_result"]["stage2_verification"]
    assert st6_2["recalculated_commitment_C_W1"] == st6_2["stored_commitment_C_W1"]
    assert s6_res["step_result"]["status"] == "MATCH"

    # Step 7: Reconstruct Complete W'
    s7_res = client.post("/api/verifier/execute_step", json={"step_number": 7}).json()
    st7 = s7_res["step_result"]["stage1_reconstruction"]
    assert len(st7["reconstructed_watermark_W"]) == 256

    # Step 8: Verify C_W
    s8_res = client.post("/api/verifier/execute_step", json={"step_number": 8}).json()
    st8_2 = s8_res["step_result"]["stage2_verification"]
    assert st8_2["recalculated_commitment_C_W"] == st8_2["stored_commitment_C_W"]
    assert s8_res["step_result"]["status"] == "MATCH"

    # Step 9: Validate B'
    s9_res = client.post("/api/verifier/execute_step", json={"step_number": 9}).json()
    st9 = s9_res["step_result"]["stage1_reconstruction"]
    assert len(st9["bitstream_B"]) == 555
    assert st9["zeros_count"] == 242
    assert st9["ones_count"] == 313

    # Step 10: Verify C_B
    s10_res = client.post("/api/verifier/execute_step", json={"step_number": 10}).json()
    st10_2 = s10_res["step_result"]["stage2_verification"]
    assert st10_2["recalculated_commitment_C_B"] == st10_2["stored_commitment_C_B"]
    assert s10_res["step_result"]["status"] == "MATCH"

    # Step 11: Watermark Relationship Formula F
    s11_res = client.post("/api/verifier/execute_step", json={"step_number": 11}).json()
    st11_1 = s11_res["step_result"]["stage1_reconstruction"]
    assert st11_1["expected_watermark_W"] == st11_1["reconstructed_watermark_W"]
    assert s11_res["step_result"]["status"] == "MATCH"

    # Step 12: Transaction Evidence & Rights
    s12_res = client.post("/api/verifier/execute_step", json={"step_number": 12}).json()
    st12_1 = s12_res["step_result"]["stage1_reconstruction"]
    assert st12_1["license_scope"] == "exclusive"
    assert s12_res["step_result"]["status"] in ("MATCH", "CONSISTENT")

