"""
Tests for TASK 1: Seller, Buyer, Verifier Profiles & Transaction Workflow.

Validates:
TEST A: Seller selects IIR Butterworth Filter and IIR Butterworth Encoding Rule,
        generates original design encoding D (143 bits), generates commitment C_D.
TEST B: Seller requests Buyer contribution, status becomes Pending.
TEST C: Buyer views request, approves it, provides exact 555-bit bitstream
        (length 555, zeros 242, ones 313), generates commitment C_B.
TEST D: Seller observes Buyer approval, contribution received, C_B available.
TEST E: Seller continues existing watermark workflow, derives W, C_W, W1, C_W1,
        watermarked Verilog, and structural encoding.
TEST F: Verifier profile exists as placeholder and is not implemented yet.
"""

import pytest
from fastapi.testclient import TestClient

from hardware_ip_protection.web.app import app
from hardware_ip_protection.pipeline.transaction_manager import (
    TransactionManager,
    DEMO_BUYER_BITSTREAM,
    AVAILABLE_DESIGNS,
    AVAILABLE_ENCODING_RULES,
)
from hardware_ip_protection.crypto.pedersen import PedersenEngine, CommitmentVerificationStatus


client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_transaction_state():
    mgr = TransactionManager.get_instance()
    mgr.reset()
    yield
    mgr.reset()


def test_part3_and_part4_design_and_rule_selection():
    """
    Validates design selection and encoding rule selection for IIR Butterworth Filter.
    """
    res = client.get("/api/transaction/state")
    assert res.status_code == 200
    data = res.json()
    assert len(data["designs"]) >= 1
    assert data["designs"][0]["name"] == "IIR Butterworth Filter"
    assert data["rules"][0]["name"] == "IIR Butterworth Encoding Rule"

    sel_res = client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_rule_v1",
    })
    assert sel_res.status_code == 200
    st = sel_res.json()["state"]
    assert st["selected_design"] == "IIR Butterworth Filter"
    assert st["selected_encoding_rule"] == "IIR Butterworth Encoding Rule"
    assert st["design_id"] == "iir_butterworth"
    assert st["encoding_rule_id"] == "iir_butterworth_rule_v1"


def test_test_a_generate_d_and_commitment_c_d():
    """
    TEST A:
    Select IIR Butterworth Filter and IIR Butterworth Encoding Rule.
    Generate D. Verify existing encoder produces the expected 143-bit encoding.
    Generate C_D. Verify C_D exists and is valid.
    """
    # Select design and rule
    client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_rule_v1",
    })

    # Generate encoding D and C_D
    enc_res = client.post("/api/transaction/encode_design", json={"use_table_quirks": False})
    assert enc_res.status_code == 200
    st = enc_res.json()["state"]

    D = st["design_encoding_D"]
    assert D is not None
    assert len(D) == 143
    # Starts with T1 node 1 (0100 0001 1 10) and node 2 (0100 0010 1 10)
    assert D.startswith("0100000111001000010110")

    C_D = st["C_D"]
    assert C_D is not None
    assert len(C_D) == 66  # 33-byte compressed EC point in hex

    # Verify commitment mathematically
    pe = PedersenEngine()
    v_status = pe.verify(D, C_D, st["blinding_factor_D"])
    assert v_status == CommitmentVerificationStatus.VALID


def test_test_b_seller_sends_buyer_request():
    """
    TEST B:
    Seller sends Buyer request.
    Verify: Status = Pending Buyer Approval.
    """
    # Generate D first
    client.post("/api/transaction/encode_design")

    # Request buyer contribution
    req_res = client.post("/api/transaction/request_buyer")
    assert req_res.status_code == 200
    st = req_res.json()["state"]
    assert st["buyer_request_status"] == "Pending Buyer Approval"


def test_test_c_buyer_approval_and_555_bit_contribution():
    """
    TEST C:
    Switch to Buyer.
    Request is visible.
    Approve request.
    Verify:
      Status = Approved.
      Exact 555-bit demonstration bitstream loaded.
      Length = 555.
      Zeros = 242.
      Ones = 313.
      C_B generated and valid.
    """
    # Setup: generate D and request buyer
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")

    # Buyer approves
    app_res = client.post("/api/transaction/approve_buyer")
    assert app_res.status_code == 200
    st = app_res.json()["state"]

    assert st["buyer_request_status"] == "Approved"
    assert st["buyer_approved"] is True
    assert st["buyer_bitstream_length"] == 555
    assert st["buyer_zeros_count"] == 242
    assert st["buyer_ones_count"] == 313
    assert st["buyer_bitstream_B"] == DEMO_BUYER_BITSTREAM

    C_B = st["C_B"]
    assert C_B is not None
    assert len(C_B) == 66

    # Verify commitment C_B mathematically
    pe = PedersenEngine()
    v_status = pe.verify(DEMO_BUYER_BITSTREAM, C_B, st["blinding_factor_B"])
    assert v_status == CommitmentVerificationStatus.VALID

    # Check buyer private info section exists
    assert st["buyer_private_info"] is not None
    assert st["buyer_private_info"]["blinding_factor_r_B"] == st["blinding_factor_B"]


def test_test_d_switch_back_to_seller_persisted_state():
    """
    TEST D:
    Switch back to Seller.
    Verify:
      Buyer status = Approved.
      Buyer contribution = Received.
      C_B is available.
    """
    # Execute through buyer approval
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")

    # Seller reads persistent transaction state
    res = client.get("/api/transaction/state")
    assert res.status_code == 200
    st = res.json()["state"]

    assert st["buyer_request_status"] == "Approved"
    assert st["buyer_approved"] is True
    assert st["buyer_bitstream_B"] is not None
    assert st["C_B"] is not None
    assert st["selected_design"] == "IIR Butterworth Filter"
    assert st["design_encoding_D"] is not None
    assert st["C_D"] is not None


def test_test_e_continue_existing_watermark_workflow():
    """
    TEST E:
    Continue existing watermark workflow.
    Verify:
      Existing watermark generation still works.
      Existing commitment generation still works.
      Existing W1/W2 workflow works.
      Existing embedding still works.
    """
    # Complete up to Buyer approval
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")

    # Continue watermark workflow
    cont_res = client.post("/api/transaction/continue_watermark", json={
        "transaction_id": "TX-2026-BW01",
        "seller_id": "SELLER-CORE-01",
        "buyer_id": "BUYER-SOC-CORP",
        "license_type": "exclusive",
        "k_tx": "K_tx_symmetric_credential_secret_777",
        "watermark_length": "auto",
    })
    assert cont_res.status_code == 200
    st = cont_res.json()["state"]

    # Canonical 256-bit watermark W
    assert st["watermark_W"] is not None
    assert len(st["watermark_W"]) == 256
    assert st["C_W"] is not None

    # Full watermark embedding (or legacy W1/W2 split)
    assert st["W1"] is not None
    assert len(st["W1"]) > 0
    assert st["C_W1"] is not None
    if st.get("is_full_watermark"):
        assert len(st["W1"]) == 256
        assert st["protected_W2"] is None
    else:
        assert st["protected_W2"] is not None
        assert len(st["W1"]) + len(st["protected_W2"]) == 256

    # Watermarked RTL embedding
    assert st["watermarked_RTL"] is not None
    assert "module iir_butterworth_filter_protected" in st["watermarked_RTL"]

    # Structural encoding present
    assert st["secured_encoding_E_S"] is not None

    # Verify commitment C_W mathematically
    pe = PedersenEngine()
    v_status = pe.verify(st["watermark_W"], st["C_W"], st["blinding_factor_W"])
    assert v_status == CommitmentVerificationStatus.VALID

    # Verify commitment C_W1 mathematically
    v1_status = pe.verify(st["W1"], st["C_W1"], st["blinding_factor_W1"])
    assert v1_status == CommitmentVerificationStatus.VALID


def test_section_14_test_a_buyer_empty_state_and_dom():
    """
    Test A: Buyer profile rendering with no pending request.
    Expected: useful empty state 'No pending transaction requests.', not a blank page.
    """
    # Verify via API state
    res = client.get("/api/transaction/state")
    assert res.status_code == 200
    st = res.json()["state"]
    assert st["buyer_request_status"] == "Not Requested"
    assert st["buyer_approved"] is False

    # Verify static HTML contains the empty state container and text
    with open("hardware_ip_protection/web/static/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    assert "No pending transaction requests." in html
    assert 'id="buyerNoRequestView"' in html
    assert 'id="buyerRequestActiveView"' in html
    assert 'id="buyerTransactionDetailsCard"' in html


def test_section_14_test_b_request_visibility_and_identifiers():
    """
    Test B: Seller sends request.
    Expected: Shared transaction appears with TX-001, SELLER-001, BUYER-001, and Pending status.
    """
    client.post("/api/transaction/encode_design")
    req_res = client.post("/api/transaction/request_buyer")
    assert req_res.status_code == 200

    # Buyer inspects state
    st_res = client.get("/api/transaction/state")
    st = st_res.json()["state"]
    assert st["transaction_id"] == "TX-001"
    assert st["seller_id"] == "SELLER-001"
    assert st["buyer_id"] == "BUYER-001"
    assert st["selected_design"] == "IIR Butterworth Filter"
    assert st["selected_encoding_rule"] == "IIR Butterworth Encoding Rule"
    assert st["buyer_request_status"] == "Pending Buyer Approval"
    assert st["buyer_contribution_status"] == "Not Received"
    assert st["buyer_commitment_status"] == "Not Generated"


def test_section_14_test_c_buyer_contribution_and_commitment_generation():
    """
    Test C: Load exact demonstration bitstream.
    Verify: length 555, 242 zeros, 313 ones.
    Generate C_B before approval.
    Expected: C_B generated, associated with TX-001, mathematically valid.
    """
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")

    # Generate buyer commitment prior to approval
    gen_res = client.post("/api/transaction/generate_buyer_commitment")
    assert gen_res.status_code == 200
    st = gen_res.json()["state"]

    # Verify bitstream properties
    assert st["buyer_bitstream_length"] == 555
    assert st["buyer_zeros_count"] == 242
    assert st["buyer_ones_count"] == 313
    assert st["buyer_bitstream_B"] == DEMO_BUYER_BITSTREAM

    # Verify counts match raw bitstream
    assert DEMO_BUYER_BITSTREAM.count("0") == 242
    assert DEMO_BUYER_BITSTREAM.count("1") == 313
    assert len(DEMO_BUYER_BITSTREAM) == 555

    # Verify C_B
    C_B = st["C_B"]
    assert C_B is not None
    assert len(C_B) == 66
    assert st["buyer_commitment_status"] == "Generated"

    # Verify commitment math
    pe = PedersenEngine()
    assert pe.verify(DEMO_BUYER_BITSTREAM, C_B, st["blinding_factor_B"]) == CommitmentVerificationStatus.VALID


def test_section_14_test_d_approval_and_rejection():
    """
    Test D: Buyer approves transfer request.
    Expected:
      - Request status = Approved
      - Buyer Approval = Approved
      - Buyer Contribution = Received
      - C_B available
      - Seller reflects approval
      - Rejection also tested
    """
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/generate_buyer_commitment")

    # Approve
    app_res = client.post("/api/transaction/approve_buyer")
    assert app_res.status_code == 200
    st = app_res.json()["state"]

    assert st["buyer_request_status"] == "Approved"
    assert st["buyer_approved"] is True
    assert st["buyer_contribution_status"] == "Received"
    assert st["buyer_commitment_status"] == "Generated"
    assert st["C_B"] is not None

    # Seller fetches state and sees approval
    seller_state = client.get("/api/transaction/state").json()["state"]
    assert seller_state["buyer_approved"] is True
    assert seller_state["buyer_request_status"] == "Approved"

    # Reset and test rejection flow
    mgr = TransactionManager.get_instance()
    mgr.reset()
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")
    rej_res = client.post("/api/transaction/reject_buyer")
    assert rej_res.status_code == 200
    rej_st = rej_res.json()["state"]
    assert rej_st["buyer_request_status"] == "Rejected"
    assert rej_st["buyer_approved"] is False
    assert rej_st["buyer_rejected"] is True


def test_section_14_test_e_private_evidence_both_profiles():
    """
    Test E: Private Evidence tabs in both profiles.
    Verify role-specific confidential data.
    Verify ungenerated values are marked and not fabricated.
    """
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")

    st = client.get("/api/transaction/state").json()["state"]

    # Before watermark workflow, seller W and W1 are not generated yet
    assert st["watermark_W"] is None
    assert st["W1"] is None
    assert st["seller_private_info"]["watermark_W"] == "Not generated yet"
    assert st["seller_private_info"]["W1_embedded"] == "Not generated yet"

    # Buyer private info contains B and r_B
    assert st["buyer_private_info"] is not None
    assert st["buyer_private_info"]["bitstream_B"] == DEMO_BUYER_BITSTREAM
    assert st["buyer_private_info"]["blinding_factor_r_B"] is not None

    # Seller continues watermark
    client.post("/api/transaction/continue_watermark", json={})
    st2 = client.get("/api/transaction/state").json()["state"]

    # Seller private info now populated
    spi = st2["seller_private_info"]
    assert spi["design_encoding_D"] == st2["design_encoding_D"]
    assert spi["watermark_W"] == st2["watermark_W"]
    assert spi["W1_embedded"] == st2["W1"]
    assert spi["W2_protected"] == st2["protected_W2"]
    assert spi["blinding_factor_r_D"] == st2["blinding_factor_D"]
    assert spi["blinding_factor_r_W"] == st2["blinding_factor_W"]
    assert spi["blinding_factor_r_W1"] == st2["blinding_factor_W1"]


def test_section_14_test_f_commitments_audit_and_cv():
    """
    Test F: Commitments categories audit:
      - C_D, C_W, C_W1, conditional C_ES ('NOT_REQUIRED')
      - C_B (buyer)
      - C_V (separately categorized for behavioral verification)
    """
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")
    client.post("/api/transaction/continue_watermark", json={})

    st = client.get("/api/transaction/state").json()["state"]

    assert st["C_D"] is not None
    assert st["C_W"] is not None
    assert st["C_W1"] is not None
    assert st["C_ES"] == "NOT_REQUIRED"
    assert st["C_B"] is not None
    assert st["C_V"] is not None

    # Ensure C_V is distinct from watermark commitments
    assert st["C_V"] != st["C_W"]
    assert st["C_V"] != st["C_W1"]


def test_section_14_test_g_existing_functionality_preserved():
    """
    Test G: Encoding, watermark generation, embedding, and behavioral verification still work.
    """
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")
    res = client.post("/api/transaction/continue_watermark", json={})
    assert res.status_code == 200
    st = res.json()["state"]

    # Watermarked RTL generated
    assert st["watermarked_RTL"] is not None
    assert len(st["watermarked_RTL"]) > 500

    # Pipeline results populated
    assert st["pipeline_result"] is not None
    assert st["pipeline_result"]["capacity_analysis"] is not None
    assert st["pipeline_result"]["watermark_mapping"] is not None
    assert st["pipeline_result"]["test_vectors"] is not None
    assert st["pipeline_result"]["behavioral_verification"]["status"] == "MATCH"


def test_section_14_test_h_incorrect_evidence_fails_verification():
    """
    Test H: Verification rejects incorrect opening or altered bitstream.
    Confirms altered values never incorrectly appear as verified.
    """
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")
    st = client.get("/api/transaction/state").json()["state"]

    pe = PedersenEngine()
    C_B = st["C_B"]
    r_B = st["blinding_factor_B"]

    # 1. Correct opening -> VALID
    assert pe.verify(DEMO_BUYER_BITSTREAM, C_B, r_B) == CommitmentVerificationStatus.VALID

    # 2. Tampered bitstream -> INVALID
    tampered_bitstream = ("1" if DEMO_BUYER_BITSTREAM[0] == "0" else "0") + DEMO_BUYER_BITSTREAM[1:]
    assert pe.verify(tampered_bitstream, C_B, r_B) == CommitmentVerificationStatus.INVALID

    # 3. Tampered blinding factor -> INVALID
    tampered_r = hex((int(r_B, 16) + 1) % (2**256))[2:].zfill(64)
    assert pe.verify(DEMO_BUYER_BITSTREAM, C_B, tampered_r) == CommitmentVerificationStatus.INVALID


def test_seller_commitment_panel_ownership_and_categories():
    """
    Validates:
    1. C_B is NOT present in Seller's viewCommitments panel.
    2. Exactly 4 categories in Seller panel: C_D, C_W, C_W1, C_ES.
    3. C_ES displays 'Not Required (E_S = D)' without a fake commitment.
    4. C_V is separated in Behavioral Verification Evidence.
    5. C_B belongs exclusively to Buyer profile.
    """
    res = client.get("/")
    assert res.status_code == 200
    html = res.text

    # Extract viewCommitments section
    assert '<div id="viewCommitments"' in html
    view_comm_start = html.index('<div id="viewCommitments"')
    view_comm_end = html.index('<!-- Reference link to Stage 1 Design Encoding -->')
    seller_comm_html = html[view_comm_start:view_comm_end]

    # 1. C_B must NOT be in Seller commitment cards
    assert 'commCbHex' not in seller_comm_html
    assert 'C_B: Buyer Contribution Commitment' not in seller_comm_html

    # 2. Four categories must be present in Seller panel
    assert 'C_D: Original Design Encoding Commitment' in seller_comm_html
    assert 'C_W: Complete Watermark Commitment' in seller_comm_html
    assert 'C_W1: Embedded Watermark Commitment' in seller_comm_html
    assert 'C_ES: Secured Encoding Commitment' in seller_comm_html

    # 3. C_ES displays 'Not Required (E_S = D)'
    assert 'Not Required (E_S = D)' in seller_comm_html
    assert 'Secured encoding commitment not required for this transaction (E_S equals D).' in seller_comm_html

    # 4. C_V is kept separate as behavioral verification evidence
    assert 'C_V: Simulation Test-Vector Commitment' in seller_comm_html
    assert 'Separately categorized behavioral verification evidence' in seller_comm_html

    # 5. C_B is in Buyer profile
    assert 'buyerDetailsCbHex' in html
    assert 'C_B: Buyer Contribution Commitment' in html


def test_seller_private_evidence_reconstruction_and_verification_rules():
    """
    Validates Seller Private Evidence area contains both:
    A. Reconstruction method/rules for independent Verifier computation
    B. Commitment verification information (formula, parameters, secret opening, stored commitment)
    Preserves exact encoding and outputs for IIR Butterworth.
    """
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")
    client.post("/api/transaction/continue_watermark", json={})

    st = client.get("/api/transaction/state").json()["state"]
    spi = st["seller_private_info"]
    assert spi is not None

    # --- C_D Evidence ---
    assert "C_D_evidence" in spi
    cd_ev = spi["C_D_evidence"]
    cd_rm = cd_ev["reconstruction_method"]
    assert cd_rm["selected_design"] == "IIR Butterworth Filter"
    assert cd_rm["encoding_rule_id"] == "iir_butterworth_rule_v1"
    assert cd_rm["encoding_rule_version"] in ("1.0", "v1.0")
    assert cd_rm["control_step_encoding_method"] is not None
    assert cd_rm["node_id_encoding_method"] is not None
    assert cd_rm["op_type_encoding_method"] is not None
    assert cd_rm["step_node_count_encoding_method"] is not None
    assert cd_rm["concatenation_procedure"] is not None
    assert cd_rm["expected_total_bits"] == 143
    assert cd_rm["canonical_bitstream"] == st["design_encoding_D"]

    cd_cv = cd_ev["commitment_verification"]
    assert "C_D = s_D * G + r_D * H" in cd_cv["commitment_scheme_formula"]
    assert cd_cv["opening_factor_r_D"] == st["blinding_factor_D"]
    assert cd_cv["stored_commitment_C_D"] == st["C_D"]

    pe = PedersenEngine()
    assert pe.verify(cd_rm["canonical_bitstream"], cd_cv["stored_commitment_C_D"], cd_cv["opening_factor_r_D"]) == CommitmentVerificationStatus.VALID

    # --- C_W Evidence ---
    assert "C_W_evidence" in spi
    cw_ev = spi["C_W_evidence"]
    cw_rm = cw_ev["reconstruction_method"]
    assert "HKDF" in cw_rm["watermark_generation_rule"]
    assert "k_tx" in cw_rm["precise_inputs_and_ordering"].lower()
    assert cw_rm["output_length_bits"] == 256
    assert cw_rm["canonical_watermark"] == st["watermark_W"]

    cw_cv = cw_ev["commitment_verification"]
    assert "C_W = s_W * G + r_W * H" in cw_cv["commitment_scheme_formula"]
    assert cw_cv["opening_factor_r_W"] == st["blinding_factor_W"]
    assert cw_cv["stored_commitment_C_W"] == st["C_W"]
    assert pe.verify(cw_rm["canonical_watermark"], cw_cv["stored_commitment_C_W"], cw_cv["opening_factor_r_W"]) == CommitmentVerificationStatus.VALID

    # --- C_W1 Evidence ---
    assert "C_W1_evidence" in spi
    cw1_ev = spi["C_W1_evidence"]
    cw1_rm = cw1_ev["reconstruction_method"]
    if st.get("is_full_watermark"):
        assert cw1_rm["w1_bit_length"] == 256
        assert cw1_rm["w2_bit_length"] == 0
        assert cw1_rm["canonical_w1"] == st["W1"]
    else:
        assert cw1_rm["w1_bit_length"] == 32
        assert cw1_rm["w2_bit_length"] == 224
        assert cw1_rm["canonical_w1"] == st["W1"]
        assert cw1_rm["canonical_w2"] == st["protected_W2"]
        assert cw1_rm["canonical_w1"] + cw1_rm["canonical_w2"] == cw_rm["canonical_watermark"]

        cw1_cv = cw1_ev["commitment_verification"]
        assert "C_W1 = s_W1 * G + r_W1 * H" in cw1_cv["commitment_scheme_formula"]
        assert cw1_cv["opening_factor_r_W1"] == st["blinding_factor_W1"]
        assert cw1_cv["stored_commitment_C_W1"] == st["C_W1"]
        assert pe.verify(cw1_rm["canonical_w1"], cw1_cv["stored_commitment_C_W1"], cw1_cv["opening_factor_r_W1"]) == CommitmentVerificationStatus.VALID

    # --- C_ES Evidence (Conditional) ---
    assert "C_ES_evidence" in spi
    ces_ev = spi["C_ES_evidence"]
    assert ces_ev["status"] == "NOT_REQUIRED"
    assert ces_ev["is_required"] is False
    assert ces_ev["invariance_analysis"]["E_S_equals_D"] is True
    assert ces_ev["commitment_verification"]["stored_commitment_C_ES"] is None


def test_buyer_private_evidence_reconstruction_and_verification_rules():
    """
    Validates Buyer Private Evidence contains exact 555-bit bitstream,
    loading/derivation method, validated bit counts, commitment formula,
    opening factor r_B, and C_B.
    """
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")

    st = client.get("/api/transaction/state").json()["state"]
    bpi = st["buyer_private_info"]
    assert bpi is not None
    assert "C_B_evidence" in bpi

    cb_ev = bpi["C_B_evidence"]
    cb_rm = cb_ev["reconstruction_method"]
    assert cb_rm["expected_length_bits"] == 555
    assert cb_rm["validated_zeros_count"] == 242
    assert cb_rm["validated_ones_count"] == 313
    assert cb_rm["canonical_bitstream_B"] == DEMO_BUYER_BITSTREAM
    assert "fingerprint_minutiae_demo_standard" in cb_rm["loading_derivation_method"]

    cb_cv = cb_ev["commitment_verification"]
    assert "C_B = s_B * G + r_B * H" in cb_cv["commitment_scheme_formula"]
    assert cb_cv["opening_factor_r_B"] == st["blinding_factor_B"]
    assert cb_cv["stored_commitment_C_B"] == st["C_B"]

    pe = PedersenEngine()
    assert pe.verify(cb_rm["canonical_bitstream_B"], cb_cv["stored_commitment_C_B"], cb_cv["opening_factor_r_B"]) == CommitmentVerificationStatus.VALID


def test_independent_stage2_progression():
    """
    Validates targeted correction:
    1. Stage 2B executes ONLY watermark generation (W), without committing, splitting, or embedding.
    2. Stage 2C executes ONLY commitment of W (C_W).
    3. Stage 2D executes ONLY splitting into W1 (32b) and W2 (224b).
    4. Stage 2E executes ONLY commitment of W1 (C_W1).
    5. Stage 3 embeds W1 into RTL and synthesizes Verilog.
    """
    pe = PedersenEngine()

    # Step 1: Design Encoding
    client.post("/api/transaction/encode_design")
    # Step 2A: Buyer Contribution
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")

    # Verify state before 2B
    st0 = client.get("/api/transaction/state").json()["state"]
    assert st0["buyer_approved"] is True
    assert st0["watermark_W"] is None

    # Substage 2B: Generate Watermark ONLY
    res_2b = client.post("/api/transaction/generate_watermark", json={
        "transaction_id": "TX-001",
        "seller_id": "SELLER-001",
        "buyer_id": "BUYER-001",
        "license_type": "exclusive",
        "k_tx": "K_tx_symmetric_credential_secret_777",
        "watermark_length": "auto",
    })
    assert res_2b.status_code == 200
    st_2b = res_2b.json()["state"]

    # Stage 2B must have generated W
    W = st_2b["watermark_W"]
    assert W is not None
    assert len(W) == 256
    # Stage 2B MUST NOT have committed, split, or embedded W
    assert st_2b["C_W"] is None
    assert st_2b["W1"] is None
    assert st_2b["protected_W2"] is None
    assert st_2b["C_W1"] is None
    assert st_2b["watermarked_RTL"] is None
    assert st_2b["pipeline_result"] is None

    # Substage 2C: Commit Original Watermark ONLY
    res_2c = client.post("/api/transaction/commit_watermark")
    assert res_2c.status_code == 200
    st_2c = res_2c.json()["state"]

    # Stage 2C must have generated C_W
    C_W = st_2c["C_W"]
    assert C_W is not None
    assert len(C_W) == 66
    assert pe.verify(W, C_W, st_2c["blinding_factor_W"]) == CommitmentVerificationStatus.VALID
    # Stage 2C MUST NOT have split or embedded W
    assert st_2c["W1"] is None
    assert st_2c["protected_W2"] is None
    assert st_2c["C_W1"] is None
    assert st_2c["watermarked_RTL"] is None

    # Substage 2D: Split and Protect Watermark ONLY
    res_2d = client.post("/api/transaction/split_watermark")
    assert res_2d.status_code == 200
    st_2d = res_2d.json()["state"]

    # Stage 2D must have split into W1 (32b) and protected W2 (224b)
    W1 = st_2d["W1"]
    W2 = st_2d["protected_W2"]
    assert W1 is not None and len(W1) == 32
    assert W2 is not None and len(W2) == 224
    assert W1 + W2 == W
    # Stage 2D MUST NOT have committed W1 or embedded W
    assert st_2d["C_W1"] is None
    assert st_2d["watermarked_RTL"] is None

    # Substage 2E: Commit Embedded Watermark ONLY
    res_2e = client.post("/api/transaction/commit_embedded_watermark")
    assert res_2e.status_code == 200
    st_2e = res_2e.json()["state"]

    # Stage 2E must have generated C_W1
    C_W1 = st_2e["C_W1"]
    assert C_W1 is not None
    assert len(C_W1) == 66
    assert pe.verify(W1, C_W1, st_2e["blinding_factor_W1"]) == CommitmentVerificationStatus.VALID
    # Stage 2E MUST NOT have embedded W into RTL yet
    assert st_2e["watermarked_RTL"] is None

    # Stage 3: Embed Watermark in RTL
    res_3 = client.post("/api/transaction/embed_watermark", json={"watermark_length": "auto"})
    assert res_3.status_code == 200
    st_3 = res_3.json()["state"]

    assert st_3["watermarked_RTL"] is not None
    assert "module iir_butterworth_filter_protected" in st_3["watermarked_RTL"]
    assert st_3["pipeline_result"] is not None
    assert st_3["secured_encoding_E_S"] is not None


def test_watermark_generation_canonical_and_prerequisites():
    """
    Validates that:
    1. Generating watermark fails if buyer contribution is not approved.
    2. Generating watermark is deterministic for identical canonical inputs.
    3. Reopening / re-fetching state does not alter or re-generate values.
    """
    # Without buyer approval, generate_watermark must fail
    res_fail = client.post("/api/transaction/generate_watermark")
    assert res_fail.status_code == 400

    # Execute prerequisites
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")

    # Generate watermark
    res1 = client.post("/api/transaction/generate_watermark")
    assert res1.status_code == 200
    w1 = res1.json()["state"]["watermark_W"]

    # Repeating with the same canonical parameters produces identical deterministic watermark
    res2 = client.post("/api/transaction/generate_watermark")
    assert res2.status_code == 200
    w2 = res2.json()["state"]["watermark_W"]
    assert w1 == w2


def test_stage3_does_not_execute_stage4():
    """
    Validates Requirement 4 & 5:
    Stage 3 embeds watermark in RTL as one operation, but Stage 4 does NOT
    execute automatically as part of embedding.
    """
    client.post("/api/transaction/reset")
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")
    client.post("/api/transaction/generate_watermark")
    client.post("/api/transaction/commit_watermark")
    client.post("/api/transaction/split_watermark")
    client.post("/api/transaction/commit_embedded_watermark")

    # Before Stage 3
    st_pre = client.get("/api/transaction/state").json()["state"]
    assert st_pre["C_W1"] is not None
    assert st_pre["watermarked_RTL"] is None

    # Execute Stage 3
    res_embed = client.post("/api/transaction/embed_watermark")
    assert res_embed.status_code == 200
    st_post = res_embed.json()["state"]

    # Stage 3 results are present
    assert st_post["watermarked_RTL"] is not None
    assert "module iir_butterworth_filter_protected" in st_post["watermarked_RTL"]
    assert st_post["pipeline_result"] is not None
    assert "cig" in st_post["pipeline_result"]
    assert "register_allocation" in st_post["pipeline_result"]

    # CRITICAL: Stage 4 operations must NOT have executed automatically
    assert st_post.get("stage4_es_calculated") is False
    assert st_post.get("stage4_encodings_compared") is False
    assert st_post.get("stage4_behavioral_verified") is False
    assert st_post.get("stage4_completed") is False


def test_stage4_sequential_user_actions_and_prerequisites():
    """
    Validates Requirement 5:
    Stage 4 executes progressively, with separate user actions for:
    - 4B: Calculate Secured Design Encoding (E_S)
    - 4C: Compare Encodings (E_S vs D)
    - 4D: Behavioral Simulation Validation
    Prerequisites must be strictly enforced: later steps cannot run until previous steps succeed.
    """
    client.post("/api/transaction/reset")
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")
    client.post("/api/transaction/generate_watermark")
    client.post("/api/transaction/commit_watermark")
    client.post("/api/transaction/split_watermark")
    client.post("/api/transaction/commit_embedded_watermark")
    client.post("/api/transaction/embed_watermark")

    # Enforce prerequisites: cannot compare before E_S calculation
    res_early_compare = client.post("/api/transaction/compare_encodings")
    assert res_early_compare.status_code == 400
    assert "must be calculated before comparing" in res_early_compare.json()["detail"]

    # Enforce prerequisites: cannot simulate before compare
    res_early_sim = client.post("/api/transaction/verify_behavioral")
    assert res_early_sim.status_code == 400
    assert "Encodings must be compared" in res_early_sim.json()["detail"]

    # Step 4B: User explicitly calculates E_S
    res_es = client.post("/api/transaction/calculate_secured_encoding")
    assert res_es.status_code == 200
    st_es = res_es.json()["state"]
    assert st_es["stage4_es_calculated"] is True
    assert st_es["secured_encoding_E_S"] is not None
    es_bits = st_es["secured_encoding_E_S"]["canonical_bitstream"] if isinstance(st_es["secured_encoding_E_S"], dict) else st_es["secured_encoding_E_S"]
    assert len(es_bits) == 143
    assert st_es["stage4_encodings_compared"] is False
    assert st_es["stage4_completed"] is False

    # Enforce prerequisites: cannot simulate before compare
    res_early_sim2 = client.post("/api/transaction/verify_behavioral")
    assert res_early_sim2.status_code == 400

    # Step 4C: User explicitly compares encodings
    res_cmp = client.post("/api/transaction/compare_encodings")
    assert res_cmp.status_code == 200
    st_cmp = res_cmp.json()["state"]
    assert st_cmp["stage4_encodings_compared"] is True
    assert st_cmp["encoding_comparison_result"]["match"] is True
    assert st_cmp["encoding_comparison_result"]["length_E_S"] == 143
    assert st_cmp["encoding_comparison_result"]["length_D"] == 143
    assert st_cmp["stage4_behavioral_verified"] is False
    assert st_cmp["stage4_completed"] is False

    # Step 4D: User explicitly executes behavioral validation
    res_behav = client.post("/api/transaction/verify_behavioral")
    assert res_behav.status_code == 200
    st_behav = res_behav.json()["state"]
    assert st_behav["stage4_behavioral_verified"] is True
    assert st_behav["stage4_completed"] is True
    b_res = st_behav["behavioral_validation_result"]
    assert b_res["total_vectors"] >= 32
    assert b_res["exact_matches"] == b_res["total_vectors"]
    assert b_res["mismatches"] == 0
    assert b_res["passed"] is True


def test_completed_substages_retain_results_without_recalculation():
    """
    Validates Requirement 1 & 6:
    Moving forward retains all previously generated results in application state
    without recalculating or duplicating commitments.
    """
    client.post("/api/transaction/reset")
    client.post("/api/transaction/encode_design")
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")
    client.post("/api/transaction/generate_watermark")
    client.post("/api/transaction/commit_watermark")
    client.post("/api/transaction/split_watermark")
    client.post("/api/transaction/commit_embedded_watermark")
    client.post("/api/transaction/embed_watermark")
    client.post("/api/transaction/calculate_secured_encoding")
    client.post("/api/transaction/compare_encodings")
    client.post("/api/transaction/verify_behavioral")

    st = client.get("/api/transaction/state").json()["state"]

    # Stage 1 evidence preserved
    assert st["design_encoding_D"] is not None
    assert st["C_D"] is not None
    assert st["blinding_factor_D"] is not None

    # Stage 2 evidence preserved
    assert st["buyer_bitstream_B"] is not None
    assert st["C_B"] is not None
    assert st["watermark_W"] is not None
    assert st["C_W"] is not None
    assert st["W1"] is not None
    assert st["protected_W2"] is not None
    assert st["C_W1"] is not None

    # Stage 3 results preserved
    assert st["watermarked_RTL"] is not None
    assert st["pipeline_result"] is not None

    # Stage 4 results preserved
    assert st["secured_encoding_E_S"] is not None
    assert st["stage4_completed"] is True
    assert st["protected_W2"] is not None
    assert st["C_W1"] is not None

    # Stage 3 results preserved
    assert st["watermarked_RTL"] is not None
    assert st["pipeline_result"] is not None

    # Stage 4 results preserved
    assert st["secured_encoding_E_S"] is not None
    assert st["stage4_completed"] is True





