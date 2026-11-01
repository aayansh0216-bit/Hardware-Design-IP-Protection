import pytest
from fastapi.testclient import TestClient

from hardware_ip_protection.web.app import app
from hardware_ip_protection.pipeline.interrogation_manager import InterrogationManager
from hardware_ip_protection.pipeline.transaction_manager import (
    TransactionManager,
    DEMO_BUYER_BITSTREAM,
)
from hardware_ip_protection.verification.interrogation_engine import (
    EXPECTED_251_SECURED_BITSTREAM,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_judge_state():
    im = InterrogationManager.get_instance()
    tx_id = "TX-TEST-INSTANT-001"
    im.reset_judge_workflow(tx_id)
    im.reset_judge_workflow("TX-001")
    yield
    im.reset_judge_workflow(tx_id)
    im.reset_judge_workflow("TX-001")


def test_manual_mode_is_default_and_starts_clean():
    """Verifies that manual interrogation is the clean default and progresses step-by-step."""
    tx_id = "TX-TEST-INSTANT-001"
    res = client.post("/api/judge/session/start", json={
        "transaction_id": tx_id,
        "workflow": "secured_design_encoding",
    })
    assert res.status_code == 200
    data = res.json()
    assert data["workflow"] == "secured_design_encoding"
    assert "IN PROGRESS" in data["status"]
    assert len(data["history_ledger"]) == 0
    assert data["current_question"] is not None
    assert data["current_question"]["id"] == "Q0.1"

    # Answer Q0.1 manually
    ans_res = client.post("/api/judge/session/answer", json={
        "session_id": data["session_id"],
        "question_id": "Q0.1",
        "answer": 251,
    })
    assert ans_res.status_code == 200
    ans_data = ans_res.json()
    assert len(ans_data["history_ledger"]) == 1
    assert ans_data["history_ledger"][0]["question_id"] == "Q0.1"
    assert ans_data["history_ledger"][0]["effective_answer"] == 251
    assert ans_data["current_question"]["id"] == "Q0.2"


def test_instant_verify_secured():
    """Verifies that Instant Verification executes the entire question pipeline and verifies C_ES."""
    tx_id = "TX-TEST-INSTANT-001"
    # Start session
    start_res = client.post("/api/judge/session/start", json={
        "transaction_id": tx_id,
        "workflow": "secured_design_encoding",
    })
    session_id = start_res.json()["session_id"]

    # Execute Instant Verification
    inst_res = client.post("/api/judge/secured/instant_verify", json={
        "session_id": session_id,
    })
    assert inst_res.status_code == 200
    data = inst_res.json()

    assert data["status"] == "COMPLETE"
    assert data["evaluation"]["is_complete_251"] is True
    assert len(data["evaluation"]["reconstructed_bitstream"]) == 251
    assert data["evaluation"]["reconstructed_bitstream"] == EXPECTED_251_SECURED_BITSTREAM

    # Check that question history is populated with all answers
    assert len(data["history_ledger"]) == 118
    assert data["evaluation"]["is_complete_251"] is True
    assert data["candidate_space"]["unresolved_positions"] >= 0

    # Check commitment verification C_ES
    cv = data["evaluation"]["commitment_verification"]
    assert cv["status"] == "VERIFIED"
    assert cv["target_commitment"] is not None
    assert cv["recalculated_commitment"] is not None


def test_unsecured_reconstruction_gating():
    """Verifies that Unsecured Encoding Reconstruction is gated behind verified Secured Encoding."""
    tx_id = "TX-TEST-INSTANT-001"

    # Attempt to access unsecured state before secured is verified
    res = client.get(f"/api/judge/unsecured/state?transaction_id={tx_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["prerequisite_met"] is False
    assert data["status"] == "BLOCKED"

    # Attempt to execute reconstruction while blocked
    recon_res = client.post("/api/judge/unsecured/reconstruct", json={
        "transaction_id": tx_id,
        "mode": "manual",
    })
    assert recon_res.status_code == 200
    rdata = recon_res.json()
    assert rdata["status"] == "BLOCKED"
    assert rdata["success"] is False


def test_unsecured_reconstruction_manual_and_instant():
    """Verifies both manual and instant reconstruction of unsecured encoding and C_D commitment check."""
    tx_id = "TX-TEST-INSTANT-001"

    # 1. Complete secured verification first via instant shortcut
    start_res = client.post("/api/judge/session/start", json={
        "transaction_id": tx_id,
        "workflow": "secured_design_encoding",
    })
    session_id = start_res.json()["session_id"]
    client.post("/api/judge/secured/instant_verify", json={"session_id": session_id})

    # 2. Check unsecured state: should now be ready
    st_res = client.get(f"/api/judge/unsecured/state?transaction_id={tx_id}")
    assert st_res.status_code == 200
    st_data = st_res.json()
    assert st_data["prerequisite_met"] is True
    assert st_data["status"] == "READY"
    genuine_count = st_data["secured_cig"]["genuine_edges_count"]
    artificial_count = st_data["secured_cig"]["artificial_edges_count"]
    assert genuine_count > 0
    assert artificial_count > 0
    assert st_data["secured_cig"]["total_edges"] == genuine_count + artificial_count

    # 3. Test Manual Reconstruction: providing specific artificial edges to strip
    art_edges = st_data["secured_cig"]["artificial_edges"]
    recon_manual = client.post("/api/judge/unsecured/reconstruct", json={
        "transaction_id": tx_id,
        "mode": "manual",
        "provided_edges": art_edges,
    })
    assert recon_manual.status_code == 200
    m_data = recon_manual.json()
    assert m_data["status"] == "VERIFIED"
    assert m_data["success"] is True
    assert m_data["recovered_cig"]["total_edges"] == genuine_count
    assert m_data["removed_constraints_count"] == artificial_count
    assert len(m_data["reconstructed_D"]) == 251
    assert m_data["commitment_verification"]["status"] == "VERIFIED"

    # 4. Test Instant Reconstruction: auto-fetching and stripping
    recon_instant = client.post("/api/judge/unsecured/reconstruct", json={
        "transaction_id": tx_id,
        "mode": "instant",
    })
    assert recon_instant.status_code == 200
    i_data = recon_instant.json()
    assert i_data["status"] == "VERIFIED"
    assert i_data["success"] is True
    assert i_data["recovered_cig"]["total_edges"] == genuine_count
    assert i_data["commitment_verification"]["status"] == "VERIFIED"


def test_watermark_verification_gating():
    """Verifies that Watermark Verification is gated behind verified Unsecured Encoding."""
    tx_id = "TX-TEST-INSTANT-001"

    # Check watermark state before unsecured is verified
    res = client.get(f"/api/judge/watermark/state?transaction_id={tx_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["prerequisite_met"] is False
    assert data["status"] == "BLOCKED"

    # Attempt to verify watermark while blocked
    wm_res = client.post("/api/judge/watermark/verify", json={
        "transaction_id": tx_id,
        "buyer_bitstream": DEMO_BUYER_BITSTREAM,
    })
    assert wm_res.status_code == 200
    assert wm_res.json()["status"] == "BLOCKED"


def test_watermark_verification_manual_and_instant():
    """Verifies watermark relationship evaluation W = HKDF(D, B, T) and commitment C_W verification."""
    tx_id = "TX-TEST-INSTANT-001"

    # 1. Complete Stage 1 (Secured)
    start_res = client.post("/api/judge/session/start", json={
        "transaction_id": tx_id,
        "workflow": "secured_design_encoding",
    })
    client.post("/api/judge/secured/instant_verify", json={"session_id": start_res.json()["session_id"]})

    # 2. Complete Stage 2 (Unsecured)
    client.post("/api/judge/unsecured/reconstruct", json={"transaction_id": tx_id, "mode": "instant"})

    # 3. Check Watermark state: should be ready
    st_res = client.get(f"/api/judge/watermark/state?transaction_id={tx_id}")
    assert st_res.status_code == 200
    st_data = st_res.json()
    assert st_data["prerequisite_met"] is True
    assert st_data["status"] == "READY"

    # 4. Test invalid buyer biometric bitstream
    inv_res = client.post("/api/judge/watermark/verify", json={
        "transaction_id": tx_id,
        "buyer_bitstream": "invalid_bits_123",
        "mode": "manual",
    })
    assert inv_res.status_code == 200
    assert inv_res.json()["status"] == "FAILED"

    # 5. Test manual verification with valid buyer biometric bitstream
    m_res = client.post("/api/judge/watermark/verify", json={
        "transaction_id": tx_id,
        "buyer_bitstream": DEMO_BUYER_BITSTREAM,
        "mode": "manual",
    })
    assert m_res.status_code == 200
    m_data = m_res.json()
    assert m_data["status"] == "VERIFIED"
    assert m_data["success"] is True
    assert len(m_data["watermark_bitstream"]) == 256
    assert m_data["commitment_verification"]["status"] == "VERIFIED"

    # 6. Test instant verification shortcut
    i_res = client.post("/api/judge/watermark/verify", json={
        "transaction_id": tx_id,
        "mode": "instant",
    })
    assert i_res.status_code == 200
    i_data = i_res.json()
    assert i_data["status"] == "VERIFIED"
    assert i_data["success"] is True


def test_final_adjudication_overview_and_reset():
    """Verifies that final adjudication overview accurately reflects all 4 stages and resets properly."""
    tx_id = "TX-TEST-INSTANT-001"

    # 1. Initially in progress
    ov_res0 = client.get(f"/api/judge/overview?transaction_id={tx_id}")
    assert ov_res0.status_code == 200
    assert ov_res0.json()["all_stages_completed"] is False
    assert ov_res0.json()["overall_verdict"] == "IN_PROGRESS"

    # 2. Complete all stages via instant shortcuts
    start_res = client.post("/api/judge/session/start", json={
        "transaction_id": tx_id,
        "workflow": "secured_design_encoding",
    })
    client.post("/api/judge/secured/instant_verify", json={"session_id": start_res.json()["session_id"]})
    client.post("/api/judge/unsecured/reconstruct", json={"transaction_id": tx_id, "mode": "instant"})
    client.post("/api/judge/watermark/verify", json={"transaction_id": tx_id, "mode": "instant"})

    # 3. Overview should now be fully verified
    ov_res1 = client.get(f"/api/judge/overview?transaction_id={tx_id}")
    assert ov_res1.status_code == 200
    ov_data = ov_res1.json()
    assert ov_data["all_stages_completed"] is True
    assert ov_data["overall_verdict"] == "AUTHENTICATED_AND_VERIFIED"
    assert ov_data["stages"]["stage1_secured_encoding"]["status"] == "VERIFIED"
    assert ov_data["stages"]["stage2_interrogation_report"]["status"] == "READY"
    assert ov_data["stages"]["stage3_unsecured_encoding"]["status"] == "VERIFIED"
    assert ov_data["stages"]["stage4_watermark_verification"]["status"] == "VERIFIED"

    # 4. Workflow Reset cascades and disables downstream
    rst_res = client.post("/api/judge/workflow/reset", json={
        "transaction_id": tx_id,
        "session_id": start_res.json()["session_id"],
    })
    assert rst_res.status_code == 200

    ov_res2 = client.get(f"/api/judge/overview?transaction_id={tx_id}")
    assert ov_res2.status_code == 200
    assert ov_res2.json()["all_stages_completed"] is False
    assert ov_res2.json()["overall_verdict"] == "IN_PROGRESS"
