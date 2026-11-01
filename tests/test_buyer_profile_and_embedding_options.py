"""
Tests for Buyer Profile visibility, removal of seller report page,
and multi-length watermark embedding options (32, 64, 128, 256 bits).
"""

import os
import pytest
from fastapi.testclient import TestClient

from hardware_ip_protection.web.app import app
from hardware_ip_protection.pipeline.transaction_manager import TransactionManager

client = TestClient(app)


def test_html_profile_buyer_and_no_seller_report_card():
    html_path = os.path.join(
        os.path.dirname(__file__), "..", "hardware_ip_protection", "web", "static", "index.html"
    )
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    # Verify profileBuyer exists as a top-level tab-pane
    assert 'id="profileBuyer"' in html
    assert 'class="profile-badge-buyer"' in html
    assert 'id="buyerTransactionSummaryCard"' in html

    # Verify all 4 profiles exist
    assert 'id="profileSeller"' in html
    assert 'id="profileBuyer"' in html
    assert 'id="profileVerifier"' in html
    assert 'id="profileJudge"' in html

    # Verify sellerReportCard was removed from seller profile
    assert 'id="sellerReportCard"' not in html
    assert 'id="sellerNavItemReport"' not in html

    # Verify embedding length radio options exist
    assert 'name="wmEmbedLengthChoice"' in html
    assert 'id="wmEmbedLen32"' in html
    assert 'id="wmEmbedLen64"' in html
    assert 'id="wmEmbedLen128"' in html
    assert 'id="wmEmbedLen256"' in html


@pytest.mark.parametrize("length, min_art_edges", [
    (32, 10),
    (64, 20),
    (128, 35),
    (256, 50),
])
def test_embed_watermark_different_lengths_endpoint(length, min_art_edges):
    tm = TransactionManager.get_instance()
    tm.reset()
    tm.select_design_and_rule("iir_butterworth", "iir_butterworth_5rule_v1")
    tm.generate_original_encoding()
    tm.request_buyer_contribution()
    tm.approve_buyer_request()
    tm.generate_transaction_watermark()
    tm.commit_original_watermark()

    # Call endpoint with specific watermark length
    resp = client.post("/api/transaction/embed_watermark", json={"watermark_length": length})
    assert resp.status_code == 200
    data = resp.json()["state"]

    # Verify state reflects selected length
    assert data["embedded_watermark_length"] == length
    res = data["pipeline_result"]
    assert res["transaction_watermark"]["bit_length"] == length
    assert len(res["transaction_watermark"]["bitstream"]) == length
    assert len(res["cig"]["artificial_edges"]) >= min_art_edges
    assert res["register_allocation"]["protected_count"] >= 16
    assert data["secured_encoding_E_S"] is not None
    assert len(data["secured_encoding_E_S"]["canonical_bitstream"]) == 251

