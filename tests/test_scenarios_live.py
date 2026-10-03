import urllib.request
import json
import pytest

def test_all_scenarios_live():
    base_url = "http://127.0.0.1:8000"
    prot_payload = {
        "benchmark_id": "4point_dct",
        "transaction_id": "TX-VERIFY-2026",
        "seller_id": "SELLER-01",
        "buyer_id": "BUYER-01",
        "license_type": "exclusive",
        "k_tx": "secret-test-key-2026",
        "watermark_length": 8,
    }
    req = urllib.request.Request(
        f"{base_url}/api/protect",
        data=json.dumps(prot_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        prot = json.loads(resp.read().decode("utf-8"))
    prot_id = prot["protection_id"]

    scenarios = ["partial_tamper", "complete_removal", "corrupted", "different_tx", "independent"]
    for s in scenarios:
        req_pre = urllib.request.Request(
            f"{base_url}/api/attack_preset",
            data=json.dumps({"protection_id": prot_id, "preset_type": s}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req_pre) as resp:
            preset = json.loads(resp.read().decode("utf-8"))

        req_disp = urllib.request.Request(
            f"{base_url}/api/dispute",
            data=json.dumps({"protection_id": prot_id, "suspicious_verilog": preset["suspicious_verilog"], "scenario": s}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req_disp) as resp:
            disp = json.loads(resp.read().decode("utf-8"))

        comp = disp["comparison"]
        res = disp["dispute_result"]
        ca = res["behavioral_verification"]["correlation_analysis"]

        # 1. SHA is different for non-untouched scenarios
        assert comp["reference_rtl_sha256"] != comp["suspicious_rtl_sha256"]
        # 2. Reference commitment check is always VALID for the pre-dispute reference design
        assert res["watermark_analysis"]["commitment"]["reference_commitment_check"] == "VALID"
        assert res["test_vector_commitment"]["status"] == "VALID"
        # 3. L1 distance is calculated
        assert ca["l1_distance"] >= 0.0
        # 4. Forensic similarity is computed
        assert comp["percentage_str"] == "N/A" or comp["percentage_str"].endswith("%")

    # Untouched Design check
    req_untouched = urllib.request.Request(
        f"{base_url}/api/dispute",
        data=json.dumps({"protection_id": prot_id, "suspicious_verilog": prot["protected_verilog"], "scenario": "Untouched Design"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req_untouched) as resp:
        disp_u = json.loads(resp.read().decode("utf-8"))

    comp_u = disp_u["comparison"]
    res_u = disp_u["dispute_result"]
    ca_u = res_u["behavioral_verification"]["correlation_analysis"]

    assert comp_u["reference_rtl_sha256"] == comp_u["suspicious_rtl_sha256"]
    assert comp_u["percentage_str"] == "100.00%"
    assert comp_u["similarity_status"] == "EXACT"
    assert ca_u["l1_distance"] == 0.0
    assert comp_u["behavior_status"] == "MATCH"
    assert res_u["watermark_analysis"]["commitment"]["reference_commitment_check"] == "VALID"
    assert res_u["test_vector_commitment"]["status"] == "VALID"
