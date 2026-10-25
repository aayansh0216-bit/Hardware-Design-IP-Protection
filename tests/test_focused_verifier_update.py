"""
Focused Verifier Test Suite:
Validates the three key focus areas:
1. Correct Encoding Verification Workflow (Branch A vs Branch B based on persisted transaction flag)
2. UI cleanliness: no premature bit lengths or success badges in initial/pending state
3. Display canonical hashes instead of raw confidential values; Pedersen commitment arithmetic over digests; hash-first opening order.
"""

import json
import subprocess
import pytest
import hashlib
from fastapi.testclient import TestClient

from hardware_ip_protection.web.app import app
from hardware_ip_protection.pipeline.transaction_manager import (
    TransactionManager,
    DEMO_BUYER_BITSTREAM,
)
from hardware_ip_protection.pipeline.verifier_engine import VerifierEngine
from hardware_ip_protection.pipeline.repository import ProtectionRepository
from hardware_ip_protection.crypto.pedersen import PedersenEngine, CommitmentVerificationStatus
from hardware_ip_protection.pipeline.stages import (
    DesignStructuralEncoder,
    DFG,
    DFGNode,
    ScheduledDFG,
)
from hardware_ip_protection.forensics.watermark_extractor import TransactionWatermarkExtractor



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


def setup_transaction_base(encoding_transform_required: bool = False):
    """Sets up a complete transaction with the specified encoding_transform_required flag."""
    client.post("/api/transaction/select_design", json={
        "design_id": "iir_butterworth",
        "rule_id": "iir_butterworth_rule_v1",
    })
    client.post("/api/transaction/encode_design", json={"use_table_quirks": False})
    client.post("/api/transaction/request_buyer")
    client.post("/api/transaction/approve_buyer")
    res = client.post("/api/transaction/continue_watermark", json={
        "transaction_id": "TX-FOCUS-001",
        "seller_id": "SELLER-001",
        "buyer_id": "BUYER-001",
        "license_type": "exclusive",
        "k_tx": "secret_key_12345",
        "watermark_length": "auto",
        "encoding_transform_required": encoding_transform_required,
    })
    assert res.status_code == 200
    tm = TransactionManager.get_instance()
    st = tm.get_state()
    st.encoding_transform_required = encoding_transform_required
    return st


# ==============================================================================
# Priority 1: Correct Encoding Verification Workflow (Branch A & Branch B)
# ==============================================================================

def test_branch_b_workflow_when_flag_is_false():
    """
    Branch B: encoding_transform_required = false.
    - Step 2 calculates E_S', records canonical hash.
    - Step 3 skips C_ES and marks NOT REQUIRED with reason tied to transaction flag.
    - Step 'transform' marks NOT REQUIRED and aliases E_U' = E_S'.
    - Step 4 verifies C_D directly using E_S' hash.
    """
    setup_transaction_base(encoding_transform_required=False)
    ve = VerifierEngine.get_instance()

    res1 = ve.execute_step(1)
    assert res1.status == "LOADED"

    res2 = ve.execute_step(2)
    assert res2.status == "EXTRACTED"
    es_hash = res2.stage1_reconstruction["canonical_hash"]
    assert len(es_hash) == 64

    # Step 3: C_ES skipped as NOT REQUIRED
    res3 = ve.execute_step(3)
    assert res3.status == "NOT REQUIRED"
    assert "Branch B" in res3.stage1_reconstruction["branch"]
    assert "encoding_transform_required = false" in res3.stage1_reconstruction["detail"]
    assert res3.stage2_verification["status"] == "NOT REQUIRED"

    # Step transform: NOT REQUIRED
    res_trans = ve.execute_step("transform")
    assert res_trans.status == "NOT REQUIRED"
    assert "NOT REQUIRED" in res_trans.stage2_verification["status"]

    # Step 4: C_D verified directly against recorded E_S' hash
    res4 = ve.execute_step(4)
    assert res4.status == "MATCH"
    assert res4.stage2_verification["status"] == "MATCH"
    assert res4.stage1_reconstruction["canonical_hash"] == es_hash


def test_branch_a_workflow_when_flag_is_true():
    """
    Branch A: encoding_transform_required = true.
    - Step 2 calculates E_S', records canonical hash.
    - Step 3 verifies C_ES before applying transformation.
    - If C_ES matches: applies transformation, derives E_U', records hash.
    - Step 4 verifies C_D against transformed E_U' hash.
    """
    setup_transaction_base(encoding_transform_required=True)
    ve = VerifierEngine.get_instance()
    pe = PedersenEngine()

    res1 = ve.execute_step(1)
    assert res1.status == "LOADED"

    res2 = ve.execute_step(2)
    assert res2.status == "EXTRACTED"
    es_hash = res2.stage1_reconstruction["canonical_hash"]

    # Generate a valid C_ES for E_S' hash
    r_es = 9876543210123456789
    c_es_comm, _ = pe.commit_from_digest(es_hash, blinding_factor=r_es)
    c_es_hex = c_es_comm.commitment_hex

    # Execute Step 3 with valid C_ES evidence
    res3 = ve.execute_step(3, overrides={
        "encoding_transform_required": True,
        "stored_c_es": c_es_hex,
        "r_es": hex(r_es)[2:],
    })
    assert res3.status == "MATCH"
    assert "Branch A" in res3.stage1_reconstruction["branch"]
    assert res3.stage2_verification["status"] == "MATCH"

    # Execute Step transform: derives E_U' and records hash
    res_trans = ve.execute_step("transform", overrides={
        "encoding_transform_required": True,
    })
    assert res_trans.status == "MATCH"
    assert res_trans.stage1_reconstruction["value_identifier"] == "E_U'"
    eu_hash = res_trans.stage1_reconstruction["canonical_hash"]
    assert len(eu_hash) == 64

    # Execute Step 4: verifies C_D
    res4 = ve.execute_step(4, overrides={
        "encoding_transform_required": True,
    })
    assert res4.status == "MATCH"
    assert res4.stage1_reconstruction["canonical_hash"] == eu_hash


def test_branch_a_failed_c_es_blocks_transformation():
    """
    In Branch A, a failed or mismatched C_ES must block the transformation
    and block downstream Step 4 verification.
    """
    setup_transaction_base(encoding_transform_required=True)
    ve = VerifierEngine.get_instance()
    pe = PedersenEngine()

    ve.execute_step(1)
    res2 = ve.execute_step(2)
    es_hash = res2.stage1_reconstruction["canonical_hash"]

    # Intentionally corrupt the C_ES commitment
    r_es = 9876543210123456789
    c_es_comm, _ = pe.commit_from_digest(es_hash, blinding_factor=r_es)
    wrong_c_es = c_es_comm.commitment_hex.replace("02", "03", 1)

    res3 = ve.execute_step(3, overrides={
        "encoding_transform_required": True,
        "stored_c_es": wrong_c_es,
        "r_es": hex(r_es)[2:],
    })
    assert res3.status == "MISMATCH"

    # Attempting transformation when Step 3 failed must be BLOCKED
    res_trans = ve.execute_step("transform", overrides={"encoding_transform_required": True})
    assert res_trans.status == "BLOCKED"

    # Step 4 must also be BLOCKED
    res4 = ve.execute_step(4, overrides={"encoding_transform_required": True})
    assert res4.status == "BLOCKED"


def test_missing_or_invalid_flag_raises_explicit_error():
    """
    If the encoding_transform_required flag is missing or invalid,
    the verifier engine must raise an explicit ValueError without silent defaults.
    """
    setup_transaction_base(encoding_transform_required=False)
    ve = VerifierEngine.get_instance()
    tm = TransactionManager.get_instance()
    st = tm.get_state()

    ve.execute_step(1)
    ve.execute_step(2)

    # Invalidate flag in state and overrides
    st.encoding_transform_required = None
    with pytest.raises(ValueError, match="Missing or invalid transaction"):
        ve.execute_step(3, overrides={"encoding_transform_required": None})


# ==============================================================================
# Priority 2: UI Cleanliness (No Premature Bit Lengths or Success Badges)
# ==============================================================================

def test_initial_html_cleanliness():
    """
    Verify that index.html contains no premature bit lengths or success badges in pending verifier cards.
    """
    with open("hardware_ip_protection/web/static/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    # Extract Verifier profile section
    v_start = html.find('id="profileVerifier"')
    v_end = html.find('id="tabDispute"')
    assert v_start != -1 and v_end != -1
    v_html = html[v_start:v_end]

    # Must NOT contain light-blue result/information badges beside status badges
    assert 'class="v-step-summary"' not in v_html
    assert 'id="vStepSummary_' not in v_html
    assert "4-Rule Structural Encoding · 143 bits" not in v_html
    assert "E_S = D (Invariant)" not in v_html
    assert "C_D Verified (P-256)" not in v_html
    assert "RTL Binding Extraction · 32 bits" not in v_html
    assert "W = W1' || W2 · 256 bits" not in v_html

    # Ensure JavaScript does not contain logic to recreate or repopulate vStepSummary
    with open("hardware_ip_protection/web/static/app.js", "r", encoding="utf-8") as f_js:
        app_js = f_js.read()
    assert "vStepSummary" not in app_js

    # Must NOT contain hardcoded bit length summaries in pending headers
    assert "· 143 bits" not in v_html
    assert "· 32 bits" not in v_html
    assert "· 256 bits" not in v_html
    assert "· 555 bits" not in v_html

    assert 'id="vStepBadge_1">READY TO EXECUTE<' in v_html
    for step_id in ["2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13"]:
        assert f'id="vStepBadge_{step_id}">Pending<' in v_html

    # Must NOT contain premature success claims on step badges before execution
    for bad_badge in [">Verified<", ">MATCH<", ">EXTRACTED<", ">VALIDATED<"]:
        for step_id in ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13"]:
            assert f'id="vStepBadge_{step_id}"{bad_badge}' not in v_html

    # Ensure verifier container exists
    assert 'id="profileVerifier"' in v_html


# ==============================================================================
# Priority 3: Hashes Instead of Raw Confidential Values & Hash-First Order
# ==============================================================================

def test_payloads_contain_hashes_not_raw_confidential_values():
    """
    Verify that ordinary API step responses expose canonical SHA-256 hashes,
    and do NOT expose raw confidential bitstreams (E_S', E_U', W1', W', B').
    """
    setup_transaction_base(encoding_transform_required=False)

    # Step 1: RTL
    res1 = client.post("/api/verifier/execute_step", json={"step_number": 1}).json()
    assert res1["step_result"]["status"] == "LOADED"

    # Step 2: E_S'
    res2 = client.post("/api/verifier/execute_step", json={"step_number": 2}).json()
    st2 = res2["step_result"]["stage1_reconstruction"]
    assert "canonical_hash" in st2 and len(st2["canonical_hash"]) == 64
    assert "extracted_bitstream" not in st2
    assert "secured_encoding_ES" not in st2

    # Step 3 & 4
    client.post("/api/verifier/execute_step", json={"step_number": 3})
    client.post("/api/verifier/execute_step", json={"step_number": 4})

    # Step 5: W1'
    res5 = client.post("/api/verifier/execute_step", json={"step_number": 5}).json()
    st5 = res5["step_result"]["stage1_reconstruction"]
    assert "canonical_hash" in st5 and len(st5["canonical_hash"]) == 64
    assert "extracted_bitstream_W1" not in st5

    # Step 7: W'
    res7 = client.post("/api/verifier/execute_step", json={"step_number": 7}).json()
    st7 = res7["step_result"]["stage1_reconstruction"]
    assert "canonical_hash" in st7 and len(st7["canonical_hash"]) == 64
    assert "reconstructed_watermark_W" not in st7

    # Step 9: B'
    res9 = client.post("/api/verifier/execute_step", json={"step_number": 9}).json()
    st9 = res9["step_result"]["stage1_reconstruction"]
    assert "canonical_hash" in st9 and len(st9["canonical_hash"]) == 64
    assert "bitstream_B" not in st9

    # Step 11: Watermark Derivation
    # First execute steps 6, 8, 10 to satisfy prerequisites
    for s in [6, 8, 10]:
        client.post("/api/verifier/execute_step", json={"step_number": s})

    res11 = client.post("/api/verifier/execute_step", json={"step_number": 11}).json()
    st11 = res11["step_result"]["stage1_reconstruction"]
    assert "expected_watermark_hash" in st11 and len(st11["expected_watermark_hash"]) == 64
    assert "reconstructed_watermark_hash" in st11 and len(st11["reconstructed_watermark_hash"]) == 64
    assert "expected_watermark_W" not in st11
    assert "reconstructed_watermark_W" not in st11


def test_hash_first_opening_order_and_anti_replacement():
    """
    Enforce hash-first opening order:
    1. Opening release fails if canonical hash is not recorded first.
    2. Once opening is released, recorded hash cannot be replaced with a different hash.
    """
    import uuid
    repo = ProtectionRepository.get_instance()
    sess_id = f"VSESS-TEST-{uuid.uuid4().hex[:8]}"
    tx_id = "TX-TEST-001"
    step_id = "step_test_hash"

    test_hash = hashlib.sha256(b"canonical_value_sample").hexdigest()
    corrupted_hash = hashlib.sha256(b"altered_tampered_value").hexdigest()

    # 1. Opening release fails before hash is recorded
    with pytest.raises(ValueError, match="cannot be released before its canonical hash is recorded"):
        repo.release_step_opening(sess_id, step_id, attempt_id=1)

    # 2. Record canonical hash
    rec = repo.record_step_hash(sess_id, tx_id, step_id, test_hash, attempt_id=1)
    assert rec["canonical_hash"] == test_hash
    assert rec["opening_released"] is False

    # 3. Release opening
    released = repo.release_step_opening(sess_id, step_id, attempt_id=1)
    assert released is True

    # 4. Attempt to replace recorded hash with a different hash fails
    with pytest.raises(ValueError, match="Security violation: Cannot replace recorded hash"):
        repo.record_step_hash(sess_id, tx_id, step_id, corrupted_hash, attempt_id=1)


# ==============================================================================
# Regression Test: Verifier Hash API Contract & Active Frontend Rendering
# ==============================================================================

def run_frontend_populate(step_num, result_payload, initial_elements=None):
    """
    Executes populateStepResultFields(stepNum, result_payload) directly from app.js
    in Node.js against a DOM mock, validating the active frontend rendering contract.
    """
    initial_elements = initial_elements or {}
    js_script = f"""
    const fs = require('fs');
    const elements = {json.dumps(initial_elements)};
    global.document = {{
        addEventListener: () => {{}},
        getElementById: (id) => {{
            if (!elements[id]) {{
                elements[id] = {{ textContent: '--', style: {{}}, classList: {{ add: ()=>{{}}, remove: ()=>{{}} }} }};
            }}
            return elements[id];
        }},
        querySelectorAll: () => []
    }};
    global.window = global;
    const code = fs.readFileSync('hardware_ip_protection/web/static/app.js', 'utf8');
    eval(code);

    const payload = {json.dumps(result_payload)};
    populateStepResultFields({json.dumps(step_num)}, payload);

    const output = {{}};
    for (const [k, v] of Object.entries(elements)) {{
        output[k] = v.textContent;
    }}
    console.log(JSON.stringify(output));
    """
    proc = subprocess.run(
        ["node", "-e", js_script],
        cwd=".",
        capture_output=True,
        text=True,
        check=True
    )
    return json.loads(proc.stdout)


def test_regression_verifier_hash_calculation_contract_and_frontend_mapping():
    """
    Regression Test for Verifier Hash Dataflow & Rendering:
    1. Executes the actual secured-encoding calculation (Step 2).
    2. Checks the actual returned API JSON schema & fields.
    3. Independently calculates the expected canonical SHA-256 digest in the test.
    4. Asserts that the returned digest matches the expected digest.
    5. Asserts that the frontend rendering function maps the actual response field to the correct HTML element.
    6. Asserts that the default result is not permanently '--' after a successful calculation.
    7. Asserts that the raw confidential bitstream is absent from the ordinary API response.
    8. Provides equivalent validation for W1' (Step 5), W' (Step 7), and B' (Step 9).
    """
    st = setup_transaction_base(encoding_transform_required=False)

    # Load Step 1
    res1 = client.post("/api/verifier/execute_step", json={"step_number": 1})
    assert res1.status_code == 200

    # --------------------------------------------------------------------------
    # Step 2: Calculate Secured Design Encoding (E_S')
    # --------------------------------------------------------------------------
    res2_resp = client.post("/api/verifier/execute_step", json={"step_number": 2})
    assert res2_resp.status_code == 200
    res2 = res2_resp.json()

    # 3. Independently calculate expected canonical digest in the test
    parsed = DesignStructuralEncoder.parse_scheduled_nodes_from_verilog(st.watermarked_RTL)
    reconstructed_nodes = [
        DFGNode(nid, parsed["node_ops"][nid], [], f"t{nid}")
        for nid in sorted(parsed["node_step"].keys())
    ]
    reconstructed_dfg = DFG(name="reconstructed_design", inputs=[], outputs=[], nodes=reconstructed_nodes)
    canon_step_nodes = {}
    for s, nids in parsed["step_nodes"].items():
        canon_step_nodes[s] = sorted(
            nids, key=lambda nid: (0 if parsed["node_ops"][nid] in ("add", "sub") else 1, nid)
        )
    reconstructed_sched = ScheduledDFG(
        dfg=reconstructed_dfg,
        node_step=parsed["node_step"],
        total_steps=parsed["total_steps"],
        resource_config={"mul": 2, "add": 1},
    )
    reconstructed_sched.step_nodes = canon_step_nodes
    enc_res = DesignStructuralEncoder.encode_scheduled_dfg(
        reconstructed_sched,
        rule4_width=2,
        use_document_table_quirks=False,
        allow_sub_as_adder=True,
    )
    expected_es_bitstream = enc_res.canonical_bitstream
    expected_es_hash = hashlib.sha256(expected_es_bitstream.encode("utf-8")).hexdigest()

    # 4. Asserts returned digest matches expected digest across API contract levels
    assert res2["canonical_hash"] == expected_es_hash
    assert res2["step_result"]["canonical_hash"] == expected_es_hash
    assert res2["step_result"]["stage1_reconstruction"]["canonical_hash"] == expected_es_hash
    assert res2["bit_length"] == len(expected_es_bitstream)
    assert res2["hash_algorithm"] == "SHA-256"

    # 5. Asserts frontend rendering maps actual response to the correct HTML element
    # Test both string '2' and int 2 (preventing type coercion bug)
    for step_arg in ["2", 2]:
        dom_result = run_frontend_populate(step_arg, res2["step_result"])
        # 6. Asserts default result is not permanently '--' after successful calculation
        assert dom_result["vStepHash_2"] != "--"
        assert dom_result["vStepHash_2"] == expected_es_hash
        assert dom_result["vStepBitLen_2"] == f"{len(expected_es_bitstream)} bits"
        assert dom_result["vStepHashAlgo_2"] == "SHA-256"

    # Test that full response object (unwrapped) also populates correctly
    dom_from_full_res = run_frontend_populate("2", res2)
    assert dom_from_full_res["vStepHash_2"] == expected_es_hash

    # 7. Asserts raw confidential bitstream is absent from ordinary API response
    assert expected_es_bitstream not in res2_resp.text
    assert "internal_confidential_values" not in res2_resp.text
    assert "es_bitstream" not in res2_resp.text

    # --------------------------------------------------------------------------
    # Step 5: Extract Embedded Watermark (W1')
    # --------------------------------------------------------------------------
    res5_resp = client.post("/api/verifier/execute_step", json={"step_number": 5})
    assert res5_resp.status_code == 200
    res5 = res5_resp.json()

    # Independent calculation of W1'
    mapping = st.pipeline_result["watermark_mapping"]
    extract_res = TransactionWatermarkExtractor.extract(
        st.watermarked_RTL, watermark_mapping=mapping, expected_length=len(mapping)
    )
    expected_w1_bitstream = extract_res.bitstream
    expected_w1_hash = hashlib.sha256(expected_w1_bitstream.encode("utf-8")).hexdigest()

    assert res5["canonical_hash"] == expected_w1_hash
    assert res5["step_result"]["canonical_hash"] == expected_w1_hash
    assert res5["step_result"]["stage1_reconstruction"]["canonical_hash"] == expected_w1_hash
    assert res5["bit_length"] == len(expected_w1_bitstream)

    for step_arg in ["5", 5]:
        dom5 = run_frontend_populate(step_arg, res5["step_result"])
        assert dom5["vStepHash_5"] != "--"
        assert dom5["vStepHash_5"] == expected_w1_hash
        assert dom5["vStepBitLen_5"] == f"{len(expected_w1_bitstream)} bits"

    assert expected_w1_bitstream not in res5_resp.text
    assert "internal_confidential_values" not in res5_resp.text

    # --------------------------------------------------------------------------
    # --------------------------------------------------------------------------
    # Step 7: Reconstruct Complete Watermark (W')
    # --------------------------------------------------------------------------
    res7_resp = client.post("/api/verifier/execute_step", json={"step_number": 7})
    assert res7_resp.status_code == 200
    res7 = res7_resp.json()

    if getattr(st, "is_full_watermark", True):
        # In the full-watermark model, all 256 bits of W' are extracted in Step 5 and verified in Step 6
        assert res7["step_result"]["status"] == "NOT REQUIRED"
        assert res7["canonical_hash"] == expected_w1_hash
        assert res7["bit_length"] == len(expected_w1_bitstream)
    else:
        # Legacy split transaction
        expected_w_bitstream = expected_w1_bitstream + (st.protected_W2 or "")
        expected_w_hash = hashlib.sha256(expected_w_bitstream.encode("utf-8")).hexdigest()
        assert res7["canonical_hash"] == expected_w_hash
        assert res7["step_result"]["canonical_hash"] == expected_w_hash
        assert res7["bit_length"] == len(expected_w_bitstream)

    for step_arg in ["7", 7]:
        dom7 = run_frontend_populate(step_arg, res7["step_result"])
        assert dom7["vStepHash_7"] != "--"
        assert dom7["vStepHash_7"] == expected_w1_hash
        assert dom7["vStepBitLen_7"] == f"{len(expected_w1_bitstream)} bits"

    assert expected_w1_bitstream not in res7_resp.text
    assert "internal_confidential_values" not in res7_resp.text

    # --------------------------------------------------------------------------
    # Step 9: Reconstruct Buyer Contribution (B')
    # --------------------------------------------------------------------------
    res9_resp = client.post("/api/verifier/execute_step", json={"step_number": 9})
    assert res9_resp.status_code == 200
    res9 = res9_resp.json()

    expected_b_bitstream = st.buyer_bitstream_B or DEMO_BUYER_BITSTREAM
    expected_b_hash = hashlib.sha256(expected_b_bitstream.encode("utf-8")).hexdigest()

    assert res9["canonical_hash"] == expected_b_hash
    assert res9["step_result"]["canonical_hash"] == expected_b_hash
    assert res9["bit_length"] == len(expected_b_bitstream)

    for step_arg in ["9", 9]:
        dom9 = run_frontend_populate(step_arg, res9["step_result"])
        assert dom9["vStepHash_9"] != "--"
        assert dom9["vStepHash_9"] == expected_b_hash
        assert dom9["vStepBitLen_9"] == f"{len(expected_b_bitstream)} bits"

    assert expected_b_bitstream not in res9_resp.text
    assert "internal_confidential_values" not in res9_resp.text


# ==============================================================================
# Full 256-Bit Watermark Embedding & Verifier Workflow Tests
# ==============================================================================

def test_full_256bit_watermark_end_to_end_verification():
    """
    Validates that:
    1. A 256-bit watermark W is generated, committed as C_W, and fully embedded into RTL.
    2. Verifier Step 5 extracts all 256 bits directly from synthesized RTL register bindings.
    3. Verifier Step 6 verifies C_W commitment directly against extracted 256-bit W'.
    4. Steps 7 & 8 return NOT REQUIRED in the full watermark model.
    5. Step 11 evaluates HKDF relationship over all 256 bits and returns MATCH.
    6. Step 13 reports consistent dispute determination.
    """
    st = setup_transaction_base(encoding_transform_required=False)
    assert st.is_full_watermark is True
    assert st.embedded_watermark_length == 256
    assert len(st.watermark_W) == 256
    assert st.protected_W2 is None

    ve = VerifierEngine.get_instance()

    # Step 1: Disputed RTL
    r1 = ve.execute_step(1)
    assert r1.status == "LOADED"

    # Step 2: E_S'
    r2 = ve.execute_step(2)
    assert r2.status == "EXTRACTED"

    # Step 3 & 4
    r3 = ve.execute_step(3)
    assert r3.status == "NOT REQUIRED"
    r4 = ve.execute_step(4)
    assert r4.status == "MATCH"

    # Step 5: Extract Complete Watermark W' (256 bits)
    r5 = ve.execute_step(5)
    assert r5.status == "EXTRACTED"
    assert r5.bit_length == 256
    extracted_w = ve.session.internal_confidential_values.get("W")
    assert extracted_w == st.watermark_W
    assert len(extracted_w) == 256

    # Step 6: Verify Complete Watermark Commitment C_W directly
    r6 = ve.execute_step(6)
    assert r6.status == "MATCH"
    assert r6.stage2_verification["status"] == "MATCH"

    # Steps 7 & 8: Marked NOT REQUIRED
    r7 = ve.execute_step(7)
    assert r7.status == "NOT REQUIRED"
    r8 = ve.execute_step(8)
    assert r8.status == "NOT REQUIRED"

    # Step 9 & 10: Buyer Contribution
    r9 = ve.execute_step(9)
    assert r9.status in ("MATCH", "VALIDATED")
    r10 = ve.execute_step(10)
    assert r10.status == "MATCH"

    # Step 11: Evaluate HKDF Relationship at full 256 bits
    r11 = ve.execute_step(11)
    assert r11.status == "MATCH"
    assert r11.bit_length == 256

    # Step 12: Buyer Signature
    r12 = ve.execute_step(12)
    assert r12.status == "MATCH"

    # Step 13: Final Report
    r13 = ve.execute_step(13)
    assert r13.status == "CONSISTENT"
    assert r13.stage2_verification["dispute_determination"] == "CONSISTENT"


def test_structural_rtl_extraction_without_comments():
    """
    Validates that watermark extraction is strictly structural:
    - Stripping all comments (// ...) from RTL does NOT impede extraction of all 256 bits.
    - 100% of bits are recovered and match the golden watermark.
    """
    import re
    st = setup_transaction_base(encoding_transform_required=False)
    assert st.watermarked_RTL is not None

    # Strip all comments from RTL
    commentless_rtl = re.sub(r'//.*', '', st.watermarked_RTL)
    assert "//" not in commentless_rtl

    # Extract watermark directly from commentless RTL
    extract_res = TransactionWatermarkExtractor.extract(
        commentless_rtl,
        watermark_mapping=st.watermark_mapping,
        expected_length=256
    )
    assert extract_res.recovered_bits == 256
    assert extract_res.unrecovered_bits == 0
    assert extract_res.bitstream == st.watermark_W


def test_forged_comments_cannot_forge_watermark():
    """
    Validates that attacker cannot forge watermark by injecting forged comments into RTL:
    - Register bindings are derived from synthesizable Verilog statements, not comments.
    - Tampering with register bindings breaks C_W verification.
    """
    st = setup_transaction_base(encoding_transform_required=False)

    # Inject forged comments claiming different bits
    forged_comment_rtl = "// WATERMARK BIT 0: VAR v0 v1 REGS R0 R1 VALUE 1\n" + st.watermarked_RTL

    extract_res = TransactionWatermarkExtractor.extract(
        forged_comment_rtl,
        watermark_mapping=st.watermark_mapping,
        expected_length=256
    )
    # Bitstream remains the genuine structural bitstream
    assert extract_res.bitstream == st.watermark_W


def test_rtl_tampering_breaks_commitment_verification():
    """
    Validates that if an attacker modifies synthesizable register bindings in RTL,
    the extracted watermark W' changes, causing Step 6 C_W verification to FAIL with MISMATCH.
    """
    st = setup_transaction_base(encoding_transform_required=False)

    # Tamper with RTL synthesizable register assignment: replace R3 with R15
    tampered_rtl = st.watermarked_RTL.replace("R3", "R15")
    assert tampered_rtl != st.watermarked_RTL

    ve = VerifierEngine.get_instance()
    ve.execute_step(1, overrides={"disputed_rtl": tampered_rtl})
    r5 = ve.execute_step(5, overrides={"disputed_rtl": tampered_rtl})
    assert r5.status == "EXTRACTED"
    # Extracted bitstream has altered bits
    extracted_w = ve.session.internal_confidential_values.get("W")
    assert extracted_w != st.watermark_W

    # Step 6 C_W verification MUST fail with MISMATCH
    r6 = ve.execute_step(6)
    assert r6.status == "MISMATCH"


def test_legacy_split_watermark_backward_compatibility():
    """
    Validates backward compatibility for legacy transactions that used W1 (32 bits) + W2 (224 bits):
    - is_full_watermark = False
    - Step 5 extracts 32-bit W1'
    - Step 6 verifies C_W1
    - Step 7 reconstructs W' = W1' || W2
    - Step 8 verifies C_W
    - Downstream steps continue normally
    """
    st = setup_transaction_base(encoding_transform_required=False)

    # Simulate legacy split configuration
    st.is_full_watermark = False
    full_w = st.watermark_W
    st.W1 = full_w[:32]
    st.protected_W2 = full_w[32:]
    st.embedded_watermark_length = 32

    pe = PedersenEngine()
    w1_hash = hashlib.sha256(st.W1.encode("utf-8")).hexdigest()
    r_w1 = 12345678901234567890
    c_w1_obj, _ = pe.commit_from_digest(w1_hash, blinding_factor=r_w1)
    st.C_W1 = c_w1_obj.commitment_hex
    st.blinding_factor_W1 = hex(r_w1)[2:]

    # Legacy mapping of first 32 bits
    legacy_mapping = st.watermark_mapping[:32]
    st.watermark_mapping = legacy_mapping

    ve = VerifierEngine.get_instance()
    ve.execute_step(1)
    ve.execute_step(2)
    ve.execute_step(3)
    ve.execute_step(4)

    # Step 5: Extracts 32-bit W1'
    r5 = ve.execute_step(5)
    assert r5.status == "EXTRACTED"
    assert r5.bit_length == 32
    assert ve.session.internal_confidential_values.get("W1") == st.W1

    # Step 6: Verifies C_W1
    r6 = ve.execute_step(6)
    assert r6.status == "MATCH"

    # Step 7: Reconstructs W' = W1' || W2
    r7 = ve.execute_step(7)
    assert r7.status == "MATCH"
    assert r7.bit_length == 256
    assert ve.session.internal_confidential_values.get("W") == full_w

    # Step 8: Verifies C_W
    r8 = ve.execute_step(8)
    assert r8.status == "MATCH"


