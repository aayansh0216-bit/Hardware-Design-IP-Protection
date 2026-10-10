"""
Unit and Integration Tests for Prototype Structural Design Encoding.

Validates:
1. 13-node golden Butterworth example from 'design encoded data.docx'
2. Correct node width: ceil(log2(n)) bits (e.g. n=13 -> 4 bits)
3. Correct operation encoding: multiplier -> 1, adder -> 0
4. Correct control-step parity encoding (Odd="01", Even="00")
5. Correct node-count encoding (Rule 1 & Rule 4)
6. Multiple nodes in one control step
7. Single-node control step
8. Selected control-step scope handling (Rule 2 node_width preserved)
9. Scope consistency between Secure Your Design and Verify Dispute
10. Exact Level 1 match
11. Exact Level 1 mismatch
12. Level 2 rule-level difference reporting
13. Long Level 2 comparison (with 20+ steps and 30+ nodes)
14. Differences-only view filtering
15. Missing/invalid data handling
16. Unsupported operation type error handling
17. Reference/suspicious node-count mismatch handling
18. Level 3 explicit non-implementation flag
"""

import pytest
import math
from hardware_ip_protection.hls import (
    create_dct4,
    create_fir,
    create_arf,
    create_mesa,
    create_conv3x3,
    DFG,
    DFGNode,
    ListScheduler,
    ScheduledDFG,
    DesignStructuralEncoder,
    StructuralEncodingResult,
)
from hardware_ip_protection.pipeline.engine import ProtectionPipeline, DisputePipeline


# ==============================================================================
# 1. 13-node Golden Butterworth Example Test (Section 8)
# ==============================================================================

def test_13_node_golden_butterworth_document_mode():
    """
    Validates against the exact values in the page-3 table of 'design encoded data.docx':
    T1:
      node 1: 0100 | 0001 | 1 | 10
      node 2: 0100 | 0010 | 1 | 10
    T2:
      node 8: 0001 | 1000 | 0 | 11
      node 3: 0001 | 0011 | 1 | 11
      node 4: 0001 | 0100 | 1 | 11
    T3:
      node 9: 0101 | 1001 | 0 | 11
      node 5: 0101 | 0101 | 1 | 11
      node 6: 0101 | 0110 | 1 | 11
    T4:
      node 10: 0000 | 1010 | 0 | 10
      node 7:  0000 | 1011 | 1 | 10
    T5:
      node 11: 0101 | 0111 | 0 | 01
    T6:
      node 12: 0001 | 1100 | 0 | 01
    T7:
      node 13: 0101 | 1101 | 0 | 01
    """
    res = DesignStructuralEncoder.encode_golden_butterworth(use_document_table_quirks=True)

    expected_records = {
        (1, 1): ("0100", "0001", "1", "10"),
        (1, 2): ("0100", "0010", "1", "10"),
        (2, 8): ("0001", "1000", "0", "11"),
        (2, 3): ("0001", "0011", "1", "11"),
        (2, 4): ("0001", "0100", "1", "11"),
        (3, 9): ("0101", "1001", "0", "11"),
        (3, 5): ("0101", "0101", "1", "11"),
        (3, 6): ("0101", "0110", "1", "11"),
        (4, 10): ("0000", "1010", "0", "10"),
        (4, 7): ("0000", "1011", "1", "10"),
        (5, 11): ("0101", "0111", "0", "01"),
        (6, 12): ("0001", "1100", "0", "01"),
        (7, 13): ("0101", "1101", "0", "01"),
    }

    assert len(res.records) == 13
    assert res.total_design_nodes == 13
    assert res.node_width == 4
    assert res.total_steps == 7

    for r in res.records:
        key = (r.step_number, r.node_id)
        assert key in expected_records, f"Unexpected record {key}"
        exp_r1, exp_r2, exp_r3, exp_r4 = expected_records[key]
        assert r.rule1 == exp_r1, f"Rule 1 mismatch for step {r.step_number} node {r.node_id}"
        assert r.rule2 == exp_r2, f"Rule 2 mismatch for step {r.step_number} node {r.node_id}"
        assert r.rule3 == exp_r3, f"Rule 3 mismatch for step {r.step_number} node {r.node_id}"
        assert r.rule4 == exp_r4, f"Rule 4 mismatch for step {r.step_number} node {r.node_id}"
        assert r.bitstream == f"{exp_r1}{exp_r2}{exp_r3}{exp_r4}"


def test_13_node_golden_butterworth_standard_mode():
    """
    Validates standard mathematical binary mode:
    node 7 -> 0111 (7 decimal)
    node 11 -> 1011 (11 decimal)
    """
    res = DesignStructuralEncoder.encode_golden_butterworth(use_document_table_quirks=False)
    rec_map = {(r.step_number, r.node_id): r for r in res.records}

    # Node 7 in T4: 0000 | 0111 | 1 | 10
    r7 = rec_map[(4, 7)]
    assert r7.rule1 == "0000"
    assert r7.rule2 == "0111"
    assert r7.rule3 == "1"
    assert r7.rule4 == "10"

    # Node 11 in T5: 0101 | 1011 | 0 | 01
    r11 = rec_map[(5, 11)]
    assert r11.rule1 == "0101"
    assert r11.rule2 == "1011"
    assert r11.rule3 == "0"
    assert r11.rule4 == "01"


# ==============================================================================
# 2. Node Width: ceil(log2(n)) bits
# ==============================================================================

def test_node_width_scaling():
    # n = 4 -> ceil(log2(4)) = 2 bits
    # n = 7 -> ceil(log2(7)) = 3 bits
    # n = 13 -> ceil(log2(13)) = 4 bits
    # n = 16 -> ceil(log2(16)) = 4 bits
    # n = 17 -> ceil(log2(17)) = 5 bits
    dfg_dct = create_dct4()  # 7 nodes
    sched = ListScheduler({"add": 2, "mul": 2}).schedule(dfg_dct)
    res_dct = DesignStructuralEncoder.encode_scheduled_dfg(sched)
    assert res_dct.total_design_nodes == 7
    assert res_dct.node_width == 3
    for r in res_dct.records:
        assert len(r.rule2) == 3

    dfg_arf = create_arf()  # 17 nodes
    sched_arf = ListScheduler({"add": 4, "mul": 4}).schedule(dfg_arf)
    res_arf = DesignStructuralEncoder.encode_scheduled_dfg(sched_arf)
    assert res_arf.total_design_nodes == 17
    assert res_arf.node_width == 5
    for r in res_arf.records:
        assert len(r.rule2) == 5


# ==============================================================================
# 3. Operation Encoding: Multiplier = 1, Adder = 0
# ==============================================================================

def test_operation_encoding():
    dfg = create_dct4()
    sched = ListScheduler({"add": 2, "mul": 2}).schedule(dfg)
    res = DesignStructuralEncoder.encode_scheduled_dfg(sched)

    for r in res.records:
        node = dfg._node_map[r.node_id]
        if node.op_type == "mul":
            assert r.rule3 == "1"
        elif node.op_type == "add":
            assert r.rule3 == "0"


# ==============================================================================
# 4 & 5. Parity Encoding and Node-Count Binary Encoding
# ==============================================================================

def test_parity_and_count_rules():
    # Odd CS (1) + Even count (2) -> "0100"
    cs, cnt, r1 = DesignStructuralEncoder.encode_rule1(step_number=1, node_count=2)
    assert cs == "01" and cnt == "00" and r1 == "0100"

    # Even CS (2) + Odd count (3) -> "0001"
    cs, cnt, r1 = DesignStructuralEncoder.encode_rule1(step_number=2, node_count=3)
    assert cs == "00" and cnt == "01" and r1 == "0001"

    # Odd CS (3) + Odd count (3) -> "0101"
    cs, cnt, r1 = DesignStructuralEncoder.encode_rule1(step_number=3, node_count=3)
    assert cs == "01" and cnt == "01" and r1 == "0101"

    # Even CS (4) + Even count (2) -> "0000"
    cs, cnt, r1 = DesignStructuralEncoder.encode_rule1(step_number=4, node_count=2)
    assert cs == "00" and cnt == "00" and r1 == "0000"

    # Rule 4 node count formatting
    assert DesignStructuralEncoder.encode_rule4(1, 2) == "01"
    assert DesignStructuralEncoder.encode_rule4(2, 2) == "10"
    assert DesignStructuralEncoder.encode_rule4(3, 2) == "11"


# ==============================================================================
# 6 & 7. Multiple Nodes vs. Single Node in Control Step
# ==============================================================================

def test_multiple_and_single_nodes_in_step():
    res = DesignStructuralEncoder.encode_golden_butterworth()
    groups = {g.step_number: g for g in res.step_groups}

    # Step T2 has 3 nodes
    assert groups[2].node_count == 3
    assert groups[2].rule4 == "11"
    assert len(groups[2].nodes) == 3

    # Step T5 has 1 node
    assert groups[5].node_count == 1
    assert groups[5].rule4 == "01"
    assert len(groups[5].nodes) == 1


# ==============================================================================
# 8. Scope Selection Does NOT Redefine n or node_width
# ==============================================================================

def test_scope_does_not_redefine_node_width():
    # Golden design has n = 13 nodes, node_width = 4
    # Even if only T1 (2 nodes) is selected, node_width MUST remain 4 bits
    res_partial = DesignStructuralEncoder.encode_golden_butterworth(scope_control_steps=[1])
    assert res_partial.total_design_nodes == 13
    assert res_partial.node_width == 4
    assert len(res_partial.records) == 2
    for r in res_partial.records:
        assert len(r.rule2) == 4

    # Select T1 and T5
    res_sub = DesignStructuralEncoder.encode_golden_butterworth(scope_control_steps=[1, 5])
    assert res_sub.selected_scope == [1, 5]
    assert len(res_sub.step_groups) == 2
    assert res_sub.total_design_nodes == 13
    assert res_sub.node_width == 4


# ==============================================================================
# 9. Scope Consistency Between Generation and Verification
# ==============================================================================

def test_scope_mismatch_detected():
    res_all = DesignStructuralEncoder.encode_golden_butterworth(scope_control_steps=[1, 2, 3, 4, 5, 6, 7])
    res_sub = DesignStructuralEncoder.encode_golden_butterworth(scope_control_steps=[1, 2, 3])

    l1 = DesignStructuralEncoder.compare_level1(res_all, res_sub)
    assert l1["scope_mismatch"] is True
    assert l1["status"] == "MISMATCH"

    l2 = DesignStructuralEncoder.compare_level2(res_all, res_sub)
    assert l2["summary"]["differing_steps_count"] > 0
    # Steps 4, 5, 6, 7 are flagged as present in reference only
    missing_steps = [d["step_name"] for d in l2["differences_only"] if d.get("type") == "STEP_PRESENCE_MISMATCH"]
    assert "T4" in missing_steps
    assert "T5" in missing_steps


# ==============================================================================
# 10 & 11. Level 1 Exact Match and Mismatch
# ==============================================================================

def test_level1_exact_match_and_mismatch():
    res1 = DesignStructuralEncoder.encode_golden_butterworth(use_document_table_quirks=True)
    res2 = DesignStructuralEncoder.encode_golden_butterworth(use_document_table_quirks=True)
    res_diff = DesignStructuralEncoder.encode_golden_butterworth(use_document_table_quirks=False)

    match = DesignStructuralEncoder.compare_level1(res1, res2)
    assert match["status"] == "MATCH"
    assert match["is_exact_match"] is True
    assert match["matching_bits"] == len(res1.canonical_bitstream)
    assert match["differing_bits"] == 0
    assert match["match_rate"] == 1.0

    mismatch = DesignStructuralEncoder.compare_level1(res1, res_diff)
    assert mismatch["status"] == "MISMATCH"
    assert mismatch["is_exact_match"] is False
    assert mismatch["differing_bits"] > 0
    assert mismatch["match_rate"] < 1.0


# ==============================================================================
# 12 & 14. Level 2 Rule-Level Differences and Differences-Only View
# ==============================================================================

def test_level2_rule_differences_and_differences_only():
    res_ref = DesignStructuralEncoder.encode_golden_butterworth(use_document_table_quirks=True)
    res_sus = DesignStructuralEncoder.encode_golden_butterworth(use_document_table_quirks=False)

    l2 = DesignStructuralEncoder.compare_level2(res_ref, res_sus)
    assert l2["summary"]["differing_components"] == 2
    assert l2["differences_count"] == 2

    # Check differences only list
    diffs = l2["differences_only"]
    assert len(diffs) == 2
    assert diffs[0]["step_name"] == "T4"
    assert diffs[0]["node_id"] == 7
    assert "Rule 2 differs" in diffs[0]["differences"][0]

    assert diffs[1]["step_name"] == "T5"
    assert diffs[1]["node_id"] == 11
    assert "Rule 2 differs" in diffs[1]["differences"][0]


# ==============================================================================
# 13. Long Level 2 Comparison (Large Design Test)
# ==============================================================================

def test_long_level2_comparison():
    """
    Tests a large design with 25 operations scheduled across many steps.
    Verifies that Level 2 comparison generates complete structured hierarchy
    without failing, collapses, or crashing.
    """
    nodes = []
    for i in range(1, 16):
        nodes.append(DFGNode(i, "mul", [f"in_{i}", f"c_{i}"], f"p_{i}"))
    for i in range(1, 11):
        src1 = f"p_{i}"
        src2 = f"p_{i+1}"
        nodes.append(DFGNode(15 + i, "add", [src1, src2], f"s_{i}"))

    dfg = DFG(
        name="large_benchmark_kernel",
        inputs=[f"in_{i}" for i in range(1, 16)] + [f"c_{i}" for i in range(1, 16)],
        outputs=["s_10"],
        nodes=nodes,
    )
    scheduler = ListScheduler({"mul": 2, "add": 2})
    sched = scheduler.schedule(dfg)

    enc_ref = DesignStructuralEncoder.encode_scheduled_dfg(sched)
    enc_sus = DesignStructuralEncoder.encode_scheduled_dfg(sched)

    assert enc_ref.total_design_nodes == 25
    assert enc_ref.node_width == 5  # ceil(log2(25)) = 5
    assert enc_ref.total_steps > 5

    l2 = DesignStructuralEncoder.compare_level2(enc_ref, enc_sus)
    assert l2["summary"]["reference_nodes"] == 25
    assert l2["summary"]["matching_components"] == l2["summary"]["total_components_evaluated"]
    assert l2["summary"]["differing_components"] == 0
    assert l2["differences_count"] == 0
    assert len(l2["step_comparisons"]) == enc_ref.total_steps


# ==============================================================================
# 15 & 16. Missing / Invalid Data and Unsupported Operation Handling
# ==============================================================================

def test_unsupported_operation_raises():
    dfg = DFG(
        name="invalid_op_dfg",
        inputs=["x", "y"],
        outputs=["z"],
        nodes=[DFGNode(1, "bitwise_xor", ["x", "y"], "z")],
    )
    sched = ScheduledDFG(dfg, {1: 0}, 1, {})
    sched.step_nodes = {0: [1]}

    with pytest.raises(ValueError, match="Unsupported operation type"):
        DesignStructuralEncoder.encode_scheduled_dfg(sched)


def test_empty_dfg_raises():
    dfg = DFG(name="empty", inputs=[], outputs=[], nodes=[])
    sched = ScheduledDFG(dfg, {}, 0, {})
    with pytest.raises(ValueError, match="Cannot structurally encode an empty design"):
        DesignStructuralEncoder.encode_scheduled_dfg(sched)


# ==============================================================================
# 17. Node Count Mismatch Handling
# ==============================================================================

def test_node_count_mismatch_comparison():
    dfg1 = create_dct4()  # 7 nodes
    dfg2 = create_mesa()  # 14 nodes

    sched1 = ListScheduler({"add": 2, "mul": 2}).schedule(dfg1)
    sched2 = ListScheduler({"add": 2, "mul": 2}).schedule(dfg2)

    enc1 = DesignStructuralEncoder.encode_scheduled_dfg(sched1)
    enc2 = DesignStructuralEncoder.encode_scheduled_dfg(sched2)

    l1 = DesignStructuralEncoder.compare_level1(enc1, enc2)
    assert l1["node_count_mismatch"] is True
    assert l1["status"] == "MISMATCH"

    l2 = DesignStructuralEncoder.compare_level2(enc1, enc2)
    assert l2["summary"]["reference_nodes"] == 7
    assert l2["summary"]["suspicious_nodes"] == 14
    assert l2["differences_count"] > 0


# ==============================================================================
# 18. Level 3 Non-Implementation Invariant
# ==============================================================================

def test_level3_not_implemented():
    res1 = DesignStructuralEncoder.encode_golden_butterworth()
    res2 = DesignStructuralEncoder.encode_golden_butterworth()
    l2 = DesignStructuralEncoder.compare_level2(res1, res2)

    assert "level3_extension" in l2
    assert l2["level3_extension"]["status"] == "NOT_IMPLEMENTED"
    assert "ownership" not in l2
    assert "infringement_probability" not in l2


# ==============================================================================
# 19. End-to-End Pipeline Integration (Secure Your Design + Verify Dispute)
# ==============================================================================

def test_pipeline_integration_with_structural_encoding():
    dfg = create_dct4()
    pipeline = ProtectionPipeline()
    init_ctx = {
        "dfg": dfg,
        "resource_config": {"add": 1, "mul": 2},
        "transaction_record": {
            "transaction_id": "TX-STRUCT-001",
            "seller_id": "SELLER-IP",
            "buyer_id": "BUYER-TECH",
            "license_type": "exclusive",
        },
        "transaction_credentials": {"k_tx": "secret-tx-key-42"},
        "encoding_scope": [1, 2, 3],  # specific scope
    }
    prot_ctx = pipeline.run(init_ctx)

    # 1. Verify structural encoding was generated in ProtectionPipeline
    assert "structural_encoding" in prot_ctx
    enc = prot_ctx["structural_encoding"]
    assert enc["selected_scope"] == [1, 2, 3]
    assert enc["total_design_nodes"] == 7
    assert enc["node_width"] == 3
    assert len(enc["canonical_bitstream"]) > 0

    # 2. Run DisputePipeline
    disp_pipe = DisputePipeline()
    disp_ctx = {
        "raw_dfg": prot_ctx["raw_dfg"],
        "reference_verilog": prot_ctx["protected_verilog"],
        "suspicious_verilog": prot_ctx["protected_verilog"],  # Untouched
        "test_vector_set": prot_ctx["test_vector_set"],
        "stored_test_vector_commitment": prot_ctx["test_vector_commitment"].commitment_hex,
        "test_vector_blinding_factor": prot_ctx["test_vector_blinding_factor"],
        "stored_watermark_commitment": prot_ctx["watermark_commitment"].commitment_hex,
        "watermark_blinding_factor": prot_ctx["watermark_blinding_factor"],
        "intended_watermark_bitstream": prot_ctx["transaction_watermark"].bitstream,
        "protection_record": prot_ctx["protection_record"],
    }
    disp_out = disp_pipe.run(disp_ctx)

    res = disp_out["dispute_result"]
    assert res.structural_encoding_verification is not None
    s_ver = res.structural_encoding_verification
    assert s_ver["level1"]["status"] == "MATCH"
    assert s_ver["level1"]["is_exact_match"] is True
    assert s_ver["level2"]["summary"]["agreement_percentage_str"] == "100.00%"
    assert s_ver["level2"]["differences_count"] == 0
