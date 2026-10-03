"""
Unit tests for HLS transformations: Scheduling, CIG mapping, and Register Allocation.
"""

import pytest
from hardware_ip_protection.hls import (
    create_dct4,
    create_fir,
    create_arf,
    create_mesa,
    create_conv3x3,
    ListScheduler,
    CIG,
    WatermarkCIGMapper,
    RegisterAllocator,
    RTLGenerator,
)


def test_benchmarks_creation():
    for factory in [create_dct4, create_fir, create_arf, create_mesa, create_conv3x3]:
        dfg = factory()
        assert len(dfg.nodes) > 0
        assert len(dfg.inputs) > 0
        assert len(dfg.outputs) > 0
        assert len(dfg.all_variables) > 0


def test_deterministic_scheduling():
    dfg = create_dct4()
    scheduler = ListScheduler({"add": 1, "mul": 2})
    sched1 = scheduler.schedule(dfg)
    sched2 = scheduler.schedule(dfg)

    assert sched1.total_steps == sched2.total_steps
    assert sched1.node_step == sched2.node_step
    assert sched1.variable_lifetimes == sched2.variable_lifetimes


def test_cig_invariant():
    dfg = create_dct4()
    sched = ListScheduler({"add": 1, "mul": 2}).schedule(dfg)
    base_cig = CIG(sched)

    # In unconstrained CIG, all edges are genuine lifetime conflicts
    assert len(base_cig.genuine_edges) > 0

    dummy_bitstream = "0" * 8 + "1" * 8
    constrained_cig = WatermarkCIGMapper.embed_watermark(base_cig, dummy_bitstream)
    assert len(constrained_cig.artificial_edges) > 0
    assert len(constrained_cig.edges) >= len(base_cig.edges)

    # Register allocation must satisfy all CIG edges
    reg_alloc = RegisterAllocator.allocate(constrained_cig)
    var_to_reg = reg_alloc.variable_to_register

    for u, v in constrained_cig.edges:
        assert var_to_reg[u] != var_to_reg[v], f"Conflict violated between {u} and {v}"


def test_rtl_generation_validity():
    dfg = create_dct4()
    sched = ListScheduler({"add": 1, "mul": 2}).schedule(dfg)
    base_cig = CIG(sched)
    reg_alloc = RegisterAllocator.allocate(base_cig)
    verilog = RTLGenerator.generate_verilog(reg_alloc, is_protected=False)

    assert "module 4point_dct_original" in verilog
    assert "input wire clk" in verilog
    assert "output reg done" in verilog
    assert "REG_BINDING:" in verilog
