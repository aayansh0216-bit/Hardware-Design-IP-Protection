"""
FastAPI Server for Hardware IP Protection V1 Web Application.

Exposes REST APIs for Tab 1 (Protect Design) and Tab 2 (Verify Dispute).
"""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import os
import re

from hardware_ip_protection.hls.dfg import (
    create_dct4,
    create_fir,
    create_arf,
    create_mesa,
    create_conv3x3,
    DFG,
)
from hardware_ip_protection.pipeline.engine import ProtectionPipeline, DisputePipeline
from hardware_ip_protection.verification.test_vector_generator import TestVectorSet
from hardware_ip_protection.forensics.watermark_extractor import TransactionWatermarkExtractor

from hardware_ip_protection.pipeline.repository import ProtectionRepository

app = FastAPI(title="Hardware IP Protection V1", version="1.0.0")

# Store in-memory recent protection runs for seamless dispute tab loading
active_sessions: Dict[str, Any] = {}

BENCHMARK_FACTORIES = {
    "4point_dct": create_dct4,
    "fir_filter": create_fir,
    "arf_filter": create_arf,
    "mesa_benchmark": create_mesa,
    "conv3x3_kernel": create_conv3x3,
}


from hardware_ip_protection.hls.scheduler import ListScheduler
from hardware_ip_protection.hls.cig import CIG, WatermarkCapacityAnalyzer


@app.get("/api/benchmarks")
def get_benchmarks():
    benchmarks = []
    for key, factory in BENCHMARK_FACTORIES.items():
        dfg: DFG = factory()
        sched = ListScheduler({"add": 2, "mul": 2, "sub": 2}).schedule(dfg)
        base_cig = CIG(sched)
        cap = WatermarkCapacityAnalyzer.analyze(base_cig)
        benchmarks.append({
            "id": key,
            "name": dfg.name,
            "operation_count": len(dfg.nodes),
            "input_count": len(dfg.inputs),
            "output_count": len(dfg.outputs),
            "variable_count": len(dfg.all_variables),
            "inputs": dfg.inputs,
            "outputs": dfg.outputs,
            "capacity": cap,
        })
    return {"benchmarks": benchmarks}


@app.get("/api/capacity")
def get_capacity(benchmark_id: str):
    if benchmark_id not in BENCHMARK_FACTORIES:
        raise HTTPException(status_code=400, detail=f"Unknown benchmark '{benchmark_id}'")
    factory = BENCHMARK_FACTORIES[benchmark_id]
    dfg: DFG = factory()
    sched = ListScheduler({"add": 2, "mul": 2, "sub": 2}).schedule(dfg)
    base_cig = CIG(sched)
    cap = WatermarkCapacityAnalyzer.analyze(base_cig)
    return {"benchmark_id": benchmark_id, "capacity": cap}


@app.get("/api/protection_records")
def list_protection_records():
    return {"records": ProtectionRepository.get_instance().list_all()}


@app.get("/api/protection_records/{protection_id}")
def get_protection_record(protection_id: str):
    rec = ProtectionRepository.get_instance().get(protection_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Protection record not found")
    return rec


class ProtectRequest(BaseModel):
    benchmark_id: str
    resource_config: Optional[Dict[str, int]] = None
    transaction_id: str
    seller_id: str
    buyer_id: str
    license_type: str
    k_tx: str
    watermark_length: Optional[Any] = "auto"
    encoding_scope: Optional[List[int]] = None


@app.post("/api/protect")
def protect_design(req: ProtectRequest):
    if req.benchmark_id not in BENCHMARK_FACTORIES:
        raise HTTPException(status_code=400, detail=f"Unknown benchmark '{req.benchmark_id}'")

    factory = BENCHMARK_FACTORIES[req.benchmark_id]
    dfg: DFG = factory()

    res_config = req.resource_config or {"add": 2, "mul": 2, "sub": 2}
    pipeline = ProtectionPipeline()
    init_ctx = {
        "dfg": dfg,
        "resource_config": res_config,
        "transaction_record": {
            "transaction_id": req.transaction_id,
            "seller_id": req.seller_id,
            "buyer_id": req.buyer_id,
            "license_type": req.license_type,
        },
        "transaction_credentials": {"k_tx": req.k_tx},
        "watermark_length": req.watermark_length,
        "encoding_scope": req.encoding_scope,
    }

    try:
        prot_ctx = pipeline.run(init_ctx)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    rec = prot_ctx["protection_record"]
    prot_ctx["benchmark_id"] = req.benchmark_id
    active_sessions[rec.protection_id] = prot_ctx

    base_cig = prot_ctx["base_cig"]
    constrained_cig = prot_ctx["constrained_cig"]
    prot_alloc = prot_ctx["protected_register_allocation"]
    orig_alloc = prot_ctx["original_register_allocation"]
    sched = prot_ctx["scheduled_dfg"]
    wm = prot_ctx["transaction_watermark"]
    cap_analysis = prot_ctx["capacity_analysis"]

    return {
        "protection_id": rec.protection_id,
        "design_hash": prot_ctx["design_hash"],
        "benchmark_id": req.benchmark_id,
        "total_steps": sched.total_steps,
        "scheduled_steps": sched.step_nodes,
        "variable_lifetimes": sched.variable_lifetimes,
        "cig": {
            "nodes": base_cig.nodes,
            "genuine_edges": [list(e) for e in sorted(list(base_cig.genuine_edges))],
            "artificial_edges": [list(e) for e in sorted(list(constrained_cig.artificial_edges))],
            "total_edges": len(constrained_cig.edges),
            "constraints_count": len(constrained_cig.artificial_edges),
        },
        "register_allocation": {
            "original_registers": orig_alloc.registers,
            "original_count": orig_alloc.register_count,
            "protected_registers": prot_alloc.registers,
            "protected_count": prot_alloc.register_count,
            "variable_to_register": prot_alloc.variable_to_register,
            "timing_table": prot_alloc.timing_table,
        },
        "transaction_watermark": {
            "bitstream": wm.bitstream,
            "bit_length": wm.bit_length,
            "hex": wm.hex,
            "watermark_hash": wm.watermark_hash,
            "commitment_hex": prot_ctx["watermark_commitment"].commitment_hex,
            "blinding_factor_hex": hex(prot_ctx["watermark_blinding_factor"])[2:].zfill(64),
            "public_generator_g": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "public_generator_h": "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3",
        },
        "capacity_analysis": cap_analysis,
        "watermark_mapping": prot_ctx["watermark_mapping"],
        "test_vectors": {
            "vector_set_id": prot_ctx["test_vector_set"].vector_set_id,
            "vector_count": len(prot_ctx["test_vector_set"]),
            "vector_hash": prot_ctx["test_vector_set"].vector_hash,
            "commitment_hex": prot_ctx["test_vector_commitment"].commitment_hex,
            "blinding_factor_hex": hex(prot_ctx["test_vector_blinding_factor"])[2:].zfill(64),
            "public_generator_g": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "public_generator_h": "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3",
            "vectors": prot_ctx["test_vector_set"].vectors,
        },
        "behavioral_verification": prot_ctx["protection_behavioral_result"].to_dict(),
        "reference_watermark_extraction": {
            "status": prot_ctx["reference_extracted_watermark"].status.value,
            "recovered_bits": prot_ctx["reference_extracted_watermark"].recovered_bits,
            "bit_length": wm.bit_length,
            "is_exact": prot_ctx["reference_extracted_watermark"].bitstream == wm.bitstream,
        },
        "original_verilog": prot_ctx["original_verilog"],
        "protected_verilog": prot_ctx["protected_verilog"],
        "structural_encoding": prot_ctx.get("structural_encoding"),
        "protection_record": rec.model_dump(),
    }


class AttackPresetRequest(BaseModel):
    protection_id: str
    preset_type: str  # untouched, partial_tamper, complete_removal, corrupted, different_tx, independent


@app.post("/api/attack_preset")
def generate_attack_preset(req: AttackPresetRequest):
    prot_ctx = active_sessions.get(req.protection_id)
    if not prot_ctx:
        raise HTTPException(status_code=404, detail="Protection ID not found in current session")

    prot_verilog = prot_ctx["protected_verilog"]
    dfg: DFG = prot_ctx["raw_dfg"]
    mapping = prot_ctx["watermark_mapping"]
    alloc = prot_ctx["protected_register_allocation"].variable_to_register

    if req.preset_type == "untouched":
        return {
            "preset": "untouched",
            "scenario_name": "Untouched Design",
            "description": "Untouched authentic protected RTL (Byte-identical to certified reference)",
            "suspicious_verilog": prot_verilog,
        }

    elif req.preset_type == "partial_tamper":
        # Find a constrained pair (u, v) where v has an explicit synthesizable wire tap
        pair_to_tamper = None
        for item in mapping:
            u, v = item["pair"]
            if f"wire [31:0] {v} = " in prot_verilog:
                pair_to_tamper = (u, v)
                break
        if not pair_to_tamper:
            pair_to_tamper = mapping[0]["pair"]

        u, v = pair_to_tamper
        target_reg = alloc[u]
        old_reg = alloc[v]

        # Modify the structural wire net tap in RTL to force variable v into u's register
        tampered_verilog = re.sub(
            rf"(wire\s+\[31:0\]\s+{v}\s*=\s*)R\d+\s*;",
            rf"\g<1>{target_reg};",
            prot_verilog,
        )
        tampered_verilog = re.sub(
            rf"\b(R\d+)\s*<=\s*{v}\s*;",
            rf"{target_reg} <= {v};",
            tampered_verilog,
        )
        # Also update comments for consistency
        tampered_verilog = tampered_verilog.replace(
            f"// REG_BINDING: {v} -> {old_reg}", f"// REG_BINDING: {v} -> {target_reg}"
        )

        return {
            "preset": "partial_tamper",
            "scenario_name": "Partial Tampering",
            "description": f"Partial structural watermark tampering: pair ({u}, {v}) merged into register {target_reg} violating non-sharing constraint",
            "suspicious_verilog": tampered_verilog,
        }

    elif req.preset_type == "complete_removal":
        # Strip all watermark structural constraints (wire net taps, comments, and internal variable references)
        # while preserving normal functional datapath and FSM execution
        stripped = re.sub(r"//.*", "", prot_verilog)
        stripped = re.sub(r"wire\s+\[\d+:\d+\]\s+[a-zA-Z]\w*\s*=\s*R\d+\s*;", "", stripped)
        stripped = re.sub(r"assign\s+[a-zA-Z]\w*\s*=\s*R\d+\s*;", "", stripped)
        stripped = re.sub(r"R\d+\s*<=\s*[a-zA-Z]\w*\s*;", "// input load unwatermarked", stripped)
        stripped = re.sub(r"[a-zA-Z]\w*\s*<=\s*R\d+\s*;", "// output write unwatermarked", stripped)
        stripped = stripped.replace(f"module {dfg.name}_protected", f"module {dfg.name}_unwatermarked")

        return {
            "preset": "complete_removal",
            "scenario_name": "Complete Removal",
            "description": "Complete watermark removal: all structural watermark taps and constraints stripped while preserving functional design",
            "suspicious_verilog": stripped,
        }

    elif req.preset_type == "corrupted":
        # Corrupt watermark: merge pair 0 to create violation 'X', and corrupt pair 1 tap to create '?'
        corrupted_verilog = prot_verilog
        if len(mapping) > 0:
            u0, v0 = mapping[0]["pair"]
            target_reg0 = alloc[u0]
            corrupted_verilog = re.sub(
                rf"(wire\s+\[31:0\]\s+{v0}\s*=\s*)R\d+\s*;",
                rf"\g<1>{target_reg0};",
                corrupted_verilog,
            )
            corrupted_verilog = re.sub(
                rf"\b(R\d+)\s*<=\s*{v0}\s*;",
                rf"{target_reg0} <= {v0};",
                corrupted_verilog,
            )
            corrupted_verilog = corrupted_verilog.replace(
                f"// REG_BINDING: {v0} -> {alloc[v0]}", f"// REG_BINDING: {v0} -> {target_reg0}"
            )
        if len(mapping) > 1:
            u1, v1 = mapping[1]["pair"]
            corrupted_verilog = re.sub(
                rf"\bwire\s+\[31:0\]\s+{v1}\b",
                f"wire [31:0] corrupted_{v1}",
                corrupted_verilog,
            )
            corrupted_verilog = re.sub(
                rf"\b(R\d+)\s*<=\s*{v1}\s*;",
                rf"\g<1> <= corrupted_{v1};",
                corrupted_verilog,
            )
            corrupted_verilog = corrupted_verilog.replace(
                f"// REG_BINDING: {v1} ->", f"// REG_BINDING: corrupted_{v1} ->"
            )

        return {
            "preset": "corrupted",
            "scenario_name": "Corrupted Mark",
            "description": "Corrupted watermark: structural constraints altered creating constraint violations and unrecovered taps",
            "suspicious_verilog": corrupted_verilog,
        }

    elif req.preset_type == "different_tx":
        # Synthesize design with a structurally valid watermark belonging to a different transaction
        b_id = prot_ctx.get("benchmark_id", "4point_dct")
        pipe2 = ProtectionPipeline()
        ref_verilog = prot_ctx["protected_verilog"]
        other_verilog = None
        for seed_idx in range(1, 20):
            dfg_other = BENCHMARK_FACTORIES[b_id]()
            other_ctx = pipe2.run({
                "dfg": dfg_other,
                "resource_config": prot_ctx["resource_config"],
                "watermark_length": prot_ctx["watermark_length"],
                "transaction_record": {
                    "transaction_id": f"TX-DIFF-{seed_idx:03d}",
                    "seller_id": "SELLER-GAMMA",
                    "buyer_id": "BUYER-PIRATE",
                    "license_type": "non_exclusive",
                },
                "transaction_credentials": {"k_tx": f"different-tx-credential-seed-{seed_idx}"},
            })
            if other_ctx["protected_verilog"] != ref_verilog:
                other_verilog = other_ctx["protected_verilog"]
                break
        if other_verilog is None:
            other_verilog = other_ctx["protected_verilog"]
        return {
            "preset": "different_tx",
            "scenario_name": "Different Transaction",
            "description": "Structurally valid design embedded with a different transaction's watermark",
            "suspicious_verilog": other_verilog,
        }

    elif req.preset_type == "independent":
        # Unwatermarked baseline design synthesized without reference transaction watermark
        return {
            "preset": "independent",
            "scenario_name": "Independent Design",
            "description": "Independently synthesized unwatermarked baseline design (functional match, independent register allocation)",
            "suspicious_verilog": prot_ctx["original_verilog"],
        }

    else:
        raise HTTPException(status_code=400, detail="Unknown preset type")


class DisputeRequest(BaseModel):
    protection_id: str
    suspicious_verilog: str
    scenario: Optional[str] = "Untouched Design"
    stored_watermark_commitment: Optional[str] = None
    watermark_blinding_factor: Optional[str] = None
    stored_test_vector_commitment: Optional[str] = None
    test_vector_blinding_factor: Optional[str] = None
    tamper_test_vectors: bool = False


@app.post("/api/dispute")
def verify_dispute(req: DisputeRequest):
    prot_ctx = active_sessions.get(req.protection_id)
    if not prot_ctx:
        raise HTTPException(status_code=404, detail="Protection context not found")

    tvs = prot_ctx["test_vector_set"]
    if req.tamper_test_vectors:
        tvs = TestVectorSet(
            [dict(v, **{list(v.keys())[0]: 0xDEADBEEF}) for v in tvs.vectors]
        )

    scenario_name = req.scenario or "Untouched Design"

    stored_wm_comm = req.stored_watermark_commitment or prot_ctx["watermark_commitment"].commitment_hex
    wm_r = req.watermark_blinding_factor or hex(prot_ctx["watermark_blinding_factor"])[2:].zfill(64)
    stored_tv_comm = req.stored_test_vector_commitment or prot_ctx["test_vector_commitment"].commitment_hex
    tv_r = req.test_vector_blinding_factor or hex(prot_ctx["test_vector_blinding_factor"])[2:].zfill(64)

    disp_pipe = DisputePipeline()
    disp_ctx = {
        "raw_dfg": prot_ctx["raw_dfg"],
        "reference_verilog": prot_ctx["protected_verilog"],
        "suspicious_verilog": req.suspicious_verilog,
        "suspicious_scenario": scenario_name,
        "reference_protection_id": req.protection_id,
        "test_vector_set": tvs,
        "stored_test_vector_commitment": stored_tv_comm,
        "test_vector_blinding_factor": tv_r,
        "stored_watermark_commitment": stored_wm_comm,
        "watermark_blinding_factor": wm_r,
        "intended_watermark_bitstream": prot_ctx["transaction_watermark"].bitstream,
        "protection_record": prot_ctx["protection_record"],
    }

    try:
        disp_out = disp_pipe.run(disp_ctx)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    res = disp_out["dispute_result"]
    bundle = disp_out["evidence_bundle"]
    sim = disp_out["watermark_similarity"]
    b_res = disp_out["dispute_behavioral_result"]
    ca = b_res.correlation_analysis or {}
    l1_val = ca.get("l1_distance", 0.0)

    return {
        "dispute_result": res.model_dump(),
        "evidence_bundle": bundle.model_dump(),
        "provenance": res.provenance.model_dump() if res.provenance else {},
        "comparison": {
            "scenario": res.suspicious_scenario,
            "reference_rtl_sha256": res.reference_rtl_sha256,
            "suspicious_rtl_sha256": res.suspicious_rtl_sha256,
            "verification_run_id": res.verification_run_id,
            "expected_bits": sim.expected_bits,
            "reference_recovered_bits": sim.reference_recovered_bits,
            "suspicious_recovered_bits": sim.suspicious_recovered_bits,
            "missing_bits": sim.missing_bits,
            "matching_positions": sim.matching_positions,
            "mismatching_positions": sim.mismatching_positions,
            "extraction_coverage": sim.extraction_coverage,
            "recovered_bit_agreement": sim.recovered_bit_agreement,
            "coverage_str": sim.coverage_str,
            "agreement_str": sim.agreement_str,
            "compared_bits": sim.compared_bits,
            "unavailable_positions": sim.unavailable_positions,
            "similarity_status": sim.status.value,
            "similarity_ratio": sim.similarity_ratio,
            "percentage_str": sim.percentage_str,
            "matching_bits": sim.matching_bits,
            "mismatching_bits": sim.mismatching_bits,
            "behavior_status": b_res.status.value,
            "l1_distance": l1_val,
            "normalized_l1_distance": l1_val,
            "correlation_analysis": ca,
            "reference_watermark_commitment_status": res.watermark_analysis.commitment.reference_commitment_check,
            "suspicious_watermark_commitment_status": res.watermark_analysis.commitment.suspicious_commitment_check,
            "watermark_commitment_status": res.watermark_analysis.commitment.status,
            "test_vector_commitment_status": res.test_vector_commitment.status,
            "public_generator_g": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "public_generator_h": "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3",
        },
        "structural_encoding_verification": res.structural_encoding_verification,
    }


# Static files mount
static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir, exist_ok=True)

app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
