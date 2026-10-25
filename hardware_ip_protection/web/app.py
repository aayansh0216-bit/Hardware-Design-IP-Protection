"""
FastAPI Server for Hardware IP Protection V1 Web Application.

Exposes REST APIs for Tab 1 (Protect Design) and Tab 2 (Verify Dispute).
"""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Dict, Any, List, Optional, Union
import os
import re

from hardware_ip_protection.hls.dfg import (
    create_dct4,
    create_fir,
    create_arf,
    create_mesa,
    create_conv3x3,
    create_iir_butterworth,
    DFG,
)
from hardware_ip_protection.pipeline.engine import ProtectionPipeline, DisputePipeline
from hardware_ip_protection.verification.test_vector_generator import TestVectorSet
from hardware_ip_protection.forensics.watermark_extractor import TransactionWatermarkExtractor

from hardware_ip_protection.pipeline.repository import ProtectionRepository
from hardware_ip_protection.pipeline.transaction_manager import (
    TransactionManager,
    AVAILABLE_DESIGNS,
    AVAILABLE_ENCODING_RULES,
)

app = FastAPI(title="Hardware IP Protection V1", version="1.0.0")

# Store in-memory recent protection runs for seamless dispute tab loading
active_sessions: Dict[str, Any] = {}

BENCHMARK_FACTORIES = {
    "4point_dct": create_dct4,
    "fir_filter": create_fir,
    "arf_filter": create_arf,
    "mesa_benchmark": create_mesa,
    "conv3x3_kernel": create_conv3x3,
    "iir_butterworth": create_iir_butterworth,
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


# ==============================================================================
# Transaction Profile Workflow Endpoints (Seller, Buyer, Verifier)
# ==============================================================================

class SelectDesignRequest(BaseModel):
    design_id: str
    rule_id: str


class EncodeDesignRequest(BaseModel):
    use_table_quirks: bool = False
    design_id: Optional[str] = None
    rule_id: Optional[str] = None


class ContinueWatermarkRequest(BaseModel):
    transaction_id: Optional[str] = "TX-001"
    seller_id: Optional[str] = "SELLER-001"
    buyer_id: Optional[str] = "BUYER-001"
    license_type: Optional[str] = "exclusive"
    k_tx: Optional[str] = "K_tx_symmetric_credential_secret_777"
    watermark_length: Optional[Any] = "auto"


@app.get("/api/transaction/state")
def get_transaction_state(role: Optional[str] = "seller"):
    mgr = TransactionManager.get_instance()
    role_clean = role or "seller"
    return {
        "state": mgr.get_state_for_role(role=role_clean),
        "designs": AVAILABLE_DESIGNS,
        "rules": AVAILABLE_ENCODING_RULES,
    }


@app.post("/api/transaction/select_design")
def select_design_endpoint(req: SelectDesignRequest):
    mgr = TransactionManager.get_instance()
    try:
        st = mgr.select_design_and_rule(req.design_id, req.rule_id)
        return {
            "state": st.model_dump(),
            "design_id": st.design_id,
            "encoding_rule_id": st.encoding_rule_id,
            "selected_design": st.selected_design,
            "selected_encoding_rule": st.selected_encoding_rule,
            "rule_version": st.encoding_rule_version,
            "encoding_transform_required": st.encoding_transform_required,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/transaction/encode_design")
def encode_design_endpoint(req: Optional[EncodeDesignRequest] = None):
    mgr = TransactionManager.get_instance()
    use_quirks = req.use_table_quirks if req else False
    try:
        if req and req.rule_id:
            des_id = req.design_id or mgr.get_state().design_id
            mgr.select_design_and_rule(des_id, req.rule_id)
        st = mgr.generate_original_encoding(use_table_quirks=use_quirks)
        return {"state": st.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/transaction/request_buyer")
def request_buyer_endpoint():
    mgr = TransactionManager.get_instance()
    try:
        st = mgr.request_buyer_contribution()
        return {"state": st.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/transaction/generate_buyer_commitment")
def generate_buyer_commitment_endpoint():
    mgr = TransactionManager.get_instance()
    try:
        st = mgr.generate_buyer_commitment()
        return {"state": st.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/transaction/approve_buyer")
def approve_buyer_endpoint():
    mgr = TransactionManager.get_instance()
    try:
        st = mgr.approve_buyer_request()
        return {"state": st.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/transaction/reject_buyer")
def reject_buyer_endpoint():
    mgr = TransactionManager.get_instance()
    try:
        st = mgr.reject_buyer_request()
        return {"state": st.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/transaction/generate_watermark")
def generate_watermark_endpoint(req: Optional[ContinueWatermarkRequest] = None):
    mgr = TransactionManager.get_instance()
    p = req or ContinueWatermarkRequest()
    cur_st = mgr.get_state()
    try:
        st = mgr.generate_transaction_watermark(
            transaction_id=p.transaction_id or cur_st.transaction_id or "TX-001",
            seller_id=p.seller_id or cur_st.seller_id or "SELLER-001",
            buyer_id=p.buyer_id or cur_st.buyer_id or "BUYER-001",
            license_type=p.license_type or cur_st.license_type or "exclusive",
            k_tx=p.k_tx or cur_st.transaction_credentials.get("k_tx", "K_tx_symmetric_credential_secret_777"),
            watermark_length=p.watermark_length or "auto",
        )
        return {"state": st.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/transaction/commit_watermark")
def commit_watermark_endpoint():
    mgr = TransactionManager.get_instance()
    try:
        st = mgr.commit_original_watermark()
        return {"state": st.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/transaction/split_watermark")
def split_watermark_endpoint():
    mgr = TransactionManager.get_instance()
    try:
        st = mgr.split_and_protect_watermark()
        return {"state": st.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/transaction/commit_embedded_watermark")
def commit_embedded_watermark_endpoint():
    mgr = TransactionManager.get_instance()
    try:
        st = mgr.commit_embedded_watermark()
        return {"state": st.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/transaction/embed_watermark")
def embed_watermark_endpoint(req: Optional[ContinueWatermarkRequest] = None):
    mgr = TransactionManager.get_instance()
    p = req or ContinueWatermarkRequest()
    try:
        st = mgr.embed_watermark_in_rtl(
            watermark_length=p.watermark_length or "auto",
        )
        if st.protection_id and st.pipeline_result:
            if st.protection_id not in active_sessions:
                active_sessions[st.protection_id] = {}
            active_sessions[st.protection_id].update({
                "protected_verilog": st.watermarked_RTL,
                "original_verilog": st.original_RTL,
                "benchmark_id": st.design_id,
                "structural_encoding": st.secured_encoding_E_S,
            })
        return {"state": st.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/transaction/calculate_secured_encoding")
def calculate_secured_encoding_endpoint():
    mgr = TransactionManager.get_instance()
    try:
        st = mgr.calculate_secured_encoding()
        return {"state": st.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/transaction/compare_encodings")
def compare_encodings_endpoint():
    mgr = TransactionManager.get_instance()
    try:
        st = mgr.compare_encodings()
        return {"state": st.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/transaction/verify_behavioral")
def verify_behavioral_endpoint():
    mgr = TransactionManager.get_instance()
    try:
        st = mgr.verify_behavioral_validation()
        return {"state": st.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/transaction/continue_watermark")
def continue_watermark_endpoint(req: Optional[ContinueWatermarkRequest] = None):
    mgr = TransactionManager.get_instance()
    p = req or ContinueWatermarkRequest()
    cur_st = mgr.get_state()
    try:
        st = mgr.continue_watermark_workflow(
            transaction_id=p.transaction_id or cur_st.transaction_id or "TX-001",
            seller_id=p.seller_id or cur_st.seller_id or "SELLER-001",
            buyer_id=p.buyer_id or cur_st.buyer_id or "BUYER-001",
            license_type=p.license_type or cur_st.license_type or "exclusive",
            k_tx=p.k_tx or cur_st.transaction_credentials.get("k_tx", "K_tx_symmetric_credential_secret_777"),
            watermark_length=p.watermark_length or "auto",
        )
        if st.protection_id and st.pipeline_result:
            if st.protection_id not in active_sessions:
                active_sessions[st.protection_id] = {}
            active_sessions[st.protection_id].update({
                "protected_verilog": st.watermarked_RTL,
                "original_verilog": st.original_RTL,
                "benchmark_id": st.design_id,
                "structural_encoding": st.secured_encoding_E_S,
            })
        return {"state": st.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/transaction/reset")
def reset_transaction_endpoint():
    mgr = TransactionManager.get_instance()
    st = mgr.reset()
    return {"state": st.model_dump()}


@app.get("/api/transaction/report")
def get_securing_report_endpoint(transaction_id: Optional[str] = None):
    """
    Read-only retrieval of the technical cost and overhead report for the active transaction.
    Does NOT rerun watermarking or alter pipeline state.
    """
    mgr = TransactionManager.get_instance()
    report = mgr.get_securing_report()
    return {"report": report, "status": report.get("overall_status", "NO_RUN_YET")}


@app.get("/api/transaction/report/export")
def export_securing_report_endpoint(transaction_id: Optional[str] = None):
    """
    Export the technical securing report as a downloadable JSON document.
    """
    from fastapi.responses import Response
    mgr = TransactionManager.get_instance()
    report = mgr.get_securing_report()
    tx_id = report.get("transaction_id", "TX-001")
    json_bytes = json.dumps(report, indent=2).encode("utf-8")
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=securing_report_{tx_id}.json"},
    )


# ==============================================================================
# Verifier Profile & Step-by-Step Dispute Verification Endpoints
# ==============================================================================

from hardware_ip_protection.pipeline.verifier_engine import VerifierEngine


class ConfigureDisputeRequest(BaseModel):
    transaction_id: Optional[str] = "TX-001"
    dispute_type: Optional[str] = "Seller ↔ Buyer Conflict"
    dispute_subcategory: Optional[str] = None


class ExecuteVerifierStepRequest(BaseModel):
    step_number: Union[int, str]
    overrides: Optional[Dict[str, Any]] = None


class RecordStepHashRequest(BaseModel):
    step_id: str
    canonical_hash: str
    artifact_id: Optional[str] = ""


class ReleaseStepOpeningRequest(BaseModel):
    step_id: str


class RunAllStepsRequest(BaseModel):
    overrides: Optional[Dict[str, Any]] = None


class AuditRefSusRequest(BaseModel):
    scenario_name: Optional[str] = "Untouched Design"
    subcategory: Optional[str] = "Exact or near-copy suspicion."
    suspicious_verilog: Optional[str] = None
    protection_id: Optional[str] = None


@app.get("/api/verifier/state")
def get_verifier_state():
    v_eng = VerifierEngine.get_instance()
    sess = v_eng.get_session()
    tx_list = v_eng.get_available_transactions()
    mgr = TransactionManager.get_instance()
    st = mgr.get_state()
    return {
        "session": sess.model_dump(),
        "available_transactions": tx_list,
        "dispute_categories": v_eng.DISPUTE_CATEGORIES,
        "transaction_state": st.model_dump(),
    }


@app.post("/api/verifier/configure_dispute")
def configure_dispute_endpoint(req: ConfigureDisputeRequest):
    v_eng = VerifierEngine.get_instance()
    tx_id = req.transaction_id or "TX-001"
    disp_type = req.dispute_type or "Seller ↔ Buyer Conflict"
    sess = v_eng.reset_session(
        transaction_id=tx_id,
        dispute_type=disp_type,
        dispute_subcategory=req.dispute_subcategory,
    )
    return {"session": sess.model_dump()}


@app.post("/api/verifier/record_step_hash")
def record_step_hash_endpoint(req: RecordStepHashRequest):
    v_eng = VerifierEngine.get_instance()
    try:
        res = v_eng.record_step_hash(step_id=req.step_id, hash_hex=req.canonical_hash, artifact_id=req.artifact_id or "")
        return {"status": "RECORDED", "record": res}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/verifier/release_opening")
def release_opening_endpoint(req: ReleaseStepOpeningRequest):
    v_eng = VerifierEngine.get_instance()
    try:
        res = v_eng.release_step_opening(step_id=req.step_id)
        return {"status": "RELEASED", "record": res}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/verifier/execute_step")
def execute_verifier_step_endpoint(req: ExecuteVerifierStepRequest):
    v_eng = VerifierEngine.get_instance()
    try:
        res = v_eng.execute_step(req.step_number, req.overrides)
        c_hash = res.canonical_hash or res.stage1_reconstruction.get("canonical_hash")
        h_algo = res.hash_algorithm or res.stage1_reconstruction.get("hash_algorithm", "SHA-256")
        b_len = res.bit_length or res.stage1_reconstruction.get("bit_length")
        return {
            "step_result": res.model_dump(),
            "session": v_eng.get_session().model_dump(),
            "canonical_hash": c_hash,
            "hash": c_hash,
            "hash_algorithm": h_algo,
            "bit_length": b_len,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/verifier/run_all_steps")
def run_all_verifier_steps_endpoint(req: Optional[RunAllStepsRequest] = None):
    v_eng = VerifierEngine.get_instance()
    ov = req.overrides if req else None
    try:
        sess = v_eng.run_all_steps(ov)
        return {"session": sess.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/verifier/reset")
def reset_verifier_endpoint():
    v_eng = VerifierEngine.get_instance()
    sess = v_eng.reset_session()
    return {"session": sess.model_dump()}


@app.post("/api/verifier/audit_ref_sus")
def audit_ref_sus_endpoint(req: AuditRefSusRequest):
    v_eng = VerifierEngine.get_instance()
    mgr = TransactionManager.get_instance()
    st = mgr.get_state()

    sus_verilog = req.suspicious_verilog or st.watermarked_RTL
    if not sus_verilog:
        raise HTTPException(status_code=400, detail="No suspicious Verilog provided and none found in transaction state.")

    try:
        result = v_eng.audit_reference_suspicious(
            suspicious_verilog=sus_verilog,
            scenario_name=req.scenario_name or "Untouched Design",
            subcategory=req.subcategory or "Exact or near-copy suspicion.",
            protection_id=req.protection_id or st.protection_id,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




# =====================================================================
# JUDGE-LED INTERROGATION ENDPOINTS (143-Bit / 251-Bit Secured Stage)
# =====================================================================
from hardware_ip_protection.pipeline.interrogation_manager import InterrogationManager

class StartJudgeSessionRequest(BaseModel):
    transaction_id: Optional[str] = None
    claimant_id: Optional[str] = "BUYER-001"
    workflow: Optional[str] = "unsecured_design_encoding"
    branch: Optional[str] = "E_U"
    block5b_enabled: Optional[bool] = False

class SubmitJudgeAnswerRequest(BaseModel):
    session_id: str
    question_id: str
    answer: Any

class SubmitJudgeCorrectionRequest(BaseModel):
    session_id: str
    question_id: str
    answer: Any

class ResetJudgeSessionRequest(BaseModel):
    session_id: str

class ToggleBlock5bRequest(BaseModel):
    session_id: str
    enabled: bool

@app.get("/api/judge/session")
def get_judge_session_endpoint(
    session_id: Optional[str] = None,
    transaction_id: Optional[str] = None,
    workflow: Optional[str] = None,
):
    im = InterrogationManager.get_instance()
    tx_id = transaction_id or "TX-001"
    target_wf = workflow or "unsecured_design_encoding"
    if session_id:
        sess = im.get_session(session_id=session_id)
    else:
        sess = im.get_session(transaction_id=tx_id, workflow=target_wf)

    if not sess:
        sess = im.start_session(transaction_id=tx_id, workflow=target_wf)
    return im.get_session_view(sess.session_id)

@app.post("/api/judge/session/start")
def start_judge_session_endpoint(req: StartJudgeSessionRequest):
    im = InterrogationManager.get_instance()
    tx_id = req.transaction_id or "TX-001"
    target_wf = req.workflow or "unsecured_design_encoding"
    sess = im.start_session(
        transaction_id=tx_id,
        claimant_id=req.claimant_id or "BUYER-001",
        workflow=target_wf,
        branch=req.branch or "E_U",
        block5b_enabled=bool(req.block5b_enabled),
    )
    return im.get_session_view(sess.session_id)

@app.post("/api/judge/session/answer")
def submit_judge_answer_endpoint(req: SubmitJudgeAnswerRequest):
    im = InterrogationManager.get_instance()
    try:
        view = im.submit_answer(req.session_id, req.question_id, req.answer)
        return view
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/judge/session/correct")
def submit_judge_correction_endpoint(req: SubmitJudgeCorrectionRequest):
    im = InterrogationManager.get_instance()
    try:
        view = im.submit_correction(req.session_id, req.question_id, req.answer)
        return view
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/judge/session/reset")
def reset_judge_session_endpoint(req: ResetJudgeSessionRequest):
    im = InterrogationManager.get_instance()
    sess = im.reset_session(req.session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found.")
    return im.get_session_view(sess.session_id)

@app.post("/api/judge/session/toggle_block5b")
def toggle_block5b_endpoint(req: ToggleBlock5bRequest):
    im = InterrogationManager.get_instance()
    sess = im.toggle_block5b(req.session_id, req.enabled)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found.")
    return im.get_session_view(sess.session_id)


# Static files mount
static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir, exist_ok=True)

app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

