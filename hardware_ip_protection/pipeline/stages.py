"""
Deterministic Pipeline Stages for Hardware IP Protection V1.

Implements all 15 Protection stages and 11 Dispute stages with explicit
input/output schemas, deterministic cache keys, and contract validation.
Supports design-dependent variable watermark lengths and comment-independent extraction.
"""

from abc import ABC, abstractmethod
import hashlib
import json
import logging
import re
import uuid
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

logger = logging.getLogger("hardware_ip_protection.dispute")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s [%(name)s]: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

from ..hls.dfg import DFG
from ..hls.scheduler import ListScheduler, ScheduledDFG
from ..hls.cig import CIG, ConstrainedCIG, WatermarkCIGMapper, WatermarkCapacityAnalyzer
from ..hls.register_allocator import RegisterAllocator, RegisterAllocationResult
from ..hls.rtl_generator import RTLGenerator
from ..crypto.pedersen import PedersenEngine, PedersenCommitment, CommitmentVerificationStatus
from ..crypto.design_hasher import DesignHasher
from ..crypto.watermark_generator import (
    TransactionWatermarkGenerator,
    SymmetricHKDFWatermarkGenerator,
    TransactionWatermark,
)
from ..verification.test_vector_generator import TestVectorGenerator, TestVectorSet
from ..verification.behavioral_verifier import BehavioralVerifier, BehavioralResult
from ..forensics.watermark_extractor import (
    TransactionWatermarkExtractor,
    ExtractionResult,
    ExtractionStatus,
)
from ..forensics.watermark_similarity import (
    WatermarkSimilarityCalculator,
    WatermarkSimilarity,
    SimilarityStatus,
)
from .schemas import (
    TransactionRecordSchema,
    ProtectionRecordSchema,
    DisputeResultSchema,
    EvidenceBundleSchema,
)
from .repository import ProtectionRepository


class PipelineStage(ABC):
    """
    Base contract for all pipeline stages.
    """

    stage_id: str
    stage_version: str = "1.0.0"

    def compute_cache_key(self, inputs: Dict[str, Any]) -> str:
        """
        Computes deterministic cache key based on stage ID, version, and input contents.
        """
        hasher = hashlib.sha256()
        hasher.update(self.stage_id.encode("utf-8"))
        hasher.update(self.stage_version.encode("utf-8"))
        serialized_inputs = json.dumps(inputs, sort_keys=True, default=str)
        hasher.update(serialized_inputs.encode("utf-8"))
        return hasher.hexdigest()

    @abstractmethod
    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes stage logic, updating and returning context dictionary.
        """
        pass


# ==============================================================================
# Protection Pipeline Stages (1-15)
# ==============================================================================

class DesignInputStage(PipelineStage):
    stage_id = "DesignInputStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        dfg = ctx.get("dfg")
        if not isinstance(dfg, DFG):
            raise ValueError("DesignInputStage requires a valid DFG instance in context['dfg']")
        resource_config = ctx.get("resource_config", {"add": 2, "mul": 2, "sub": 2})
        ctx["raw_dfg"] = dfg
        ctx["resource_config"] = resource_config
        return ctx


class DesignCanonicalizationStage(PipelineStage):
    stage_id = "DesignCanonicalizationStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        dfg: DFG = ctx["raw_dfg"]
        canonical_str = DesignHasher.canonicalize_dfg(dfg.to_dict())
        ctx["canonical_design_representation"] = canonical_str
        return ctx


class DesignHashStage(PipelineStage):
    stage_id = "DesignHashStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        canonical_str = ctx["canonical_design_representation"]
        design_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        ctx["design_hash"] = design_hash
        return ctx


class SchedulingStage(PipelineStage):
    stage_id = "SchedulingStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        dfg: DFG = ctx["raw_dfg"]
        res_config = ctx["resource_config"]
        scheduler = ListScheduler(res_config)
        sched_dfg = scheduler.schedule(dfg)
        ctx["scheduled_dfg"] = sched_dfg
        return ctx


class CIGConstructionStage(PipelineStage):
    stage_id = "CIGConstructionStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        sched_dfg: ScheduledDFG = ctx["scheduled_dfg"]
        base_cig = CIG(sched_dfg)
        ctx["base_cig"] = base_cig

        # Capacity Analysis (Section 7)
        capacity_analysis = WatermarkCapacityAnalyzer.analyze(base_cig)
        ctx["capacity_analysis"] = capacity_analysis

        # Unconstrained register allocation for baseline original design
        orig_alloc = RegisterAllocator.allocate(base_cig)
        ctx["original_register_allocation"] = orig_alloc
        return ctx


class TestVectorGenerationStage(PipelineStage):
    stage_id = "TestVectorGenerationStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        dfg: DFG = ctx["raw_dfg"]
        test_vectors = TestVectorGenerator.generate_stratified(dfg, count=32)
        ctx["test_vector_set"] = test_vectors
        return ctx


class TestVectorCommitmentStage(PipelineStage):
    stage_id = "TestVectorCommitmentStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        test_vectors: TestVectorSet = ctx["test_vector_set"]
        pe = PedersenEngine()
        commitment, r_v = pe.commit(test_vectors.canonical_json)
        ctx["test_vector_commitment"] = commitment
        ctx["test_vector_blinding_factor"] = r_v
        return ctx


class TransactionWatermarkGenerationStage(PipelineStage):
    stage_id = "TransactionWatermarkGenerationStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        tx_info = dict(ctx["transaction_record"])
        tx_info["design_hash"] = ctx["design_hash"]
        credentials = ctx.get("transaction_credentials", {"k_tx": "default_key_v1"})

        # Determine watermark length (Section 8)
        cap_analysis = ctx["capacity_analysis"]
        req_length = ctx.get("watermark_length")
        if req_length is None or req_length == "auto" or str(req_length).lower() == "automatic":
            watermark_length = cap_analysis["recommended_default_length"]
        else:
            watermark_length = int(req_length)

        # Check capacity
        is_ok, msg = WatermarkCapacityAnalyzer.check_capacity(ctx["base_cig"], watermark_length)
        if not is_ok:
            raise ValueError(msg)

        generator: TransactionWatermarkGenerator = ctx.get(
            "watermark_generator", SymmetricHKDFWatermarkGenerator()
        )
        watermark = generator.generate(tx_info, credentials, watermark_length=watermark_length)

        ctx["watermark_length"] = watermark_length
        ctx["final_transaction_record"] = tx_info
        ctx["transaction_watermark"] = watermark
        return ctx


class WatermarkCommitmentStage(PipelineStage):
    stage_id = "WatermarkCommitmentStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        watermark: TransactionWatermark = ctx["transaction_watermark"]
        pe = PedersenEngine()
        # Commit over the COMPLETE canonical 256-bit watermark (Section 9 & 24, Part H)
        commitment_data = getattr(watermark, "canonical_bitstream", watermark.bitstream)
        commitment, r_w = pe.commit(commitment_data)
        ctx["watermark_commitment"] = commitment
        ctx["watermark_blinding_factor"] = r_w
        return ctx


class WatermarkConstraintStage(PipelineStage):
    stage_id = "WatermarkConstraintStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        base_cig: CIG = ctx["base_cig"]
        watermark: TransactionWatermark = ctx["transaction_watermark"]
        constrained_cig = WatermarkCIGMapper.embed_watermark(base_cig, watermark.bitstream)
        ctx["constrained_cig"] = constrained_cig
        ctx["watermark_mapping"] = constrained_cig.embedding_log
        return ctx


class RegisterAllocationStage(PipelineStage):
    stage_id = "RegisterAllocationStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        constrained_cig: ConstrainedCIG = ctx["constrained_cig"]
        protected_alloc = RegisterAllocator.allocate(constrained_cig)
        ctx["protected_register_allocation"] = protected_alloc
        return ctx


class RTLGenerationStage(PipelineStage):
    stage_id = "RTLGenerationStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        orig_alloc = ctx["original_register_allocation"]
        prot_alloc = ctx["protected_register_allocation"]

        original_verilog = RTLGenerator.generate_verilog(orig_alloc, is_protected=False)
        protected_verilog = RTLGenerator.generate_verilog(prot_alloc, is_protected=True)

        ctx["original_verilog"] = original_verilog
        ctx["protected_verilog"] = protected_verilog
        return ctx


class BehavioralVerificationStage(PipelineStage):
    stage_id = "BehavioralVerificationStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        dfg: DFG = ctx["raw_dfg"]
        test_vectors: TestVectorSet = ctx["test_vector_set"]
        orig_verilog: str = ctx["original_verilog"]
        prot_verilog: str = ctx["protected_verilog"]

        result = BehavioralVerifier.verify(dfg, test_vectors, orig_verilog, prot_verilog)
        ctx["protection_behavioral_result"] = result
        if result.status.value != "MATCH":
            raise RuntimeError(f"Behavioral verification failed during protection: {result.to_dict()}")
        return ctx


class ReferenceWatermarkExtractionStage(PipelineStage):
    stage_id = "ReferenceWatermarkExtractionStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        prot_verilog: str = ctx["protected_verilog"]
        intended_wm: TransactionWatermark = ctx["transaction_watermark"]
        mapping: List[Dict[str, Any]] = ctx["watermark_mapping"]

        # Extraction without depending on comments (Section 12)
        ext_result = TransactionWatermarkExtractor.extract(
            prot_verilog, watermark_mapping=mapping, expected_length=intended_wm.bit_length
        )
        ctx["reference_extracted_watermark"] = ext_result

        # Reconstruct canonical 256-bit watermark: W_256' = W_embedded' || W_remaining
        pe = PedersenEngine()
        r_w = ctx["watermark_blinding_factor"]
        comm: PedersenCommitment = ctx["watermark_commitment"]
        remaining_bits = getattr(intended_wm, "remaining_bitstream", "")
        reconstructed_wm = (ext_result.bitstream or "") + remaining_bits

        v_status = pe.verify(reconstructed_wm, comm.commitment_hex, r_w)
        ctx["reference_commitment_status"] = v_status
        return ctx


class ProtectionRecordStage(PipelineStage):
    stage_id = "ProtectionRecordStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        dfg: DFG = ctx["raw_dfg"]
        tx_info = ctx["final_transaction_record"]
        wm: TransactionWatermark = ctx["transaction_watermark"]
        wm_comm: PedersenCommitment = ctx["watermark_commitment"]
        tvs: TestVectorSet = ctx["test_vector_set"]
        tv_comm: PedersenCommitment = ctx["test_vector_commitment"]
        b_res: BehavioralResult = ctx["protection_behavioral_result"]
        ref_ext: ExtractionResult = ctx["reference_extracted_watermark"]
        mapping: List[Dict[str, Any]] = ctx["watermark_mapping"]
        cap_analysis: Dict[str, Any] = ctx["capacity_analysis"]
        prot_alloc = ctx["protected_register_allocation"]
        constrained_cig = ctx["constrained_cig"]
        orig_verilog: str = ctx["original_verilog"]
        prot_verilog: str = ctx["protected_verilog"]

        protection_id = f"PROT-{tx_info['transaction_id']}-{wm.watermark_hash[:8]}"

        canonical_len = getattr(wm, "canonical_length", 256)
        embedded_len = getattr(wm, "embedded_length", wm.bit_length)
        remaining_len = getattr(wm, "remaining_length", max(0, canonical_len - embedded_len))
        remaining_bits = getattr(wm, "remaining_bitstream", "")

        reconstruction_metadata = {
            "canonical_watermark_length": canonical_len,
            "embedded_watermark_length": embedded_len,
            "remaining_watermark_length": remaining_len,
            "remaining_bitstream": remaining_bits,
            "embedded_bit_range": [0, embedded_len],
        }

        orig_rtl_sha256 = hashlib.sha256(orig_verilog.encode("utf-8")).hexdigest()
        prot_rtl_sha256 = hashlib.sha256(prot_verilog.encode("utf-8")).hexdigest()

        rec_dict = {
            "protection_id": protection_id,
            "design": {
                "design_hash": ctx["design_hash"],
                "original_design": dfg.name,
                "protected_design": f"{dfg.name}_protected",
            },
            "transaction": {
                "protocol_version": "1.0",
                "transaction_id": tx_info["transaction_id"],
                "seller_id": tx_info["seller_id"],
                "buyer_id": tx_info["buyer_id"],
                "design_hash": ctx["design_hash"],
                "license_type": tx_info["license_type"],
            },
            "test_vectors": {
                "vector_set_id": tvs.vector_set_id,
                "vector_hash": tvs.vector_hash,
                "vector_count": len(tvs),
                "commitment": tv_comm.commitment_hex,
                "commitment_scheme": "pedersen",
            },
            "transaction_watermark": {
                "bit_length": wm.bit_length,
                "watermark_hash": wm.watermark_hash,
                "commitment": wm_comm.commitment_hex,
                "commitment_scheme": "pedersen",
                "canonical_bit_length": canonical_len,
                "embedded_bit_length": embedded_len,
                "remaining_bit_length": remaining_len,
                "reconstruction_data": remaining_bits,
                "blinding_factor_hex": hex(ctx["watermark_blinding_factor"])[2:].zfill(64),
            },
            "behavioral_verification": {
                "status": b_res.status.value,
                "test_count": b_res.test_count,
                "matching_outputs": b_res.matching_outputs,
                "mismatching_outputs": b_res.mismatching_outputs,
                "match_ratio": b_res.match_ratio,
            },
            "reference_watermark_extraction": {
                "status": ref_ext.status.value,
                "recovered_bits": ref_ext.recovered_bits,
                "bit_length": wm.bit_length,
                "is_exact_match": (ref_ext.bitstream == wm.bitstream),
            },
            "provenance": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "protection_id": protection_id,
                "algorithm_versions": {
                    "hls": "v1.0.0",
                    "pedersen": "v1.0.0-p256",
                    "cig_mapper": "v1.0.0-variable_pair",
                },
            },
            "watermark_mapping": mapping,
            "capacity_analysis": cap_analysis,
            "canonical_watermark_length": canonical_len,
            "embedded_watermark_length": embedded_len,
            "remaining_watermark_length": remaining_len,
            "reconstruction_metadata": reconstruction_metadata,
            "register_bindings": prot_alloc.variable_to_register,
            "cig_constraints": [list(e) for e in sorted(list(constrained_cig.artificial_edges))],
            "original_rtl_sha256": orig_rtl_sha256,
            "protected_rtl_sha256": prot_rtl_sha256,
        }

        # Validate with Pydantic
        record_model = ProtectionRecordSchema(**rec_dict)
        ctx["protection_record"] = record_model

        # Persist to SQLite repository
        try:
            ProtectionRepository.get_instance().save(record_model)
        except Exception as ex:
            logger.warning(f"Could not persist protection record to SQLite: {ex}")

        return ctx


# ==============================================================================
# Dispute Pipeline Stages (1-11)
# ==============================================================================

class ReferenceDesignLoadStage(PipelineStage):
    stage_id = "ReferenceDesignLoadStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        if "reference_verilog" not in ctx:
            raise ValueError("ReferenceDesignLoadStage requires context['reference_verilog']")
        ctx["reference_rtl_sha256"] = hashlib.sha256(ctx["reference_verilog"].encode("utf-8")).hexdigest()
        return ctx


class SuspiciousDesignLoadStage(PipelineStage):
    stage_id = "SuspiciousDesignLoadStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        if "suspicious_verilog" not in ctx:
            raise ValueError("SuspiciousDesignLoadStage requires context['suspicious_verilog']")
        ctx["suspicious_rtl_sha256"] = hashlib.sha256(ctx["suspicious_verilog"].encode("utf-8")).hexdigest()
        return ctx


class TestVectorLoadVerificationStage(PipelineStage):
    stage_id = "TestVectorLoadVerificationStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        tvs = ctx.get("test_vector_set")
        if not tvs:
            raise ValueError("TestVectorLoadVerificationStage requires context['test_vector_set']")
        ctx["verified_test_vector_set"] = tvs
        return ctx


class DisputeBehavioralVerificationStage(PipelineStage):
    stage_id = "DisputeBehavioralVerificationStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        dfg: DFG = ctx["raw_dfg"]
        tvs: TestVectorSet = ctx["verified_test_vector_set"]
        ref_verilog = ctx["reference_verilog"]
        sus_verilog = ctx["suspicious_verilog"]

        b_res = BehavioralVerifier.verify(dfg, tvs, ref_verilog, sus_verilog)
        ctx["dispute_behavioral_result"] = b_res
        return ctx


class ReferenceWatermarkExtractionDisputeStage(PipelineStage):
    stage_id = "ReferenceWatermarkExtractionDisputeStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        ref_verilog = ctx["reference_verilog"]
        mapping = ctx.get("watermark_mapping")
        if mapping is None and "protection_record" in ctx:
            pr = ctx["protection_record"]
            if hasattr(pr, "watermark_mapping"):
                mapping = pr.watermark_mapping
            elif isinstance(pr, dict) and "watermark_mapping" in pr:
                mapping = pr["watermark_mapping"]

        expected_len = ctx.get("watermark_length")
        if expected_len is None and "protection_record" in ctx:
            pr = ctx["protection_record"]
            if hasattr(pr, "watermark_mapping") and pr.watermark_mapping:
                expected_len = len(pr.watermark_mapping)
            elif isinstance(pr, dict) and "watermark_mapping" in pr and pr["watermark_mapping"]:
                expected_len = len(pr["watermark_mapping"])
        if expected_len is None:
            expected_len = len(mapping) if mapping else 16

        ref_ext = TransactionWatermarkExtractor.extract(
            ref_verilog, watermark_mapping=mapping, expected_length=expected_len
        )
        ctx["dispute_reference_extraction"] = ref_ext
        return ctx


class SuspiciousWatermarkExtractionStage(PipelineStage):
    stage_id = "SuspiciousWatermarkExtractionStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        sus_verilog = ctx["suspicious_verilog"]
        mapping = ctx.get("watermark_mapping")
        if mapping is None and "protection_record" in ctx:
            pr = ctx["protection_record"]
            if hasattr(pr, "watermark_mapping"):
                mapping = pr.watermark_mapping
            elif isinstance(pr, dict) and "watermark_mapping" in pr:
                mapping = pr["watermark_mapping"]

        expected_len = ctx.get("watermark_length")
        if expected_len is None and "protection_record" in ctx:
            pr = ctx["protection_record"]
            if hasattr(pr, "watermark_mapping") and pr.watermark_mapping:
                expected_len = len(pr.watermark_mapping)
            elif isinstance(pr, dict) and "watermark_mapping" in pr and pr["watermark_mapping"]:
                expected_len = len(pr["watermark_mapping"])
        if expected_len is None:
            expected_len = len(mapping) if mapping else 16

        sus_ext = TransactionWatermarkExtractor.extract(
            sus_verilog, watermark_mapping=mapping, expected_length=expected_len
        )
        ctx["dispute_suspicious_extraction"] = sus_ext
        return ctx


class WatermarkSimilarityStage(PipelineStage):
    stage_id = "WatermarkSimilarityStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        ref_ext: ExtractionResult = ctx["dispute_reference_extraction"]
        sus_ext: ExtractionResult = ctx["dispute_suspicious_extraction"]

        sim = WatermarkSimilarityCalculator.calculate(ref_ext, sus_ext)
        ctx["watermark_similarity"] = sim
        return ctx


class WatermarkCommitmentVerificationStage(PipelineStage):
    stage_id = "WatermarkCommitmentVerificationStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        pe = PedersenEngine()
        sus_ext: ExtractionResult = ctx["dispute_suspicious_extraction"]
        stored_comm = ctx.get("stored_watermark_commitment")
        r_w = ctx.get("watermark_blinding_factor")

        # Obtain authorized reconstruction data W_remaining from protection record or context
        remaining_bits = ctx.get("remaining_watermark_bitstream")
        if remaining_bits is None and "protection_record" in ctx:
            pr = ctx["protection_record"]
            if hasattr(pr, "reconstruction_metadata") and isinstance(pr.reconstruction_metadata, dict):
                remaining_bits = pr.reconstruction_metadata.get("remaining_bitstream", "")
            elif isinstance(pr, dict) and "reconstruction_metadata" in pr:
                remaining_bits = pr["reconstruction_metadata"].get("remaining_bitstream", "")
            elif hasattr(pr, "transaction_watermark") and hasattr(pr.transaction_watermark, "reconstruction_data"):
                remaining_bits = pr.transaction_watermark.reconstruction_data or ""
        if remaining_bits is None and "transaction_watermark" in ctx:
            wm = ctx["transaction_watermark"]
            if hasattr(wm, "remaining_bitstream"):
                remaining_bits = wm.remaining_bitstream
        # Refinement Requirement 9 & 10:
        # Check 1: Reference watermark extracted vs SAME pre-dispute stored C_W
        ref_ext: Optional[ExtractionResult] = ctx.get("dispute_reference_extraction")
        if ref_ext and ref_ext.status != ExtractionStatus.FAILED and ref_ext.bitstream and "?" not in ref_ext.bitstream and stored_comm and r_w:
            ref_reconstructed = ref_ext.bitstream + remaining_bits
            ref_status = pe.verify(ref_reconstructed, stored_comm, r_w)
        else:
            ref_status = CommitmentVerificationStatus.NOT_VERIFIABLE

        # Check 2: Suspicious watermark extracted vs SAME pre-dispute stored C_W
        if sus_ext.status == ExtractionStatus.FAILED or not sus_ext.bitstream or "?" in sus_ext.bitstream:
            sus_status = CommitmentVerificationStatus.NOT_VERIFIABLE
            recomp = None
        elif not stored_comm or not r_w:
            sus_status = CommitmentVerificationStatus.NOT_VERIFIABLE
            recomp = None
        else:
            # Reconstruct canonical 256-bit watermark: W_256' = W_embedded' || W_remaining
            reconstructed_wm = sus_ext.bitstream + remaining_bits
            sus_status = pe.verify(reconstructed_wm, stored_comm, r_w)
            try:
                s = pe.hash_to_scalar(reconstructed_wm)
                r_int = int(r_w, 16) if isinstance(r_w, str) else int(r_w)
                recomp = pe.point_to_hex((s * pe.G) + (r_int * pe.H))
            except Exception:
                recomp = None

        ctx["reference_watermark_commitment_status"] = ref_status
        ctx["suspicious_watermark_commitment_status"] = sus_status
        ctx["watermark_commitment_status"] = sus_status
        ctx["watermark_commitment_recomputed"] = recomp
        ctx["pedersen_engine"] = pe
        return ctx


class TestVectorCommitmentVerificationStage(PipelineStage):
    stage_id = "TestVectorCommitmentVerificationStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        pe = PedersenEngine()
        tvs: TestVectorSet = ctx["verified_test_vector_set"]
        stored_comm = ctx.get("stored_test_vector_commitment")
        r_v = ctx.get("test_vector_blinding_factor")

        if not stored_comm or not r_v:
            status = CommitmentVerificationStatus.NOT_VERIFIABLE
            recomp = None
        else:
            status = pe.verify(tvs.canonical_json, stored_comm, r_v)
            try:
                s = pe.hash_to_scalar(tvs.canonical_json)
                r_int = int(r_v, 16) if isinstance(r_v, str) else int(r_v)
                recomp = pe.point_to_hex((s * pe.G) + (r_int * pe.H))
            except Exception:
                recomp = None

        ctx["test_vector_commitment_status"] = status
        ctx["test_vector_commitment_recomputed"] = recomp
        return ctx


class DisputeVerificationResultStage(PipelineStage):
    stage_id = "DisputeVerificationResultStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        b_res: BehavioralResult = ctx["dispute_behavioral_result"]
        ref_ext: ExtractionResult = ctx["dispute_reference_extraction"]
        sus_ext: ExtractionResult = ctx["dispute_suspicious_extraction"]
        sim: WatermarkSimilarity = ctx["watermark_similarity"]
        wm_status: CommitmentVerificationStatus = ctx["watermark_commitment_status"]
        tv_status: CommitmentVerificationStatus = ctx["test_vector_commitment_status"]

        # Helper for safe dictionary or attribute extraction
        def _get_field(obj: Any, key: str, default: Any = "") -> Any:
            if obj is None:
                return default
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)

        # Provenance Calculations
        ref_rtl_sha256 = ctx.get("reference_rtl_sha256") or hashlib.sha256(ctx.get("reference_verilog", "").encode("utf-8")).hexdigest()
        sus_rtl_sha256 = ctx.get("suspicious_rtl_sha256") or hashlib.sha256(ctx.get("suspicious_verilog", "").encode("utf-8")).hexdigest()

        if "suspicious_scenario" in ctx and ctx["suspicious_scenario"]:
            sus_scenario = ctx["suspicious_scenario"]
            norm_scenario = " ".join(str(sus_scenario).lower().split())
            if "untouched" in norm_scenario:
                assert ref_rtl_sha256 == sus_rtl_sha256, (
                    f"Untouched scenario requires reference_rtl_sha256 == suspicious_rtl_sha256, "
                    f"but got {ref_rtl_sha256} != {sus_rtl_sha256}"
                )
            elif norm_scenario not in ("custom verification", "custom verilog input analysis"):
                assert ref_rtl_sha256 != sus_rtl_sha256, (
                    f"Scenario '{sus_scenario}' must not reuse the exact reference RTL: "
                    f"reference_rtl_sha256={ref_rtl_sha256}, suspicious_rtl_sha256={sus_rtl_sha256}"
                )
        else:
            if ref_rtl_sha256 == sus_rtl_sha256:
                sus_scenario = "Untouched"
            else:
                sus_scenario = "Suspicious / Modified RTL"

        prot_rec = ctx.get("protection_record")
        ref_prot_id = _get_field(prot_rec, "protection_id", ctx.get("reference_protection_id", "PROT-UNKNOWN"))

        design_obj = _get_field(prot_rec, "design", None)
        if design_obj is not None:
            ref_design_hash = _get_field(design_obj, "design_hash", "")
        elif "raw_dfg" in ctx:
            ref_design_hash = hashlib.sha256(ctx["raw_dfg"].name.encode("utf-8")).hexdigest()
        else:
            ref_design_hash = ""

        sus_design_hash = hashlib.sha256(re.sub(r"//.*", "", ctx.get("suspicious_verilog", "")).strip().encode("utf-8")).hexdigest()

        wm_obj = _get_field(prot_rec, "transaction_watermark", None)
        if wm_obj is not None:
            ref_wm_hash = _get_field(wm_obj, "watermark_hash", "")
        elif ref_ext.bitstream:
            ref_wm_hash = hashlib.sha256(ref_ext.bitstream.encode("utf-8")).hexdigest()
        else:
            ref_wm_hash = ""

        ext_wm_hash = hashlib.sha256((sus_ext.bitstream or "NONE").encode("utf-8")).hexdigest()
        verification_run_id = f"VRUN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

        # Useful Debugging Logs (Requirement 15)
        logger.info(
            f"\n[DISPUTE AUDIT RUN: {verification_run_id}]\n"
            f"  selected scenario            : {sus_scenario}\n"
            f"  reference protection ID      : {ref_prot_id}\n"
            f"  reference RTL hash           : {ref_rtl_sha256}\n"
            f"  suspicious RTL hash          : {sus_rtl_sha256}\n"
            f"  number of ref watermark bits : {ref_ext.recovered_bits}/{ref_ext.bit_length}\n"
            f"  number of sus extracted bits : {sus_ext.recovered_bits}/{sus_ext.bit_length}\n"
            f"  matching bits                : {sim.matching_bits}\n"
            f"  mismatching bits             : {sim.mismatching_bits}\n"
            f"  unrecovered bits             : {sim.unavailable_positions}\n"
            f"  commitment status            : {wm_status.value}\n"
            f"  test vector status           : {tv_status.value}"
        )

        findings = []
        if b_res.status == "MATCH":
            findings.append(f"Behavioral Verification: MATCH ({b_res.matching_outputs}/{b_res.test_count} tests identical).")
        else:
            findings.append(f"Behavioral Verification: MISMATCH ({b_res.matching_outputs}/{b_res.test_count} tests matching).")

        findings.append(
            f"Watermark Extraction: Reference={ref_ext.status.value} ({ref_ext.recovered_bits}/{ref_ext.bit_length} bits), "
            f"Suspicious={sus_ext.status.value} ({sus_ext.recovered_bits}/{sus_ext.bit_length} bits)."
        )

        if sim.similarity_ratio is not None:
            findings.append(
                f"Structural Forensic Similarity: {sim.percentage_str} ({sim.matching_bits} matching, "
                f"{sim.mismatching_bits} mismatching out of {sim.compared_bits} compared)."
            )
        else:
            findings.append("Structural Forensic Similarity: NOT_AVAILABLE (Extraction failed or insufficient bits).")

        findings.append(f"Watermark Pedersen Commitment: {wm_status.value} (Exact discrete-log cryptographic binding).")
        findings.append(f"Test Vector Commitment: {tv_status.value} (Verifies test vector set integrity without post-hoc cherry-picking).")

        dispute_id = f"DISP-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

        provenance_dict = {
            "reference_protection_id": ref_prot_id,
            "reference_rtl_sha256": ref_rtl_sha256,
            "suspicious_rtl_sha256": sus_rtl_sha256,
            "suspicious_scenario": sus_scenario,
            "reference_design_hash": ref_design_hash,
            "suspicious_design_hash": sus_design_hash,
            "reference_watermark_hash": ref_wm_hash,
            "extracted_watermark_hash": ext_wm_hash,
            "verification_run_id": verification_run_id,
        }

        res_dict = {
            "dispute_id": dispute_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reference_protection_id": ref_prot_id,
            "reference_rtl_sha256": ref_rtl_sha256,
            "suspicious_rtl_sha256": sus_rtl_sha256,
            "suspicious_scenario": sus_scenario,
            "reference_design_hash": ref_design_hash,
            "suspicious_design_hash": sus_design_hash,
            "reference_watermark_hash": ref_wm_hash,
            "extracted_watermark_hash": ext_wm_hash,
            "verification_run_id": verification_run_id,
            "provenance": provenance_dict,
            "behavioral_verification": b_res.to_dict(),
            "watermark_analysis": {
                "reference_extraction": {
                    "status": ref_ext.status.value,
                    "recovered_bits": ref_ext.recovered_bits,
                    "bit_length": ref_ext.bit_length,
                    "reason": ref_ext.reason,
                },
                "suspicious_extraction": {
                    "status": sus_ext.status.value,
                    "recovered_bits": sus_ext.recovered_bits,
                    "bit_length": sus_ext.bit_length,
                    "reason": sus_ext.reason,
                },
                "similarity": sim.to_dict(),
                "commitment": {
                    "status": wm_status.value,
                    "reference_commitment_check": ctx.get("reference_watermark_commitment_status", wm_status).value,
                    "suspicious_commitment_check": ctx.get("suspicious_watermark_commitment_status", wm_status).value,
                    "recomputed_commitment": ctx.get("watermark_commitment_recomputed"),
                    "stored_commitment": ctx.get("stored_watermark_commitment", ""),
                    "public_generator_g": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                    "public_generator_h": "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3",
                },
            },
            "test_vector_commitment": {
                "status": tv_status.value,
                "recomputed_commitment": ctx.get("test_vector_commitment_recomputed"),
                "stored_commitment": ctx.get("stored_test_vector_commitment", ""),
                "public_generator_g": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                "public_generator_h": "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3",
            },
            "findings_summary": findings,
        }

        dispute_model = DisputeResultSchema(**res_dict)
        ctx["dispute_result"] = dispute_model
        return ctx


class EvidencePackagingStage(PipelineStage):
    stage_id = "EvidencePackagingStage"

    def execute(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        disp_res: DisputeResultSchema = ctx["dispute_result"]
        prot_rec: Optional[ProtectionRecordSchema] = ctx.get("protection_record")

        tx_record = ctx.get("transaction_record")
        if not tx_record and prot_rec:
            tx_record = prot_rec.transaction.model_dump()
        if not tx_record:
            tx_record = {
                "protocol_version": "1.0",
                "transaction_id": "UNKNOWN",
                "seller_id": "UNKNOWN",
                "buyer_id": "UNKNOWN",
                "design_hash": "UNKNOWN",
                "license_type": "exclusive",
            }

        ref_hash = ctx.get("reference_rtl_sha256") or hashlib.sha256(ctx.get("reference_verilog", "").encode("utf-8")).hexdigest()
        sus_hash = ctx.get("suspicious_rtl_sha256") or hashlib.sha256(ctx.get("suspicious_verilog", "").encode("utf-8")).hexdigest()

        evidence_dict = {
            "dispute_id": disp_res.dispute_id,
            "protection_id": disp_res.reference_protection_id or (prot_rec.protection_id if prot_rec else "MANUAL-AUDIT"),
            "transaction_record": tx_record,
            "dispute_result": disp_res.model_dump(),
            "verilog_hashes": {
                "reference_verilog_sha256": ref_hash,
                "suspicious_verilog_sha256": sus_hash,
            },
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        bundle = EvidenceBundleSchema(**evidence_dict)
        ctx["evidence_bundle"] = bundle
        return ctx
