"""
Pipeline Execution Engine with Deterministic Caching.

Runs ProtectionPipeline (15 stages) and DisputePipeline (11 stages)
with validation, content-hash caching, and contract enforcement.
"""

from typing import Dict, Any, List, Optional
import copy
from .stages import (
    PipelineStage,
    # Protection stages
    DesignInputStage,
    DesignCanonicalizationStage,
    DesignHashStage,
    SchedulingStage,
    CIGConstructionStage,
    TestVectorGenerationStage,
    TestVectorCommitmentStage,
    TransactionWatermarkGenerationStage,
    WatermarkCommitmentStage,
    WatermarkConstraintStage,
    RegisterAllocationStage,
    RTLGenerationStage,
    BehavioralVerificationStage,
    ReferenceWatermarkExtractionStage,
    ProtectionRecordStage,
    # Dispute stages
    ReferenceDesignLoadStage,
    SuspiciousDesignLoadStage,
    TestVectorLoadVerificationStage,
    DisputeBehavioralVerificationStage,
    ReferenceWatermarkExtractionDisputeStage,
    SuspiciousWatermarkExtractionStage,
    WatermarkSimilarityStage,
    WatermarkCommitmentVerificationStage,
    TestVectorCommitmentVerificationStage,
    DisputeVerificationResultStage,
    EvidencePackagingStage,
)
from .schemas import ProtectionRecordSchema, DisputeResultSchema, EvidenceBundleSchema


class ProtectionPipeline:
    """
    Executes the 15-stage Hardware IP Protection Workflow.
    """

    def __init__(self, cache_enabled: bool = True):
        self.cache_enabled = cache_enabled
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.stages: List[PipelineStage] = [
            DesignInputStage(),
            DesignCanonicalizationStage(),
            DesignHashStage(),
            SchedulingStage(),
            CIGConstructionStage(),
            TestVectorGenerationStage(),
            TestVectorCommitmentStage(),
            TransactionWatermarkGenerationStage(),
            WatermarkCommitmentStage(),
            WatermarkConstraintStage(),
            RegisterAllocationStage(),
            RTLGenerationStage(),
            BehavioralVerificationStage(),
            ReferenceWatermarkExtractionStage(),
            ProtectionRecordStage(),
        ]

    def run(self, initial_context: Dict[str, Any]) -> Dict[str, Any]:
        ctx = dict(initial_context)

        for stage in self.stages:
            stage_name = stage.stage_id
            try:
                ctx = stage.execute(ctx)
            except Exception as e:
                raise RuntimeError(f"Error in pipeline stage '{stage_name}': {str(e)}") from e

        return ctx


import hashlib


class DisputePipeline:
    """
    Executes the 11-stage Hardware IP Dispute Verification Workflow.
    Supports deterministic multi-dimensional caching distinguishing:
    - reference protection identity
    - suspicious scenario
    - suspicious design content hash
    - verification configuration/version
    """

    def __init__(self, cache_enabled: bool = False):
        self.cache_enabled = cache_enabled
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.stages: List[PipelineStage] = [
            ReferenceDesignLoadStage(),
            SuspiciousDesignLoadStage(),
            TestVectorLoadVerificationStage(),
            DisputeBehavioralVerificationStage(),
            ReferenceWatermarkExtractionDisputeStage(),
            SuspiciousWatermarkExtractionStage(),
            WatermarkSimilarityStage(),
            WatermarkCommitmentVerificationStage(),
            TestVectorCommitmentVerificationStage(),
            DisputeVerificationResultStage(),
            EvidencePackagingStage(),
        ]

    def compute_cache_key(self, ctx: Dict[str, Any]) -> str:
        """
        Computes deterministic cache identity taking into account all inputs
        that can affect the dispute outcome.
        """
        ref_id = "UNKNOWN"
        if "protection_record" in ctx and hasattr(ctx["protection_record"], "protection_id"):
            ref_id = ctx["protection_record"].protection_id
        elif "reference_protection_id" in ctx:
            ref_id = str(ctx["reference_protection_id"])

        scenario = str(ctx.get("suspicious_scenario", "Untouched"))
        sus_hash = hashlib.sha256(str(ctx.get("suspicious_verilog", "")).encode("utf-8")).hexdigest()
        ref_hash = hashlib.sha256(str(ctx.get("reference_verilog", "")).encode("utf-8")).hexdigest()
        config_version = "v1.0.0"

        key_str = f"{ref_id}|{scenario}|{sus_hash}|{ref_hash}|{config_version}"
        return hashlib.sha256(key_str.encode("utf-8")).hexdigest()

    def run(self, initial_context: Dict[str, Any]) -> Dict[str, Any]:
        ctx = dict(initial_context)

        if self.cache_enabled:
            cache_key = self.compute_cache_key(ctx)
            if cache_key in self.cache:
                return dict(self.cache[cache_key])

        for stage in self.stages:
            stage_name = stage.stage_id
            try:
                ctx = stage.execute(ctx)
            except Exception as e:
                raise RuntimeError(f"Error in dispute stage '{stage_name}': {str(e)}") from e

        if self.cache_enabled:
            cache_key = self.compute_cache_key(initial_context)
            self.cache[cache_key] = dict(ctx)

        return ctx
