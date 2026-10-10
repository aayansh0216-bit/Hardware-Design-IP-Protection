"""
Pydantic Schemas for Hardware IP Protection V1.

Enforces strict schemas for TransactionRecord, ProtectionRecord, DisputeResult,
and all pipeline stage contracts. Supports variable design-dependent watermark lengths.
"""

from typing import Dict, List, Any, Optional, Literal
from pydantic import BaseModel, Field


class TransactionRecordSchema(BaseModel):
    transaction_id: str = Field(..., description="Unique transaction identifier")
    seller_id: str = Field(..., description="Identifier of the selling party")
    buyer_id: str = Field(..., description="Identifier of the purchasing party")
    design_hash: str = Field(..., description="SHA-256 hash of canonical design representation")
    license_type: Literal["exclusive", "non_exclusive"] = Field(
        ..., description="License grant: exclusive or non_exclusive"
    )
    protocol_version: str = Field(default="1.0", description="Protocol version identifier")


class CommitmentMetadataSchema(BaseModel):
    commitment_hex: str
    curve_name: str = "NIST256p"
    scheme: str = "pedersen"
    message_hash: Optional[str] = None


class TestVectorMetadataSchema(BaseModel):
    vector_set_id: str
    vector_hash: str
    vector_count: int
    commitment: str
    commitment_scheme: str = "pedersen"


class TransactionWatermarkMetadataSchema(BaseModel):
    bit_length: int
    watermark_hash: str
    commitment: str
    commitment_scheme: str = "pedersen"
    canonical_bit_length: int = 256
    embedded_bit_length: Optional[int] = None
    remaining_bit_length: Optional[int] = None
    reconstruction_data: Optional[str] = None
    blinding_factor_hex: Optional[str] = None


class BehavioralVerificationSchema(BaseModel):
    status: Literal["MATCH", "MISMATCH"]
    test_count: int
    matching_outputs: int
    mismatching_outputs: int
    match_ratio: float
    total_test_vectors: int = 0
    exact_output_matches: int = 0
    exact_output_mismatches: int = 0
    exact_output_match_rate: float = 0.0
    exact_vector_matches: int = 0
    exact_vector_mismatches: int = 0
    exact_match_rate: float = 0.0
    total_output_bits: int = 0
    differing_output_bits: int = 0
    hamming_distance: int = 0
    hamming_similarity: float = 1.0
    correlation_analysis: Optional[Dict[str, Any]] = None


class ReferenceWatermarkExtractionSchema(BaseModel):
    status: Literal["SUCCESS", "PARTIAL", "FAILED"]
    recovered_bits: int
    bit_length: int
    is_exact_match: bool


class ProvenanceSchema(BaseModel):
    timestamp: str
    protection_id: str
    algorithm_versions: Dict[str, str] = Field(default_factory=dict)


class ProtectionRecordSchema(BaseModel):
    protection_id: str
    design: Dict[str, str]  # design_hash, original_design_name, protected_module_name
    transaction: TransactionRecordSchema
    test_vectors: TestVectorMetadataSchema
    transaction_watermark: TransactionWatermarkMetadataSchema
    behavioral_verification: BehavioralVerificationSchema
    reference_watermark_extraction: ReferenceWatermarkExtractionSchema
    provenance: ProvenanceSchema
    watermark_mapping: List[Dict[str, Any]] = Field(default_factory=list)
    capacity_analysis: Dict[str, Any] = Field(default_factory=dict)
    canonical_watermark_length: int = 256
    embedded_watermark_length: Optional[int] = None
    remaining_watermark_length: Optional[int] = None
    reconstruction_metadata: Dict[str, Any] = Field(default_factory=dict)
    register_bindings: Dict[str, str] = Field(default_factory=dict)
    cig_constraints: List[List[str]] = Field(default_factory=list)
    original_rtl_sha256: str = ""
    protected_rtl_sha256: str = ""
    structural_encoding: Optional[Dict[str, Any]] = None


# ==============================================================================
# Dispute Schemas
# ==============================================================================

class WatermarkExtractionDisputeSchema(BaseModel):
    status: Literal["SUCCESS", "PARTIAL", "FAILED"]
    recovered_bits: int
    bit_length: int
    reason: Optional[str] = None


class WatermarkSimilaritySchema(BaseModel):
    status: Literal["EXACT", "PARTIAL", "MISMATCH", "NOT_AVAILABLE"]
    matching_bits: int
    mismatching_bits: int
    recovered_bits: int
    unavailable_positions: int
    compared_bits: int
    similarity_ratio: Optional[float] = None
    percentage_str: str
    expected_bits: int = 0
    reference_recovered_bits: int = 0
    suspicious_recovered_bits: int = 0
    missing_bits: int = 0
    matching_positions: int = 0
    mismatching_positions: int = 0
    extraction_coverage: float = 0.0
    recovered_bit_agreement: Optional[float] = None
    coverage_str: str = "0.00%"
    agreement_str: str = "N/A"
    policy_note: str = ""


class WatermarkCommitmentDisputeSchema(BaseModel):
    status: Literal["VALID", "INVALID", "NOT_VERIFIABLE"]
    reference_commitment_check: Literal["VALID", "INVALID", "NOT_VERIFIABLE"] = "VALID"
    suspicious_commitment_check: Literal["VALID", "INVALID", "NOT_VERIFIABLE"] = "VALID"
    recomputed_commitment: Optional[str] = None
    stored_commitment: str
    public_generator_g: Optional[str] = None
    public_generator_h: Optional[str] = None


class TestVectorCommitmentDisputeSchema(BaseModel):
    status: Literal["VALID", "INVALID", "NOT_VERIFIABLE"]
    recomputed_commitment: Optional[str] = None
    stored_commitment: str
    public_generator_g: Optional[str] = None
    public_generator_h: Optional[str] = None


class WatermarkAnalysisDisputeSchema(BaseModel):
    reference_extraction: WatermarkExtractionDisputeSchema
    suspicious_extraction: WatermarkExtractionDisputeSchema
    similarity: WatermarkSimilaritySchema
    commitment: WatermarkCommitmentDisputeSchema


class DisputeProvenanceSchema(BaseModel):
    reference_protection_id: str
    reference_rtl_sha256: str
    suspicious_rtl_sha256: str
    suspicious_scenario: str
    reference_design_hash: str
    suspicious_design_hash: str
    reference_watermark_hash: str
    extracted_watermark_hash: str
    verification_run_id: str


class DisputeResultSchema(BaseModel):
    dispute_id: str
    timestamp: str
    reference_protection_id: str = "UNKNOWN"
    reference_rtl_sha256: str = ""
    suspicious_rtl_sha256: str = ""
    suspicious_scenario: str = "Untouched"
    reference_design_hash: str = ""
    suspicious_design_hash: str = ""
    reference_watermark_hash: str = ""
    extracted_watermark_hash: str = ""
    verification_run_id: str = ""
    provenance: Optional[DisputeProvenanceSchema] = None
    behavioral_verification: BehavioralVerificationSchema
    watermark_analysis: WatermarkAnalysisDisputeSchema
    test_vector_commitment: TestVectorCommitmentDisputeSchema
    structural_encoding_verification: Optional[Dict[str, Any]] = None
    findings_summary: List[str]


class EvidenceBundleSchema(BaseModel):
    dispute_id: str
    protection_id: str
    transaction_record: TransactionRecordSchema
    dispute_result: DisputeResultSchema
    verilog_hashes: Dict[str, str]
    export_timestamp: str
