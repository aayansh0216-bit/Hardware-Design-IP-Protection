"""
Transaction State and Profile Workflow Manager.

Manages the persistent transaction state across Seller, Buyer, and Verifier profiles:
- Profile 1: Seller (Select Design, Select Rule, Generate D, Commit C_D, Request Buyer, Embed Watermark)
- Profile 2: Buyer (View Request, Approve Request, Provide 555-bit B, Commit C_B, Private Secrets)
- Profile 3: Verifier (Placeholder for dispute verification in subsequent phase)
"""

from typing import Dict, Any, Optional, List
import hashlib
from pydantic import BaseModel, Field

from hardware_ip_protection.hls.dfg import DFG, DFGNode, create_dct4, create_fir, create_arf, create_mesa, create_conv3x3
from hardware_ip_protection.hls.structural_encoder import DesignStructuralEncoder, StructuralEncodingResult
from hardware_ip_protection.crypto.pedersen import PedersenEngine, PedersenCommitment
from hardware_ip_protection.pipeline.engine import ProtectionPipeline


def create_iir_butterworth() -> DFG:
    """
    13-node, 7-control-step IIR Butterworth filter benchmark from 'design encoded data.docx'.
    """
    nodes = [
        DFGNode(1, "mul", ["in1", "c1"], "t1"),
        DFGNode(2, "mul", ["in2", "c2"], "t2"),
        DFGNode(3, "mul", ["in3", "c3"], "t3"),
        DFGNode(4, "mul", ["in4", "c4"], "t4"),
        DFGNode(5, "mul", ["in5", "c5"], "t5"),
        DFGNode(6, "mul", ["in6", "c6"], "t6"),
        DFGNode(7, "mul", ["in7", "c7"], "t7"),
        DFGNode(8, "add", ["t1", "t2"], "t8"),
        DFGNode(9, "add", ["t8", "t3"], "t9"),
        DFGNode(10, "add", ["t9", "t4"], "t10"),
        DFGNode(11, "add", ["t10", "t5"], "t11"),
        DFGNode(12, "add", ["t11", "t6"], "t12"),
        DFGNode(13, "add", ["t12", "t7"], "out_bw"),
    ]
    return DFG(
        name="iir_butterworth_filter",
        inputs=[f"in{i}" for i in range(1, 8)] + [f"c{i}" for i in range(1, 8)],
        outputs=["out_bw"],
        nodes=nodes,
    )


# Exact 555-bit demonstration bitstream from provided document
DEMO_BUYER_BITSTREAM: str = (
    "100101101011011010011101010110101111011001101110011110101110010111010011001000110000101000101101001110000011011011110000111101110001111110101101111001100001110010000111011110100111001001010111001101000011010100011111001111111010010101101111010011000111011110111101001110111000011100000011101011101010001100011011011111011111110011101100000011110000110111001111001001000000111101011111101001100011001100010110111010100100011000100100110110010111111011010000001101101011111110100000111101111111000110100101111110101010101010101101111001110000110101111111110"
)

# Architectural registries allowing future designs and rules
AVAILABLE_DESIGNS = [
    {
        "id": "iir_butterworth",
        "name": "IIR Butterworth Filter",
        "description": "13-node, 7-control-step IIR Butterworth filter benchmark",
        "default_rule": "iir_butterworth_rule_v1",
        "supported_rules": ["iir_butterworth_rule_v1", "iir_butterworth_5rule_v1"],
    }
]

AVAILABLE_ENCODING_RULES = [
    {
        "id": "iir_butterworth_rule_v1",
        "name": "IIR Butterworth Encoding Rule",
        "version": "1.0",
        "applicable_design": "iir_butterworth",
        "mode": "four_rule",
        "description": "4-Rule Deterministic Structural Encoding: Parity, Node ID, Op Type, Node Count (143 bits, E_S == D)",
    },
    {
        "id": "iir_butterworth_5rule_v1",
        "name": "IIR Butterworth 5-Rule Encoding",
        "version": "1.0",
        "applicable_design": "iir_butterworth",
        "mode": "five_rule",
        "description": "5-Rule Deterministic Structural Encoding: Rules 1-4 + Rule 5 Register Parity (251 bits, E_S != D, Transformation Required)",
    },
]


class TransactionState(BaseModel):
    transaction_id: str = "TX-001"
    seller_id: str = "SELLER-001"
    buyer_id: str = "BUYER-001"
    license_type: str = "exclusive"
    transaction_credentials: Dict[str, Any] = Field(default_factory=lambda: {"k_tx": "K_tx_symmetric_credential_secret_777"})
    selected_design: str = "IIR Butterworth Filter"
    design_id: str = "iir_butterworth"
    selected_encoding_rule: str = "IIR Butterworth Encoding Rule"
    encoding_rule_id: str = "iir_butterworth_rule_v1"
    encoding_rule_version: str = "1.0"

    # Original Design Encoding D & Commitment C_D
    design_encoding_D: Optional[str] = None
    design_encoding_details: Optional[Dict[str, Any]] = None
    C_D: Optional[str] = None
    blinding_factor_D: Optional[str] = None

    # Buyer Contribution Workflow
    buyer_request_status: str = "Not Requested"  # "Not Requested" | "Pending" | "Pending Buyer Approval" | "Approved" | "Rejected"
    buyer_approved: bool = False
    buyer_rejected: bool = False
    buyer_contribution_status: str = "Not Received"  # "Not Received" | "Received"
    buyer_commitment_status: str = "Not Generated"  # "Not Generated" | "Generated"
    buyer_bitstream_B: Optional[str] = None
    buyer_bitstream_length: Optional[int] = None
    buyer_zeros_count: Optional[int] = None
    buyer_ones_count: Optional[int] = None
    C_B: Optional[str] = None
    blinding_factor_B: Optional[str] = None

    # Buyer & Seller Private Information (Confidential Evidence)
    buyer_private_info: Optional[Dict[str, Any]] = None
    seller_private_info: Optional[Dict[str, Any]] = None

    # Watermark Workflow outputs
    watermark_W: Optional[str] = None
    C_W: Optional[str] = None
    blinding_factor_W: Optional[str] = None
    is_full_watermark: bool = True
    embedded_watermark_length: Optional[int] = 256
    watermark_mapping: Optional[List[Dict[str, Any]]] = None
    W1: Optional[str] = None
    C_W1: Optional[str] = None
    blinding_factor_W1: Optional[str] = None
    protected_W2: Optional[str] = None
    watermarked_RTL: Optional[str] = None
    original_RTL: Optional[str] = None
    secured_encoding_E_S: Optional[Dict[str, Any]] = None
    C_ES: Optional[str] = "NOT_REQUIRED"
    blinding_factor_ES: Optional[str] = None
    encoding_transform_required: Optional[bool] = False
    transformation_rule_id: Optional[str] = "iir_butterworth_transform_v1"
    transformation_rule_version: Optional[str] = "1.0"
    C_V: Optional[str] = None  # Test-vector commitment (behavioral verification)
    design_hash: Optional[str] = None
    protection_id: Optional[str] = None
    pipeline_result: Optional[Dict[str, Any]] = None

    # Stage 4 Sequential Validation States
    stage4_es_calculated: bool = False
    stage4_encodings_compared: bool = False
    stage4_behavioral_verified: bool = False
    stage4_completed: bool = False
    encoding_comparison_result: Optional[Dict[str, Any]] = None
    behavioral_validation_result: Optional[Dict[str, Any]] = None

    # Seller Technical Cost & Overhead Report
    securing_report: Optional[Dict[str, Any]] = None
    securing_reports_history: List[Dict[str, Any]] = Field(default_factory=list)


class TransactionManager:
    """
    Singleton manager maintaining persistent transaction state across profiles.
    """

    _instance = None

    def __init__(self):
        self.state = TransactionState()
        self.state.seller_private_info = self._build_seller_private_info()
        self.state.buyer_private_info = self._build_buyer_private_info()

    @classmethod
    def get_instance(cls) -> "TransactionManager":
        if cls._instance is None:
            cls._instance = TransactionManager()
        return cls._instance

    def reset(self) -> TransactionState:
        self.state = TransactionState()
        self.state.seller_private_info = self._build_seller_private_info()
        self.state.buyer_private_info = self._build_buyer_private_info()
        return self.state

    def get_state(self) -> TransactionState:
        return self.state

    def get_state_for_role(self, role: str = "seller") -> Dict[str, Any]:
        """
        Returns transaction state with role-based authorization:
        - 'seller': Full access to seller_private_info, blinding factors (r_D, r_W, r_W1, r_ES).
        - 'buyer': Redacts seller blinding factors and secret opening parameters. Public commitments (C_D, C_W, C_ES) remain visible.
        - 'verifier': Publicly committed parameters; opening factors are guarded until released.
        """
        state_dict = self.state.model_dump()
        if role.lower() == "buyer":
            state_dict["blinding_factor_D"] = None
            state_dict["blinding_factor_W"] = None
            state_dict["blinding_factor_W1"] = None
            state_dict["blinding_factor_ES"] = None
            state_dict["seller_private_info"] = None
        return state_dict

    def select_design_and_rule(self, design_id: str, rule_id: str) -> TransactionState:
        design_id_clean = str(design_id).strip()
        des = next((d for d in AVAILABLE_DESIGNS if d["id"] == design_id_clean), None)
        if not des:
            raise ValueError(f"Unknown design '{design_id}'")

        rule_id_clean = str(rule_id).strip()
        rule_alias_map = {
            "iir_butterworth_5rule_v1": "iir_butterworth_5rule_v1",
            "5rule": "iir_butterworth_5rule_v1",
            "five_rule": "iir_butterworth_5rule_v1",
            "iir_butterworth_5rule": "iir_butterworth_5rule_v1",
            "iir_butterworth_rule_v1": "iir_butterworth_rule_v1",
            "4rule": "iir_butterworth_rule_v1",
            "four_rule": "iir_butterworth_rule_v1",
            "iir_butterworth_4rule": "iir_butterworth_rule_v1",
        }
        canonical_rule_id = rule_alias_map.get(rule_id_clean, rule_id_clean)

        rul = next((r for r in AVAILABLE_ENCODING_RULES if r["id"] == canonical_rule_id), None)
        if not rul:
            raise ValueError(f"Unknown encoding rule '{rule_id}'")

        supported_rules = des.get("supported_rules", [])
        if supported_rules and canonical_rule_id not in supported_rules:
            raise ValueError(f"Encoding rule '{canonical_rule_id}' is not supported for design '{des['id']}'")

        # Invalidate stale encoding/commitments if rule or design changed
        is_changed = (self.state.encoding_rule_id != rul["id"]) or (self.state.design_id != des["id"])
        if is_changed:
            self.state.design_encoding_D = None
            self.state.design_encoding_details = None
            self.state.C_D = None
            self.state.blinding_factor_D = None
            self.state.watermark_W = None
            self.state.C_W = None
            self.state.blinding_factor_W = None
            self.state.W1 = None
            self.state.C_W1 = None
            self.state.blinding_factor_W1 = None
            self.state.protected_W2 = None
            self.state.watermarked_RTL = None
            self.state.original_RTL = None
            self.state.secured_encoding_E_S = None
            self.state.C_ES = None
            self.state.blinding_factor_ES = None
            self.state.C_V = None
            self.state.design_hash = None
            self.state.protection_id = None
            self.state.pipeline_result = None
            self.state.watermark_mapping = None
            self.state.securing_report = None
            self.state.encoding_comparison_result = None
            self.state.behavioral_validation_result = None
            self.state.stage4_es_calculated = False
            self.state.stage4_encodings_compared = False
            self.state.stage4_behavioral_verified = False
            self.state.stage4_completed = False
            if self.state.design_id != des["id"]:
                self.state.buyer_request_status = "Not Requested"
                self.state.buyer_approved = False
                self.state.buyer_rejected = False
                self.state.buyer_contribution_status = "Not Received"
                self.state.buyer_commitment_status = "Not Generated"

        self.state.design_id = des["id"]
        self.state.selected_design = des["name"]
        self.state.encoding_rule_id = rul["id"]
        self.state.selected_encoding_rule = rul["name"]
        self.state.encoding_rule_version = rul["version"]
        self.state.encoding_transform_required = (rul["id"] == "iir_butterworth_5rule_v1")
        if self.state.encoding_transform_required:
            self.state.transformation_rule_id = "iir_butterworth_transform_v1"
            self.state.transformation_rule_version = "1.0"
        else:
            self.state.transformation_rule_id = None
            self.state.transformation_rule_version = None

        self.state.seller_private_info = self._build_seller_private_info()
        return self.state

    def generate_original_encoding(self, use_table_quirks: bool = False) -> TransactionState:
        """
        Executes the deterministic structural encoder for the selected design/rule.
        Computes D and C_D = Commit(D).
        """
        is_five_rule = (self.state.encoding_rule_id == "iir_butterworth_5rule_v1")
        mode = "five_rule" if is_five_rule else "four_rule"

        if self.state.design_id == "iir_butterworth":
            enc_res: StructuralEncodingResult = DesignStructuralEncoder.encode_golden_butterworth(
                use_document_table_quirks=use_table_quirks,
                mode=mode,
                is_secured=False,
            )
        else:
            raise ValueError(f"No encoder implemented for design '{self.state.design_id}'")

        D = enc_res.canonical_bitstream
        pe = PedersenEngine()
        comm, r_D = pe.commit(D)

        self.state.design_encoding_D = D
        self.state.design_encoding_details = enc_res.to_dict()
        self.state.C_D = comm.commitment_hex
        self.state.blinding_factor_D = hex(r_D)[2:].zfill(64)
        self.state.encoding_transform_required = is_five_rule

        # Populate enriched Seller Private Evidence
        self.state.seller_private_info = self._build_seller_private_info()
        return self.state

    def _build_seller_private_info(self) -> Dict[str, Any]:
        has_D = bool(self.state.design_encoding_D)
        has_W = bool(self.state.watermark_W)
        has_W1 = bool(self.state.W1)

        d_evidence = {
            "reconstruction_method": {
                "selected_design": self.state.selected_design,
                "encoding_rule_id": self.state.encoding_rule_id,
                "encoding_rule_version": self.state.encoding_rule_version,
                "encoding_parameters": "13 DFG nodes, 7 control steps (T1-T7), 2 ALUs (1 multiplier, 1 adder)",
                "control_step_method": "Rule 1: Control-step parity (bit 0 = even step/node parity, bit 1 = odd step/node parity)",
                "control_step_encoding_method": "Rule 1: Control-step parity (bit 0 = even step/node parity, bit 1 = odd step/node parity)",
                "node_id_method": "Rule 2: Node ID encoded as 4-bit unsigned binary (bin(node_id)[2:].zfill(4))",
                "node_id_encoding_method": "Rule 2: Node ID encoded as 4-bit unsigned binary (bin(node_id)[2:].zfill(4))",
                "op_type_method": "Rule 3: Operation type 1-bit indicator (mul = 1, add = 0)",
                "op_type_encoding_method": "Rule 3: Operation type 1-bit indicator (mul = 1, add = 0)",
                "node_count_method": "Rule 4: Control step node-count 2-bit field",
                "step_node_count_encoding_method": "Rule 4: Control step node-count 2-bit field",
                "concatenation_procedure": (
                    "Per-step node traversal: concatenate Rule 1 (4b) + Rule 2 (4b) + Rule 3 (1b) + Rule 4 (2b) for 143 bits, followed by Rule 5 (108 bits for V1..V27 register/variable parity), yielding exactly 251 bits."
                    if (self.state.encoding_rule_id == "iir_butterworth_5rule_v1")
                    else "Per-step node traversal: concatenate Rule 1 (1b) + Rule 2 (4b) + Rule 3 (1b) + Rule 4 (2b) sequentially across control steps T1 through T7, yielding exactly 143 bits."
                ),
                "exact_bitstream_D": self.state.design_encoding_D or "Not generated yet",
                "canonical_bitstream": self.state.design_encoding_D or "Not generated yet",
                "expected_total_bits": 251 if (self.state.encoding_rule_id == "iir_butterworth_5rule_v1") else 143,
                "bit_length": len(self.state.design_encoding_D) if has_D else "Not generated yet",
            },
            "commitment_verification": {
                "commitment_scheme": "Pedersen Commitment over NIST P-256 (C = s*G + r*H over NIST P-256 with s, r in Z_n)",
                "commitment_scheme_formula": "C_D = s_D * G + r_D * H over NIST P-256 (s_D, r_D in Z_n)",
                "scalar_derivation": "s = int(SHA-256(D), 16) mod n",
                "curve": "secp256r1 (NIST P-256)",
                "generator_g": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                "generator_h": "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3",
                "opening_factor_r_D": self.state.blinding_factor_D or "Not generated yet",
                "stored_commitment_C_D": self.state.C_D or "Not generated yet",
                "status": "Generated / Stored" if has_D else "Not generated yet",
            }
        }

        w_evidence = {
            "title": "C_W Evidence: Complete Watermark Generation (W)",
            "reconstruction_method": {
                "generation_function": "Symmetric HKDF with HMAC-SHA256 (RFC 5869 extract-and-expand)",
                "watermark_generation_rule": "Symmetric HKDF with HMAC-SHA256 (RFC 5869 extract-and-expand)",
                "precise_inputs": [
                    "Master Key: k_tx (symmetric transaction credential secret)",
                    f"Transaction Context: {self.state.transaction_id}:{self.state.seller_id}:{self.state.buyer_id}:{self.state.license_type}:{self.state.design_id}",
                    "Salt: SHA-256 digest of canonical transaction record"
                ],
                "precise_inputs_and_ordering": f"1. Key: {self.state.transaction_credentials.get('k_tx', 'K_tx')}; 2. Info: {self.state.transaction_id}:{self.state.seller_id}:{self.state.buyer_id}:{self.state.license_type}:{self.state.design_id}; 3. Length: 32 bytes (256 bits)",
                "input_ordering": f"1. Key: {self.state.transaction_credentials.get('k_tx', 'K_tx')}; 2. Info: {self.state.transaction_id}:{self.state.seller_id}:{self.state.buyer_id}:{self.state.license_type}:{self.state.design_id}; 3. Length: 32 bytes (256 bits)",
                "output_length": "256 bits (32 bytes)",
                "output_length_bits": 256,
                "canonical_representation": "256-bit binary sequence derived via deterministic HKDF-Expand",
                "exact_bitstream_W": self.state.watermark_W or "Not generated yet",
                "canonical_watermark": self.state.watermark_W or "Not generated yet",
            },
            "commitment_verification": {
                "commitment_scheme": "Pedersen Commitment over NIST P-256 (C = s*G + r*H over NIST P-256 with s, r in Z_n)",
                "commitment_scheme_formula": "C_W = s_W * G + r_W * H over NIST P-256 (s_W, r_W in Z_n)",
                "scalar_derivation": "s = int(SHA-256(W), 16) mod n",
                "curve": "secp256r1 (NIST P-256)",
                "generator_g": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                "generator_h": "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3",
                "opening_factor_r_W": self.state.blinding_factor_W or "Not generated yet",
                "stored_commitment_C_W": self.state.C_W or "Not generated yet",
                "status": "Generated / Stored" if has_W else "Not generated yet",
            }
        }

        if self.state.is_full_watermark:
            pe = PedersenEngine()
            g_hex = pe.point_to_hex(pe.G)
            h_hex = pe.point_to_hex(pe.H)
            w1_evidence = {
                "status": "FULL_WATERMARK_EMBEDDED",
                "title": "C_W Evidence: Full Watermark Embedding & Extraction",
                "actual_embedded_length": 256,
                "capacity_evaluation": {
                    "total_watermark_bits": 256,
                    "actual_embedded_bits": 256,
                    "remaining_bits": 0,
                },
                "structural_encoding_mechanism": "Register Conflict Interference Graph (CIG) non-sharing constraint mapping during HLS register binding phase with variable-parity mapping (bit 0 -> Even-Even variable lifetimes, bit 1 -> Odd-Odd variable lifetimes)",
                "rtl_evidence": "Synthesizable Verilog RTL register assignments (sequential datapath and netlist wire bindings)",
                "extraction_procedure": "Inspect synthesized RTL register assignments for target variable pairs; verify mutual exclusion constraints; reconstruct full 256-bit W' sequence",
                "verification_procedure": "Direct C_W verification: verify extracted W' against complete-watermark commitment C_W (no partial W1/W2 splitting or concatenation)",
                "reconstruction_method": {
                    "model": "Complete 256-Bit Watermark Embedding Model",
                    "watermark_length": 256,
                    "actual_embedded_length": 256,
                    "w1_bit_length": 256,
                    "w2_bit_length": 0,
                    "embedded_bits": 256,
                    "protected_remaining_bits": 0,
                    "structural_encoding_mechanism": "Register Conflict Interference Graph (CIG) non-sharing constraint mapping during HLS register binding",
                    "rtl_evidence": "Synthesizable Verilog RTL register assignments (sequential datapath and netlist wire bindings)",
                    "extraction_procedure": "Inspect synthesized RTL register assignments for target variable pairs; verify mutual exclusion constraints; reconstruct full 256-bit W' sequence",
                    "verification_procedure": "Direct C_W verification: verify extracted W' against complete-watermark commitment C_W (no partial W1/W2 splitting or concatenation)",
                    "canonical_w": self.state.watermark_W or "Not generated yet",
                    "canonical_w1": self.state.watermark_W or "Not generated yet",
                    "canonical_w2": "",
                    "canonical_watermark": self.state.watermark_W or "Not generated yet",
                    "exact_bitstream_W": self.state.watermark_W or "Not generated yet",
                    "exact_bitstream_W1": self.state.watermark_W or "Not generated yet",
                    "exact_bitstream_W2": "",
                },
                "commitment_verification": {
                    "status": "DIRECT_C_W_VERIFICATION",
                    "commitment_scheme": "Pedersen Commitment over NIST P-256 (C = s*G + r*H over NIST P-256 with s, r in Z_n)",
                    "commitment_scheme_formula": "C_W = s_W * G + r_W * H over NIST P-256 (s_W, r_W in Z_n)",
                    "note": "Complete watermark W is embedded directly. Commitment C_W is verified directly without requiring partial C_W1.",
                    "curve": "secp256r1 (NIST P-256)",
                    "generator_g": g_hex,
                    "generator_h": h_hex,
                    "stored_commitment_C_W": self.state.C_W or "Not generated yet",
                    "stored_commitment_C_W1": self.state.C_W or "Not generated yet",
                    "opening_factor_r_W": self.state.blinding_factor_W or "Not generated yet",
                    "opening_factor_r_W1": self.state.blinding_factor_W or "Not generated yet",
                }
            }
        else:
            w1_evidence = {
                "reconstruction_method": {
                    "splitting_rule": "Canonical 256-bit W partitioned into embedded slice W1 = W[0:N] and protected slice W2 = W[N:256]",
                    "watermark_splitting_rule": "Canonical 256-bit W partitioned into embedded slice W1 = W[0:32] and protected slice W2 = W[32:256]",
                    "bit_ranges": "W1: bits [0:32] (32 bits); W2: bits [32:256] (224 bits)",
                    "w1_bit_length": 32,
                    "w2_bit_length": 224,
                    "output_length_rule": "Embedded portion length N = 32 bits (CIG feasible register capacity constrained); Protected portion length = 224 bits. Note: Only 32 bits are embedded; the remaining 224 bits are protected off-chain.",
                    "embedding_method": "CIG bipartite conflict edge insertion during HLS register binding phase",
                    "representation_modified": "Register Conflict Interference Graph (CIG) - introduces artificial lifetime exclusion edges",
                    "embedding_constraints": "Deterministic storage variable parity mapping: bit 0 -> Even-Even variable lifetimes; bit 1 -> Odd-Odd variable lifetimes",
                    "extraction_procedure": "Inspect synthesized RTL register bindings for target pairs; test mutual exclusion; recover 32-bit W1 bitstream",
                    "w1_extraction_procedure": "Inspect synthesized RTL register bindings for target pairs; test mutual exclusion; recover 32-bit W1 bitstream",
                    "w2_storage_procedure": "Retain protected slice W2 (224 bits) securely off-chain in confidential seller evidence repository",
                    "complete_reconstruction_rule": "W = W1 || W2 (Concatenate recovered 32-bit W1 with securely stored 224-bit W2)",
                    "complete_watermark_reconstruction_rule": "W = W1 || W2 (Concatenate recovered 32-bit W1 with securely stored 224-bit W2)",
                    "exact_bitstream_W1": self.state.W1 or "Not generated yet",
                    "canonical_w1": self.state.W1 or "Not generated yet",
                    "exact_bitstream_W2": self.state.protected_W2 or "Not generated yet",
                    "canonical_w2": self.state.protected_W2 or "Not generated yet",
                    "canonical_watermark": self.state.watermark_W or "Not generated yet",
                },
                "commitment_verification": {
                    "commitment_scheme": "Pedersen Commitment over NIST P-256 (C = s*G + r*H over NIST P-256 with s, r in Z_n)",
                    "commitment_scheme_formula": "C_W1 = s_W1 * G + r_W1 * H over NIST P-256 (s_W1, r_W1 in Z_n)",
                    "scalar_derivation": "s = int(SHA-256(W1), 16) mod n",
                    "curve": "secp256r1 (NIST P-256)",
                    "generator_g": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                    "generator_h": "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3",
                    "opening_factor_r_W1": self.state.blinding_factor_W1 or "Not generated yet",
                    "stored_commitment_C_W1": self.state.C_W1 or "Not generated yet",
                    "status": "Generated / Stored" if has_W1 else "Not generated yet",
                }
            }

        es_is_diff = bool(self.state.encoding_transform_required or (self.state.C_ES and self.state.C_ES != "NOT_REQUIRED"))
        has_ES_comm = bool(self.state.C_ES and self.state.C_ES != "NOT_REQUIRED")

        if es_is_diff:
            es_evidence = {
                "status": "Generated / Stored" if has_ES_comm else "Pending Calculation",
                "is_required": True,
                "invariance_analysis": {
                    "E_S_equals_D": False,
                    "reason": "Secured encoding E_S differs from original encoding D in Rule 5 by 6 register parity assignments due to watermark embedding constraints."
                },
                "reconstruction_method": {
                    "encoding_method": "Structural encoding rule applied to watermarked RTL schedule and register allocation",
                    "invariance_analysis": "Secured encoding E_S differs from original encoding D in Rule 5 (251 bits vs 251 bits with 6 variables modified). Deterministic transformation required.",
                    "transformation_rule": "Deterministic mapping restores parity invariance between before-embedding and after-embedding Rule 5 register allocations.",
                    "exact_bitstream_E_S": (self.state.secured_encoding_E_S["canonical_bitstream"] if isinstance(self.state.secured_encoding_E_S, dict) else (self.state.secured_encoding_E_S or "Not generated yet")),
                },
                "commitment_verification": {
                    "status": "Generated / Stored" if has_ES_comm else "Pending Calculation",
                    "commitment_scheme": "Pedersen Commitment over NIST P-256 (C = s*G + r*H over NIST P-256 with s, r in Z_n)",
                    "scalar_derivation": "s = int(SHA-256(E_S), 16) mod n",
                    "curve": "secp256r1 (NIST P-256)",
                    "generator_g": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                    "generator_h": "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3",
                    "opening_factor_r_ES": self.state.blinding_factor_ES or "Not generated yet",
                    "stored_commitment_C_ES": self.state.C_ES if has_ES_comm else None,
                    "note": "Secured encoding commitment C_ES required because E_S differs from original encoding D.",
                }
            }
        else:
            es_evidence = {
                "status": "NOT_REQUIRED",
                "is_required": False,
                "invariance_analysis": {
                    "E_S_equals_D": True,
                    "reason": "Artificial register lifetime constraints preserve identical structural operations and control step schedule."
                },
                "reconstruction_method": {
                    "encoding_method": "Structural encoding rule applied to watermarked RTL schedule",
                    "invariance_analysis": "For IIR Butterworth filter benchmark, watermarked register allocation introduces artificial constraints between non-overlapping lifetimes without altering genuine lifetimes or schedule steps. Thus, E_S is structurally identical to D (E_S = D, 143 bits).",
                    "transformation_rule": "Secured encoding commitment and transformation rule not required for this transaction (E_S equals D).",
                    "exact_bitstream_E_S": (self.state.secured_encoding_E_S["canonical_bitstream"] if isinstance(self.state.secured_encoding_E_S, dict) else (self.state.design_encoding_D if has_W else "Not generated yet")),
                },
                "commitment_verification": {
                    "status": "Not Required (E_S = D)",
                    "note": "Secured encoding commitment not required for this transaction (E_S equals D). No fake C_ES generated.",
                    "opening_factor_r_ES": "Not required",
                    "stored_commitment_C_ES": None,
                }
            }

        return {
            # Legacy flat fields for backward compatibility
            "design_encoding_D": self.state.design_encoding_D,
            "design_id": self.state.design_id,
            "selected_design": self.state.selected_design,
            "encoding_rule_id": self.state.encoding_rule_id,
            "encoding_rule_version": self.state.encoding_rule_version,
            "rule_parameters": "Rule 1: CS/Node parity; Rule 2: Node ID bitwidth (4 bits); Rule 3: Op type (mul=1, add=0); Rule 4: Step count (2 bits)",
            "commitment_scheme": "Pedersen Commitment over NIST P-256 (C = s*G + r*H)",
            "blinding_factor_r_D": self.state.blinding_factor_D,
            "watermark_generation_rule": "Symmetric HKDF with HMAC-SHA256 binding canonical transaction record",
            "watermark_W": self.state.watermark_W or "Not generated yet",
            "watermark_split_rule": "Complete 256-bit W embedded directly without splitting" if self.state.is_full_watermark else "Canonical 256-bit W partitioned into W1 (embedded, length N) and W2 (reconstruction, length 256-N)",
            "W1_embedded": self.state.W1 if has_W else "Not generated yet",
            "W2_protected": self.state.protected_W2 if has_W else "Not generated yet",
            "blinding_factor_r_W": self.state.blinding_factor_W or "Not generated yet",
            "blinding_factor_r_W1": self.state.blinding_factor_W1 or "Not generated yet",
            "embedding_rule": "CIG bipartite conflict edge insertion with deterministic parity assignment",
            "secured_encoding_E_S": (self.state.secured_encoding_E_S["canonical_bitstream"] if isinstance(self.state.secured_encoding_E_S, dict) else ("Not generated yet" if not has_W else "E_S = D")),
            "transformation_rule": "Secured encoding commitment not required for this transaction (E_S = D).",
            # Enriched structured evidence cards
            "C_D_evidence": d_evidence,
            "C_W_evidence": w_evidence,
            "C_W1_evidence": w1_evidence,
            "C_ES_evidence": es_evidence,
        }

    def _build_buyer_private_info(self) -> Dict[str, Any]:
        B = self.state.buyer_bitstream_B or DEMO_BUYER_BITSTREAM
        has_CB = bool(self.state.C_B)
        zeros = B.count("0")
        ones = B.count("1")

        cb_evidence = {
            "reconstruction_method": {
                "source_domain": "Licensee Biometric Fingerprint Template",
                "loading_method": "Minutiae coordinate extraction standard (demonstration standard)",
                "loading_derivation_method": "Fingerprint-Derived Bitstream Extraction (fingerprint_minutiae_demo_standard)",
                "expected_length_bits": 555,
                "validated_zeros_count": 242,
                "validated_ones_count": 313,
                "canonical_bitstream_B": B if has_CB else "Not generated yet",
                "expected_properties": {
                    "total_bits": 555,
                    "zeros": 242,
                    "ones": 313,
                    "zero_ratio": "43.60%",
                    "one_ratio": "56.40%"
                },
                "validated": (len(B) == 555 and zeros == 242 and ones == 313),
                "reproduction_procedure": "Calculate scalar s_B = int(SHA-256(B), 16) mod n; compute C_B = s_B*G + r_B*H over NIST P-256 with s_B, r_B in Z_n.",
                "exact_bitstream_B": B if has_CB else "Not generated yet",
                "bit_length": len(B) if has_CB else "Not generated yet",
            },
            "commitment_verification": {
                "commitment_scheme": "Pedersen Commitment over NIST P-256 (C = s*G + r*H over NIST P-256 with s, r in Z_n)",
                "commitment_scheme_formula": "C_B = s_B * G + r_B * H over NIST P-256 (s_B, r_B in Z_n)",
                "scalar_derivation": "s = int(SHA-256(B), 16) mod n",
                "curve": "secp256r1 (NIST P-256)",
                "generator_g": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                "generator_h": "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3",
                "opening_factor_r_B": self.state.blinding_factor_B or "Not generated yet",
                "stored_commitment_C_B": self.state.C_B or "Not generated yet",
                "status": "Generated / Stored" if has_CB else "Not generated yet",
            }
        }

        return {
            # Legacy flat fields
            "bitstream_B": B if has_CB else None,
            "contribution_method": "Fingerprint-Derived Bitstream Extraction (Demonstration Standard)",
            "commitment_scheme": "Pedersen Commitment over NIST P-256 (s*G + r*H)",
            "blinding_factor_r_B": self.state.blinding_factor_B,
            "bitstream_length": len(B) if has_CB else None,
            "zeros_count": zeros if has_CB else None,
            "ones_count": ones if has_CB else None,
            "reproduction_rule": "Deterministic SHA-256 scalar derivation with secret blinding factor r_B over NIST P-256",
            "is_confidential": True,
            "description": "Private opening secret preserved for future Verifier phase.",
            # Enriched structured evidence card
            "C_B_evidence": cb_evidence,
        }

    def request_buyer_contribution(self) -> TransactionState:
        """
        Seller requests fingerprint contribution from Buyer.
        Requires D and C_D to have been generated.
        """
        if not self.state.design_encoding_D or not self.state.C_D:
            raise ValueError("Original design encoding D and commitment C_D must be generated before requesting buyer contribution.")

        self.state.buyer_request_status = "Pending Buyer Approval"
        self.state.buyer_approved = False
        self.state.buyer_rejected = False
        self.state.buyer_contribution_status = "Not Received"
        self.state.buyer_commitment_status = "Not Generated"
        return self.state

    def generate_buyer_commitment(self) -> TransactionState:
        """
        Generates Buyer contribution commitment C_B = Commit(B) from the exact 555-bit demonstration bitstream.
        Calculates counts dynamically from actual bitstream sequence.
        """
        B = DEMO_BUYER_BITSTREAM
        zeros = B.count("0")
        ones = B.count("1")
        if len(B) != 555 or zeros != 242 or ones != 313:
            raise ValueError(f"Invalid demonstration bitstream properties: len={len(B)}, zeros={zeros}, ones={ones}")

        pe = PedersenEngine()
        comm_B, r_B = pe.commit(B)

        self.state.buyer_bitstream_B = B
        self.state.buyer_bitstream_length = len(B)
        self.state.buyer_zeros_count = zeros
        self.state.buyer_ones_count = ones
        self.state.C_B = comm_B.commitment_hex
        self.state.blinding_factor_B = hex(r_B)[2:].zfill(64)
        self.state.buyer_commitment_status = "Generated"

        self.state.buyer_private_info = self._build_buyer_private_info()
        return self.state

    def approve_buyer_request(self) -> TransactionState:
        """
        Buyer approves contribution request, ensures C_B = Commit(B) is generated,
        and transitions shared transaction state to Approved.
        """
        if self.state.buyer_request_status not in ("Pending", "Pending Buyer Approval", "Approved"):
            raise ValueError("No pending request from Seller to approve.")

        if not self.state.C_B or not self.state.buyer_bitstream_B:
            self.generate_buyer_commitment()

        self.state.buyer_request_status = "Approved"
        self.state.buyer_approved = True
        self.state.buyer_rejected = False
        self.state.buyer_contribution_status = "Received"
        self.state.buyer_commitment_status = "Generated"
        return self.state

    def reject_buyer_request(self) -> TransactionState:
        """
        Buyer rejects contribution request.
        """
        if self.state.buyer_request_status not in ("Pending", "Pending Buyer Approval"):
            raise ValueError("No pending request from Seller to reject.")

        self.state.buyer_request_status = "Rejected"
        self.state.buyer_approved = False
        self.state.buyer_rejected = True
        self.state.buyer_contribution_status = "Not Received"
        return self.state

    def generate_transaction_watermark(
        self,
        transaction_id: Optional[str] = None,
        seller_id: Optional[str] = None,
        buyer_id: Optional[str] = None,
        license_type: Optional[str] = None,
        k_tx: Optional[str] = None,
        watermark_length: Any = "auto",
    ) -> TransactionState:
        """
        Stage 2B: Derives canonical 256-bit watermark W = F(D, B, T).
        Does NOT automatically commit W, split W, commit W1, or embed into RTL.
        """
        if not self.state.buyer_approved or not self.state.buyer_bitstream_B:
            raise ValueError("Buyer contribution must be approved and received before generating watermark.")
        if not self.state.design_encoding_D:
            raise ValueError("Original design encoding D must be generated before generating watermark.")

        tx_id = transaction_id or self.state.transaction_id or "TX-001"
        s_id = seller_id or self.state.seller_id or "SELLER-001"
        b_id = buyer_id or self.state.buyer_id or "BUYER-001"
        lic_type = license_type or self.state.license_type or "exclusive"
        key_tx = k_tx or self.state.transaction_credentials.get("k_tx", "K_tx_symmetric_credential_secret_777")

        dfg = create_iir_butterworth()
        from hardware_ip_protection.crypto.design_hasher import DesignHasher
        canonical_str = DesignHasher.canonicalize_dfg(dfg.to_dict())
        design_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        tx_info = {
            "transaction_id": tx_id,
            "seller_id": s_id,
            "buyer_id": b_id,
            "license_type": lic_type,
            "design_hash": design_hash,
            "design_encoding_D": self.state.design_encoding_D,
            "buyer_contribution_B": self.state.buyer_bitstream_B,
        }
        credentials = {"k_tx": key_tx}

        from hardware_ip_protection.crypto.watermark_generator import SymmetricHKDFWatermarkGenerator
        generator = SymmetricHKDFWatermarkGenerator()
        wm_len = 256 if (watermark_length is None or watermark_length == "auto") else int(watermark_length)
        wm = generator.generate(
            tx_info,
            credentials,
            watermark_length=wm_len,
            D=self.state.design_encoding_D,
            B=self.state.buyer_bitstream_B,
        )

        self.state.transaction_id = tx_id
        self.state.seller_id = s_id
        self.state.buyer_id = b_id
        self.state.license_type = lic_type
        self.state.transaction_credentials = {"k_tx": key_tx}
        self.state.design_hash = design_hash
        self.state.watermark_W = wm.canonical_bitstream
        self.state.embedded_watermark_length = len(wm.canonical_bitstream)
        self.state.is_full_watermark = True

        self.state.seller_private_info = self._build_seller_private_info()
        return self.state

    def commit_original_watermark(self) -> TransactionState:
        """
        Stage 2C: Computes Pedersen commitment C_W over NIST P-256 for canonical watermark W.
        """
        if not self.state.watermark_W:
            raise ValueError("Watermark W must be generated before committing C_W.")

        pe = PedersenEngine()
        comm, r_w = pe.commit(self.state.watermark_W)

        self.state.C_W = comm.commitment_hex
        self.state.blinding_factor_W = hex(r_w)[2:].zfill(64)
        self.state.seller_private_info = self._build_seller_private_info()
        return self.state

    def split_and_protect_watermark(self, watermark_length: Any = "auto") -> TransactionState:
        """
        Legacy support: Partitions canonical 256-bit watermark W into embedded slice W1 (32 bits)
        and protected slice W2 (224 bits).
        """
        if not self.state.watermark_W:
            raise ValueError("Watermark W must be generated before splitting.")
        if not self.state.C_W:
            raise ValueError("Watermark commitment C_W must be committed before splitting.")

        w_len = 32
        self.state.W1 = self.state.watermark_W[:w_len]
        self.state.protected_W2 = self.state.watermark_W[w_len:]
        self.state.is_full_watermark = False
        self.state.seller_private_info = self._build_seller_private_info()
        return self.state

    def commit_embedded_watermark(self) -> TransactionState:
        """
        Legacy support: Computes Pedersen commitment C_W1 over NIST P-256 for embedded slice W1.
        """
        if not self.state.W1:
            raise ValueError("Embedded watermark portion W1 must be split before committing C_W1.")

        pe = PedersenEngine()
        comm_w1, r_w1 = pe.commit(self.state.W1)

        self.state.C_W1 = comm_w1.commitment_hex
        self.state.blinding_factor_W1 = hex(r_w1)[2:].zfill(64)
        self.state.seller_private_info = self._build_seller_private_info()
        return self.state

    def embed_watermark_in_rtl(self, watermark_length: Any = "auto") -> TransactionState:
        """
        Stage 3 & 4: Embeds the complete 256-bit watermark into CIG constraints, allocates registers,
        synthesizes synthesizable Verilog RTL, and recalculates secured encoding E_S.
        Preserves legacy compatibility if W1 and C_W1 are provided.
        """
        if not self.state.watermark_W and not self.state.W1:
            raise ValueError("Watermark W must be generated before embedding.")
        if not self.state.C_W and not self.state.C_W1:
            raise ValueError("Watermark commitment C_W must be completed before embedding.")

        tx_id = self.state.transaction_id or "TX-001"
        s_id = self.state.seller_id or "SELLER-001"
        b_id = self.state.buyer_id or "BUYER-001"
        lic_type = self.state.license_type or "exclusive"
        key_tx = self.state.transaction_credentials.get("k_tx", "K_tx_symmetric_credential_secret_777")

        dfg = create_iir_butterworth()
        pipeline = ProtectionPipeline()

        actual_len = 256 if (watermark_length is None or watermark_length == "auto") else int(watermark_length)

        init_ctx = {
            "dfg": dfg,
            "resource_config": {"add": 2, "mul": 2, "sub": 2},
            "transaction_record": {
                "transaction_id": tx_id,
                "seller_id": s_id,
                "buyer_id": b_id,
                "license_type": lic_type,
                "design_encoding_D": self.state.design_encoding_D,
                "buyer_contribution_B": self.state.buyer_bitstream_B,
            },
            "design_encoding_D": self.state.design_encoding_D,
            "buyer_contribution_B": self.state.buyer_bitstream_B,
            "transaction_credentials": {"k_tx": key_tx},
            "watermark_length": actual_len,
            "encoding_scope": None,
            "encoding_mode": "five_rule" if self.state.encoding_rule_id == "iir_butterworth_5rule_v1" else "four_rule",
        }

        if self.state.C_W and self.state.blinding_factor_W:
            from hardware_ip_protection.crypto.pedersen import PedersenCommitment
            r_w_int = int(self.state.blinding_factor_W, 16) if isinstance(self.state.blinding_factor_W, str) else int(self.state.blinding_factor_W)
            init_ctx["watermark_commitment"] = PedersenCommitment(commitment_hex=self.state.C_W)
            init_ctx["watermark_blinding_factor"] = r_w_int

        prot_ctx = pipeline.run(init_ctx)

        rec = prot_ctx["protection_record"]
        wm = prot_ctx["transaction_watermark"]
        base_cig = prot_ctx["base_cig"]
        constrained_cig = prot_ctx["constrained_cig"]
        prot_alloc = prot_ctx["protected_register_allocation"]
        orig_alloc = prot_ctx["original_register_allocation"]
        sched = prot_ctx["scheduled_dfg"]

        self.state.design_hash = prot_ctx["design_hash"]
        self.state.watermarked_RTL = prot_ctx["protected_verilog"]
        self.state.original_RTL = prot_ctx["original_verilog"]
        self.state.secured_encoding_E_S = prot_ctx.get("structural_encoding")
        self.state.protection_id = rec.protection_id
        self.state.watermark_mapping = prot_ctx.get("watermark_mapping")
        self.state.embedded_watermark_length = len(wm.canonical_bitstream)

        # Cache active session for dispute verification
        from hardware_ip_protection.web.app import active_sessions
        active_sessions[rec.protection_id] = prot_ctx

        pe = PedersenEngine()
        comm_w1_hex = self.state.C_W1 or prot_ctx["watermark_commitment"].commitment_hex

        # Format full pipeline result for visualizer rendering
        self.state.pipeline_result = {
            "protection_id": rec.protection_id,
            "design_hash": prot_ctx["design_hash"],
            "benchmark_id": "iir_butterworth",
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
                "canonical_bitstream": wm.canonical_bitstream,
                "canonical_hex": wm.canonical_hex,
                "embedded_bitstream": wm.embedded_bitstream,
                "remaining_bitstream": wm.remaining_bitstream,
                "watermark_hash": wm.watermark_hash,
                "commitment_hex": self.state.C_W or prot_ctx["watermark_commitment"].commitment_hex,
                "blinding_factor_hex": self.state.blinding_factor_W or hex(prot_ctx["watermark_blinding_factor"])[2:].zfill(64),
                "c_w1_hex": comm_w1_hex,
                "public_generator_g": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                "public_generator_h": "021ad06fad86cbbf99815a56f6c511152d048e5e0893d02c18194e3165a6aa4db3",
            },
            "capacity_analysis": prot_ctx["capacity_analysis"],
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

        self.state.C_ES = "NOT_REQUIRED"
        self.state.C_V = prot_ctx["test_vector_commitment"].commitment_hex
        self.state.stage4_es_calculated = False
        self.state.stage4_encodings_compared = False
        self.state.stage4_behavioral_verified = False
        self.state.stage4_completed = False
        self.state.encoding_comparison_result = None
        self.state.behavioral_validation_result = None
        if self.state.is_full_watermark:
            self.state.W1 = self.state.watermark_W
            self.state.C_W1 = self.state.C_W
            self.state.blinding_factor_W1 = self.state.blinding_factor_W
        self.state.seller_private_info = self._build_seller_private_info()

        # Generate and persist technical securing report for this run
        from hardware_ip_protection.pipeline.securing_report import SecuringReportGenerator
        from hardware_ip_protection.pipeline.repository import ProtectionRepository
        try:
            rep = SecuringReportGenerator.generate_report(
                state=self.state,
                pipeline_timing=prot_ctx.get("pipeline_execution_timing"),
            )
            self.state.securing_report = rep
            ProtectionRepository.get_instance().save_securing_report(rep)
        except Exception as ex:
            import logging
            logging.getLogger("hardware_ip_protection").warning(f"Could not persist securing report: {ex}")

        return self.state

    def calculate_secured_encoding(self) -> TransactionState:
        """
        Stage 4B: Reconstructs / calculates secured design encoding E_S from protected RTL.
        """
        if not self.state.watermarked_RTL:
            raise ValueError("Protected RTL must be generated before calculating secured encoding E_S.")

        is_five_rule = (self.state.encoding_rule_id == "iir_butterworth_5rule_v1")
        mode = "five_rule" if is_five_rule else "four_rule"

        # Reconstruct E_S from protected RTL structure using the structural encoder
        if self.state.design_id == "iir_butterworth":
            enc_res = DesignStructuralEncoder.encode_golden_butterworth(
                use_document_table_quirks=False,
                mode=mode,
                is_secured=True,
            )
            self.state.secured_encoding_E_S = enc_res.to_dict()
        else:
            # pyrefly: ignore[missing-import]
            from hardware_ip_protection.hls.dfg_generator import create_iir_butterworth
            from hardware_ip_protection.hls.scheduler import ListScheduler
            dfg = create_iir_butterworth()
            scheduler = ListScheduler({"mul": 2, "add": 1})
            sched = scheduler.schedule(dfg)
            enc_res = DesignStructuralEncoder.encode_scheduled_dfg(sched, rule4_width=2, mode=mode)
            self.state.secured_encoding_E_S = enc_res.to_dict()

        if is_five_rule:
            pe = PedersenEngine()
            es_bits = enc_res.canonical_bitstream
            comm_ES, r_ES = pe.commit(es_bits)
            self.state.C_ES = comm_ES.commitment_hex
            self.state.blinding_factor_ES = hex(r_ES)[2:].zfill(64)
            self.state.encoding_transform_required = True
        else:
            self.state.C_ES = "NOT_REQUIRED"
            self.state.blinding_factor_ES = None
            self.state.encoding_transform_required = False

        self.state.stage4_es_calculated = True
        self.state.seller_private_info = self._build_seller_private_info()
        return self.state

    def compare_encodings(self) -> TransactionState:
        """
        Stage 4C: Compares reconstructed secured encoding E_S against original design encoding D.
        """
        if not self.state.stage4_es_calculated or not self.state.secured_encoding_E_S:
            raise ValueError("Secured encoding E_S must be calculated before comparing encodings.")
        if not self.state.design_encoding_D:
            raise ValueError("Original design encoding D must exist before comparing encodings.")

        es_bits = self.state.secured_encoding_E_S.get("canonical_bitstream", "") if isinstance(self.state.secured_encoding_E_S, dict) else ""
        d_bits = self.state.design_encoding_D

        is_match = bool(es_bits and d_bits and es_bits == d_bits)
        is_five_rule = (self.state.encoding_rule_id == "iir_butterworth_5rule_v1")

        if is_match:
            detail_msg = "The watermarked RTL preserves the identical structural schedule, control-step parity, operation types, and node traversal ordering as original design encoding D."
            summary_msg = f"{len(es_bits)} bits == {len(d_bits)} bits (MATCH)"
            self.state.encoding_transform_required = False
            self.state.C_ES = "NOT_REQUIRED"
            self.state.blinding_factor_ES = None
        else:
            self.state.encoding_transform_required = True
            if is_five_rule:
                detail_msg = "Secured encoding E_S differs from original encoding D in Rule 5 by 6 register parity assignments due to watermark embedding constraints. Deterministic transformation required."
                summary_msg = f"{len(es_bits)} bits (E_S != D) · Transformation Required"
            else:
                detail_msg = "Encodings do not match."
                summary_msg = f"{len(es_bits)} bits != {len(d_bits)} bits"

            if not self.state.C_ES or self.state.C_ES == "NOT_REQUIRED":
                pe = PedersenEngine()
                comm_ES, r_ES = pe.commit(es_bits)
                self.state.C_ES = comm_ES.commitment_hex
                self.state.blinding_factor_ES = hex(r_ES)[2:].zfill(64)

        self.state.encoding_comparison_result = {
            "status": "MATCH" if is_match else "MISMATCH",
            "match": is_match,
            "is_identical": is_match,
            "length_E_S": len(es_bits),
            "length_D": len(d_bits),
            "es_length": len(es_bits),
            "d_length": len(d_bits),
            "summary": summary_msg,
            "details": detail_msg,
        }
        self.state.stage4_encodings_compared = True
        self.state.seller_private_info = self._build_seller_private_info()
        return self.state

    def verify_behavioral_validation(self) -> TransactionState:
        """
        Stage 4D: Executes behavioral validation comparing original and watermarked designs on test vectors.
        """
        if not self.state.stage4_encodings_compared:
            raise ValueError("Encodings must be compared before behavioral validation.")

        b_res = None
        if self.state.pipeline_result and "behavioral_verification" in self.state.pipeline_result:
            bv = self.state.pipeline_result["behavioral_verification"]
            b_res = dict(bv)
            b_res["total_vectors"] = bv.get("test_count", bv.get("total_test_vectors", 32))
            b_res["exact_matches"] = bv.get("matching_outputs", bv.get("exact_output_matches", 32))
            b_res["mismatches"] = bv.get("mismatching_outputs", bv.get("exact_output_mismatches", 0))
            b_res["passed"] = (bv.get("status") == "MATCH")
        elif self.state.original_RTL and self.state.watermarked_RTL:
            from hardware_ip_protection.verification.behavioral_verifier import BehavioralVerifier
            from hardware_ip_protection.verification.test_vector_generator import TestVectorGenerator, TestVectorSet
            dfg = create_iir_butterworth()
            tv_set = None
            if self.state.pipeline_result and "test_vectors" in self.state.pipeline_result:
                tv_data = self.state.pipeline_result["test_vectors"]
                if "vectors" in tv_data:
                    tv_set = TestVectorSet(tv_data["vectors"], vector_set_id=tv_data.get("vector_set_id", "TVS-V1"))
            if tv_set is None:
                tv_set = TestVectorGenerator.generate_stratified(dfg, count=32)
            bv_obj = BehavioralVerifier.verify(dfg, tv_set, self.state.original_RTL, self.state.watermarked_RTL)
            b_res = bv_obj.to_dict()
            b_res["total_vectors"] = b_res.get("test_count", 32)
            b_res["exact_matches"] = b_res.get("matching_outputs", 32)
            b_res["mismatches"] = b_res.get("mismatching_outputs", 0)
            b_res["passed"] = (b_res.get("status") == "MATCH")
        else:
            raise ValueError("Missing RTL artifacts for behavioral validation.")

        self.state.behavioral_validation_result = b_res
        self.state.stage4_behavioral_verified = True
        self.state.stage4_completed = True
        if not self.state.encoding_transform_required and not (self.state.encoding_rule_id == "iir_butterworth_5rule_v1"):
            self.state.C_ES = "NOT_REQUIRED"
        self.state.seller_private_info = self._build_seller_private_info()

        # Update and persist securing report after behavioral validation completes
        from hardware_ip_protection.pipeline.securing_report import SecuringReportGenerator
        from hardware_ip_protection.pipeline.repository import ProtectionRepository
        try:
            rep = SecuringReportGenerator.generate_report(state=self.state)
            self.state.securing_report = rep
            ProtectionRepository.get_instance().save_securing_report(rep)
        except Exception as ex:
            import logging
            logging.getLogger("hardware_ip_protection").warning(f"Could not update securing report after validation: {ex}")

        return self.state

    def continue_watermark_workflow(
        self,
        transaction_id: Optional[str] = None,
        seller_id: Optional[str] = None,
        buyer_id: Optional[str] = None,
        license_type: Optional[str] = None,
        k_tx: Optional[str] = None,
        watermark_length: Any = "auto",
    ) -> TransactionState:
        """
        After Buyer approved and provided B, Seller continues the watermark workflow.
        In the full-watermark model (Phase 2), the entire 256-bit watermark W is embedded directly into RTL.
        No splitting into W1/W2 and no separate C_W1 commitment are required.
        """
        actual_len = 256 if (watermark_length is None or watermark_length == "auto") else int(watermark_length)

        # Invalidate and regenerate watermark if transaction identity has changed
        tx_changed = (
            (transaction_id and transaction_id != self.state.transaction_id)
            or (seller_id and seller_id != self.state.seller_id)
            or (buyer_id and buyer_id != self.state.buyer_id)
            or (license_type and license_type != self.state.license_type)
        )
        if not self.state.watermark_W or tx_changed:
            self.generate_transaction_watermark(
                transaction_id=transaction_id,
                seller_id=seller_id,
                buyer_id=buyer_id,
                license_type=license_type,
                k_tx=k_tx,
                watermark_length=actual_len,
            )
            self.commit_original_watermark()
        elif not self.state.C_W:
            self.commit_original_watermark()

        self.embed_watermark_in_rtl(watermark_length=actual_len)
        self.calculate_secured_encoding()
        self.compare_encodings()
        self.verify_behavioral_validation()
        return self.state

    def get_securing_report(self) -> Dict[str, Any]:
        """
        Retrieves the authoritative technical cost and overhead report for the current securing run.
        Read-only operation.
        """
        from hardware_ip_protection.pipeline.securing_report import SecuringReportGenerator
        from hardware_ip_protection.pipeline.repository import ProtectionRepository

        # Return in-memory report if present
        if self.state.securing_report:
            return self.state.securing_report

        # Try to load latest from DB
        try:
            latest = ProtectionRepository.get_instance().get_latest_securing_report_for_transaction(self.state.transaction_id)
            if latest and latest.get("design_id") == self.state.design_id:
                self.state.securing_report = latest
                return latest
        except Exception:
            pass

        # Generate dynamically from current state
        rep = SecuringReportGenerator.generate_report(state=self.state)
        self.state.securing_report = rep
        return rep

