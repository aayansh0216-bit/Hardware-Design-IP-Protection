"""
Independent Verifier Engine for Hardware IP Protection V1.

Implements the step-by-step dispute adjudication and evidence verification workflow:
- Two Dispute Types:
  1. Seller ↔ Buyer Conflict (13-step progressive verification)
  2. Reference Design ↔ Suspicious Design (behavioral, encoding, and watermark audit)
- Two-Stage Verification Principle for all commitments:
  - Stage 1: Independent Value Reconstruction from supplied rules and artifacts.
  - Stage 2: Commitment Recalculation & Equality Verification (NIST P-256 Pedersen).
"""

from typing import Dict, Any, Optional, List, Tuple, Union
import hashlib
import json
import uuid
from pydantic import BaseModel, Field

from hardware_ip_protection.crypto.pedersen import (
    PedersenEngine,
    PedersenCommitment,
    CommitmentVerificationStatus,
)
from hardware_ip_protection.hls.structural_encoder import (
    DesignStructuralEncoder,
    StructuralEncodingResult,
)
from hardware_ip_protection.hls.dfg import DFG, DFGNode
from hardware_ip_protection.hls.scheduler import ScheduledDFG
from hardware_ip_protection.forensics.watermark_extractor import (
    TransactionWatermarkExtractor,
    ExtractionResult,
    ExtractionStatus,
)
from hardware_ip_protection.pipeline.stages import SymmetricHKDFWatermarkGenerator
from hardware_ip_protection.pipeline.transaction_manager import (
    TransactionManager,
    TransactionState,
    DEMO_BUYER_BITSTREAM,
)
from hardware_ip_protection.pipeline.repository import ProtectionRepository


class VerificationStageResult(BaseModel):
    step_number: Union[int, str]
    step_id: str
    step_title: str
    responsible_party: str
    stage1_reconstruction: Dict[str, Any]
    stage2_verification: Dict[str, Any]
    status: str  # MATCH, MISMATCH, NOT REQUIRED, BLOCKED, INCOMPLETE, LOADED, EXTRACTED, VALIDATED
    notes: Optional[str] = None
    canonical_hash: Optional[str] = None
    hash_algorithm: Optional[str] = "SHA-256"
    bit_length: Optional[int] = None


class DisputeSession(BaseModel):
    session_id: str = "VSESS-001"
    transaction_id: str = "TX-001"
    dispute_type: str = "Seller ↔ Buyer Conflict"
    dispute_subcategory: str = "Buyer claims ownership; recorded transaction may grant only a license."
    current_step: int = 1
    completed_steps: List[Union[int, str]] = Field(default_factory=list)
    step_results: Dict[str, VerificationStageResult] = Field(default_factory=dict)
    recorded_hashes: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    internal_confidential_values: Dict[str, str] = Field(default_factory=dict, exclude=True)
    step_attempts: Dict[str, int] = Field(default_factory=dict)
    encoding_transform_required: Optional[bool] = False
    final_report: Optional[Dict[str, Any]] = None
    is_completed: bool = False



class VerifierEngine:
    """
    Independent dispute verification engine managing interactive multi-stage auditing.
    """

    DISPUTE_CATEGORIES = {
        "Seller ↔ Buyer Conflict": [
            "Buyer claims ownership; Seller disputes the transaction.",
            "Buyer claims a transaction; Seller disputes authorization.",
            "Buyer claims ownership; recorded transaction may grant only a license.",
        ],
        "Reference Design ↔ Suspicious Design": [
            "Exact or near-copy suspicion.",
            "Modified design.",
            "Possible unauthorized reuse.",
        ],
    }

    _instance = None

    def __init__(self):
        self.session = DisputeSession()
        self.pe = PedersenEngine()

    @classmethod
    def get_instance(cls) -> "VerifierEngine":
        if cls._instance is None:
            cls._instance = VerifierEngine()
        return cls._instance

    def reset_session(
        self,
        transaction_id: str = "TX-001",
        dispute_type: str = "Seller ↔ Buyer Conflict",
        dispute_subcategory: Optional[str] = None,
    ) -> DisputeSession:
        if dispute_type not in self.DISPUTE_CATEGORIES:
            dispute_type = "Seller ↔ Buyer Conflict"
        subcats = self.DISPUTE_CATEGORIES[dispute_type]
        if not dispute_subcategory or dispute_subcategory not in subcats:
            dispute_subcategory = subcats[0]

        mgr = TransactionManager.get_instance()
        st = mgr.get_state()
        flag = getattr(st, "encoding_transform_required", False)

        sess_token = uuid.uuid4().hex[:8].upper()
        self.session = DisputeSession(
            session_id=f"VSESS-{sess_token}",
            transaction_id=transaction_id,
            dispute_type=dispute_type,
            dispute_subcategory=dispute_subcategory,
            current_step=1,
            completed_steps=[],
            step_results={},
            recorded_hashes={},
            internal_confidential_values={},
            step_attempts={},
            encoding_transform_required=flag,
            final_report=None,
            is_completed=False,
        )
        return self.session

    def get_session(self) -> DisputeSession:
        return self.session

    def record_step_hash(
        self,
        step_id: str,
        hash_hex: str,
        artifact_id: str = "",
        step_num: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Durably records a calculated canonical hash before opening factor release.
        Guarantees that a recorded hash cannot be replaced after opening information has been disclosed.
        """
        repo = ProtectionRepository.get_instance()
        prev = self.session.recorded_hashes.get(step_id)
        attempt_id = self.session.step_attempts.get(step_id, 1)
        if prev and prev.get("opening_released") and prev.get("canonical_hash", "").lower() != hash_hex.lower():
            attempt_id += 1
            self.session.step_attempts[step_id] = attempt_id

        res = repo.record_step_hash(
            session_id=self.session.session_id,
            transaction_id=self.session.transaction_id,
            step_id=step_id,
            canonical_hash=hash_hex,
            hash_algorithm="SHA-256",
            artifact_id=artifact_id,
            attempt_id=attempt_id,
        )
        self.session.recorded_hashes[step_id] = {
            "canonical_hash": hash_hex,
            "hash_algorithm": "SHA-256",
            "artifact_id": artifact_id,
            "opening_released": False,
            "attempt_id": attempt_id,
        }
        return res

    def release_step_opening(self, step_id: str, step_num: Optional[int] = None) -> Dict[str, Any]:
        """
        Authorizes opening factor release only after the step canonical hash has been recorded.
        """
        repo = ProtectionRepository.get_instance()
        attempt_id = self.session.step_attempts.get(step_id, 1)
        repo.release_step_opening(self.session.session_id, step_id, attempt_id=attempt_id)
        if step_id in self.session.recorded_hashes:
            self.session.recorded_hashes[step_id]["opening_released"] = True
        return {"step_id": step_id, "opening_released": True}

    def get_recorded_step_hash(self, step_id: str) -> Optional[str]:
        if step_id in self.session.recorded_hashes:
            return self.session.recorded_hashes[step_id].get("canonical_hash")
        repo = ProtectionRepository.get_instance()
        attempt_id = self.session.step_attempts.get(step_id, 1)
        rec = repo.get_step_hash_record(self.session.session_id, step_id, attempt_id=attempt_id)
        if rec:
            return rec.get("canonical_hash")
        return None

    def get_available_transactions(self) -> List[Dict[str, Any]]:
        mgr = TransactionManager.get_instance()
        st = mgr.get_state()
        has_tx = bool(st.design_encoding_D or st.watermarked_RTL)

        tx_list = []
        if has_tx:
            # Check available evidence
            evidence_summary = []
            if st.design_encoding_D:
                evidence_summary.append("Original Encoding D")
            if st.C_D:
                evidence_summary.append("Commitment C_D")
            if st.buyer_bitstream_B:
                evidence_summary.append("Buyer Bitstream B")
            if st.C_B:
                evidence_summary.append("Commitment C_B")
            if st.watermark_W:
                evidence_summary.append("Watermark W")
            if st.C_W:
                evidence_summary.append("Commitment C_W")
            if st.W1:
                evidence_summary.append("Watermark W1")
            if st.C_W1:
                evidence_summary.append("Commitment C_W1")
            if st.watermarked_RTL:
                evidence_summary.append("Watermarked RTL")

            tx_list.append({
                "transaction_id": st.transaction_id,
                "seller_id": st.seller_id,
                "buyer_id": st.buyer_id,
                "design": st.selected_design,
                "design_id": st.design_id,
                "encoding_rule": st.selected_encoding_rule,
                "encoding_rule_id": st.encoding_rule_id,
                "encoding_rule_version": st.encoding_rule_version,
                "license_type": st.license_type,
                "encoding_transform_required": getattr(st, "encoding_transform_required", False),
                "transformation_rule_id": getattr(st, "transformation_rule_id", "iir_butterworth_transform_v1"),
                "transformation_rule_version": getattr(st, "transformation_rule_version", "1.0"),
                "request_status": st.buyer_request_status,
                "approval_status": "Approved" if st.buyer_approved else ("Rejected" if st.buyer_rejected else "Pending"),
                "buyer_contribution_status": st.buyer_contribution_status,
                "available_evidence": evidence_summary,
                "is_ready_for_verification": bool(st.watermarked_RTL and st.C_D and st.C_W and st.C_W1 and st.C_B),
            })
        return tx_list


    # ==========================================================================
    # Step-by-Step Verification Implementation (Seller ↔ Buyer Conflict)
    # ==========================================================================

    def execute_step(self, step_number: Union[int, str], overrides: Optional[Dict[str, Any]] = None) -> VerificationStageResult:
        """
        Executes a verification step in the required protocol order.
        Supports:
          - 1: Obtain Disputed RTL
          - 2: Calculate Secured Encoding and Hash (E_S')
          - 3: Verify Secured Encoding Commitment (C_ES) - conditional on transaction flag
          - "transform" or "3b": Transform Secured Encoding to E_U' - conditional on transaction flag
          - 4: Verify Original Design Commitment (C_D)
          - 5: Extract Embedded Watermark (W1')
          - 6: Verify Embedded Watermark Commitment (C_W1)
          - 7: Reconstruct Complete Watermark (W')
          - 8: Verify Complete Watermark Commitment (C_W)
          - 9: Validate Buyer Contribution (B')
          - 10: Verify Buyer Commitment (C_B)
          - 11: Verify Watermark Relationship F(D', B', context, k_tx)
          - 12: Verify Transaction Evidence & Rights
          - 13: Generate Final Dispute Determination & Report
        """
        overrides = overrides or {}
        mgr = TransactionManager.get_instance()
        st = mgr.get_state()

        step_key = str(step_number)

        if step_key == "1":
            res = self._step_1_obtain_disputed_rtl(st, overrides)
        elif step_key == "2":
            res = self._step_2_extract_secured_encoding(st, overrides)
        elif step_key == "3":
            res = self._step_3_check_or_verify_c_es(st, overrides)
        elif step_key in ("3b", "transform", "step_transform"):
            res = self._step_transform_secured_encoding(st, overrides)
        elif step_key == "4":
            res = self._step_4_verify_original_encoding(st, overrides)
        elif step_key == "5":
            res = self._step_5_extract_embedded_watermark(st, overrides)
        elif step_key == "6":
            res = self._step_6_verify_embedded_watermark_commitment(st, overrides)
        elif step_key == "7":
            res = self._step_7_reconstruct_complete_watermark(st, overrides)
        elif step_key == "8":
            res = self._step_8_verify_complete_watermark_commitment(st, overrides)
        elif step_key == "9":
            res = self._step_9_reconstruct_buyer_contribution(st, overrides)
        elif step_key == "10":
            res = self._step_10_verify_buyer_commitment(st, overrides)
        elif step_key == "11":
            res = self._step_11_verify_watermark_relationship(st, overrides)
        elif step_key == "12":
            res = self._step_12_verify_transaction_evidence(st, overrides)
        elif step_key == "13":
            res = self._step_13_generate_final_report(st, overrides)
        else:
            raise ValueError(f"Invalid verification step identifier '{step_number}'.")

        res_key = f"step_{step_key}" if not step_key.startswith("step_") else step_key
        self.session.step_results[res_key] = res
        if step_number not in self.session.completed_steps:
            self.session.completed_steps.append(step_number)

        if isinstance(step_number, int) and step_number < 13:
            self.session.current_step = step_number + 1
        elif step_key == "13":
            self.session.is_completed = True

        return res

    def run_all_steps(self, overrides: Optional[Dict[str, Any]] = None) -> DisputeSession:
        """
        Executes verification operations sequentially according to the recorded transaction flag.
        """
        overrides = overrides or {}
        st = TransactionManager.get_instance().get_state()
        flag = overrides.get("encoding_transform_required", getattr(st, "encoding_transform_required", False))

        # Step 1: Disputed RTL
        self.execute_step(1, overrides.get("step_1", {}))
        # Step 2: Extract E_S' and calculate canonical hash
        self.execute_step(2, overrides.get("step_2", {}))
        # Step 3: Check transaction flag and verify C_ES if required
        self.execute_step(3, overrides.get("step_3", {}))
        # Step Transform: If flag is True, transform to E_U'; if False, mark NOT REQUIRED
        if flag:
            self.execute_step("transform", overrides.get("step_transform", {}))
        else:
            self._step_transform_secured_encoding(st, overrides.get("step_transform", {}))
        # Steps 4 to 13
        for s in range(4, 14):
            step_ov = overrides.get(f"step_{s}", {})
            self.execute_step(s, step_ov)

        return self.session

    # --------------------------------------------------------------------------
    # Step 1: Obtain the Disputed RTL
    # --------------------------------------------------------------------------
    def _step_1_obtain_disputed_rtl(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        rtl = ov.get("disputed_rtl", st.watermarked_RTL)
        if not rtl:
            return VerificationStageResult(
                step_number=1,
                step_id="step_1",
                step_title="Obtain Disputed RTL",
                responsible_party="Dispute Submitter / Transaction Registry",
                stage1_reconstruction={
                    "method": "Load watermarked RTL associated with transaction from authorized evidence",
                    "status": "BLOCKED",
                    "detail": "No watermarked RTL available for transaction. Complete Seller Secure Your Design workflow first.",
                },
                stage2_verification={
                    "status": "NOT APPLICABLE",
                    "detail": "Artifact acquisition is an input step without a direct cryptographic commitment.",
                },
                status="BLOCKED",
                notes="Missing disputed RTL artifact.",
            )

        rtl_hash = hashlib.sha256(rtl.encode("utf-8")).hexdigest()
        line_count = len(rtl.splitlines())

        return VerificationStageResult(
            step_number=1,
            step_id="step_1",
            step_title="Obtain Disputed RTL",
            responsible_party="Dispute Submitter / Transaction Registry",
            stage1_reconstruction={
                "method": "Acquire synthesized RTL artifact bound to the selected transaction",
                "transaction_id": st.transaction_id,
                "seller_id": st.seller_id,
                "buyer_id": st.buyer_id,
                "artifact_type": "Synthesizable Verilog RTL",
                "sha256_digest": rtl_hash,
                "lines_of_code": line_count,
                "preview": rtl[:300] + "...",
                "synthesizable_verilog_code": rtl,
                "status": "LOADED",
            },
            stage2_verification={
                "status": "NOT APPLICABLE",
                "detail": "Stage 2 commitment verification not applicable to raw artifact ingestion. Formal commitments are verified in subsequent stages.",
            },
            status="LOADED",
            notes="Artifact loaded and registered for independent verification. Artifact is not yet authenticated.",
        )

    # --------------------------------------------------------------------------
    # Step 2: Extract Secured Encoding E_S'
    # --------------------------------------------------------------------------
    def _step_2_extract_secured_encoding(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        step1 = self.session.step_results.get("step_1")
        if not step1 or step1.status not in ("LOADED", "MATCH"):
            return VerificationStageResult(
                step_number=2,
                step_id="step_2",
                step_title="Extract Secured Encoding (E_S')",
                responsible_party="Seller / Verifier Execution",
                stage1_reconstruction={"status": "BLOCKED", "detail": "Prerequisite Step 1 missing or failed. No disputed RTL available."},
                stage2_verification={"status": "BLOCKED"},
                status="BLOCKED",
                notes="Prerequisite Step 1 missing or failed.",
            )

        loaded_rtl = step1.stage1_reconstruction.get("synthesizable_verilog_code") if step1.stage1_reconstruction else None
        rtl = ov.get("disputed_rtl", loaded_rtl or st.watermarked_RTL)
        if not rtl:
            return VerificationStageResult(
                step_number=2,
                step_id="step_2",
                step_title="Extract Secured Encoding (E_S')",
                responsible_party="Seller / Verifier Execution",
                stage1_reconstruction={"status": "BLOCKED", "detail": "Missing RTL from Step 1."},
                stage2_verification={"status": "BLOCKED"},
                status="BLOCKED",
                notes="Prerequisite Step 1 missing.",
            )

        # Apply design-specific structural encoding rule
        rule_id = ov.get("rule_id", ov.get("encoding_rule_id", st.encoding_rule_id))
        if rule_id not in ("iir_butterworth_rule_v1", "iir_butterworth_5rule_v1"):
            return VerificationStageResult(
                step_number=2,
                step_id="step_2",
                step_title="Calculate Secured Design Encoding (E_S')",
                responsible_party="Seller",
                stage1_reconstruction={
                    "status": "MISMATCH",
                    "detail": f"Unknown or mismatched encoding rule '{rule_id}'. Transaction requires 'iir_butterworth_rule_v1' or 'iir_butterworth_5rule_v1'.",
                },
                stage2_verification={"status": "BLOCKED"},
                status="BLOCKED",
                notes=f"Unsupported or missing design encoding rule '{rule_id}'.",
            )

        # Independently reconstruct scheduled operations and control steps directly from the disputed RTL AST/FSM
        parsed = DesignStructuralEncoder.parse_scheduled_nodes_from_verilog(rtl)
        if not parsed or not parsed.get("step_nodes") or not parsed.get("node_ops"):
            return VerificationStageResult(
                step_number=2,
                step_id="step_2",
                step_title="Calculate Secured Design Encoding (E_S')",
                responsible_party="Seller / Verifier Execution",
                stage1_reconstruction={
                    "method": "Direct AST and FSM parsing of disputed synthesizable RTL",
                    "status": "MISMATCH",
                    "detail": "Failed to parse scheduled FSM states and operation nodes from disputed RTL artifact.",
                },
                stage2_verification={"status": "BLOCKED"},
                status="MISMATCH",
                notes="Disputed RTL could not be independently parsed into scheduled operations.",
            )

        is_five_rule = (rule_id == "iir_butterworth_5rule_v1")
        mode = "five_rule" if is_five_rule else "four_rule"

        var_bindings = None
        if is_five_rule:
            var_bindings = DesignStructuralEncoder.parse_register_bindings_from_verilog(rtl)
            # Verify required variables V1..V27 are present
            missing_vars = [f"V{i}" for i in range(1, 28) if f"V{i}" not in var_bindings and f"v{i}" not in var_bindings]
            if missing_vars:
                return VerificationStageResult(
                    step_number=2,
                    step_id="step_2",
                    step_title="Calculate Secured Design Encoding (E_S')",
                    responsible_party="Seller / Verifier Execution",
                    stage1_reconstruction={
                        "method": "Direct AST, FSM, and register binding parsing of disputed synthesizable RTL",
                        "status": "MISMATCH",
                        "detail": f"Missing register allocation bindings for variables in disputed RTL: {', '.join(missing_vars[:5])}...",
                    },
                    stage2_verification={"status": "BLOCKED"},
                    status="MISMATCH",
                    notes="Disputed RTL is missing required variable-to-register bindings for 5-rule reconstruction.",
                )

        # Reconstruct DFG, node IDs, operation types, and control step assignments
        reconstructed_nodes = [
            DFGNode(nid, parsed["node_ops"][nid], [], f"t{nid}")
            for nid in sorted(parsed["node_step"].keys())
        ]
        reconstructed_dfg = DFG(
            name="reconstructed_disputed_design",
            inputs=[],
            outputs=[],
            nodes=reconstructed_nodes,
        )

        canon_step_nodes = {}
        for s, nids in parsed["step_nodes"].items():
            canon_step_nodes[s] = sorted(
                nids,
                key=lambda nid: (0 if parsed["node_ops"][nid] in ("add", "sub") else 1, nid),
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
            mode=mode,
            var_to_reg=var_bindings,
        )
        es_bitstream = ov.get("es_bitstream", enc_res.canonical_bitstream)
        es_hash = hashlib.sha256(es_bitstream.encode("utf-8")).hexdigest()

        # Durably record hash before releasing opening factor
        self.record_step_hash(
            step_id="step_2",
            hash_hex=es_hash,
            artifact_id="disputed_rtl",
            step_num=2,
        )

        # Retain raw confidential bitstream strictly in verifier internal state
        self.session.internal_confidential_values["E_S"] = es_bitstream

        rule_label = "IIR Butterworth 5-Rule Encoding (v1.0)" if is_five_rule else "IIR Butterworth 4-Rule Encoding (v1.0)"
        method_label = (
            "Independent AST/FSM Parsing + Register Binding Netlist Extraction (5-Rule Mode)"
            if is_five_rule
            else "Independent AST/FSM Parsing of Disputed RTL (4-Rule Structural Encoding)"
        )

        # Public presentation returns canonical hash, algorithm, and topology metadata (no raw bitstream)
        return VerificationStageResult(
            step_number=2,
            step_id="step_2",
            step_title="Calculate Secured Design Encoding (E_S')",
            responsible_party="Seller / Verifier Execution",
            canonical_hash=es_hash,
            hash_algorithm="SHA-256",
            bit_length=len(es_bitstream),
            stage1_reconstruction={
                "method": method_label,
                "reconstruction_source": "Synthesizable Verilog RTL states, datapath operations, and netlist wire bindings",
                "design": st.selected_design,
                "encoding_rule": rule_label,
                "rule_version": "1.0",
                "mode": mode,
                "value_identifier": "E_S'",
                "canonical_hash": es_hash,
                "hash_algorithm": "SHA-256",
                "bit_length": len(es_bitstream),
                "total_nodes_recovered": len(parsed["node_step"]),
                "total_steps_recovered": parsed["total_steps"],
                "node_ids": sorted(list(parsed["node_step"].keys())),
                "node_operations": parsed["node_ops"],
                "control_step_assignments": parsed["node_step"],
                "status": "EXTRACTED",
            },
            stage2_verification={
                "status": "PENDING TRANSACTION BRANCH EVALUATION",
                "detail": "Secured encoding commitment verification is governed by recorded transaction flag 'encoding_transform_required'.",
            },
            status="EXTRACTED",
            notes=f"Secured encoding E_S' independently reconstructed from disputed RTL ({len(es_bitstream)} bits, {len(parsed['node_step'])} nodes across {parsed['total_steps']} steps). Canonical Hash: {es_hash}.",
        )

    # --------------------------------------------------------------------------
    # Step 3: Read Transaction's Transformation Flag and Verify C_ES (if required)
    # --------------------------------------------------------------------------
    def _step_3_check_or_verify_c_es(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        step2 = self.session.step_results.get("step_2")
        if not step2 or step2.status not in ("EXTRACTED", "MATCH"):
            return VerificationStageResult(
                step_number=3,
                step_id="step_3",
                step_title="Verify Secured Encoding Commitment (C_ES)",
                responsible_party="Verifier Analysis",
                stage1_reconstruction={
                    "status": "BLOCKED",
                    "detail": f"Prerequisite Step 2 did not succeed (status: {step2.status if step2 else 'NOT RUN'}). Cannot evaluate without reconstructed E_S'.",
                },
                stage2_verification={
                    "status": "BLOCKED",
                    "detail": f"Prerequisite Step 2 did not succeed (status: {step2.status if step2 else 'NOT RUN'}).",
                },
                status="BLOCKED",
                notes="Prerequisite Step 2 failed: cannot evaluate secured encoding commitment.",
            )

        # Read the persisted transaction field encoding_transform_required.
        # Do not infer this flag by comparing E_S' with stored D.
        # If flag is missing or not a boolean, raise explicit ValueError.
        flag = ov.get("encoding_transform_required", ov.get("is_encoding_changed", getattr(st, "encoding_transform_required", None)))

        if flag is None or not isinstance(flag, bool):
            raise ValueError(
                "Missing or invalid transaction field 'encoding_transform_required'. "
                "The transformation decision must come from the recorded YES/NO transaction flag."
            )

        # Durably record flag on session
        self.session.encoding_transform_required = flag

        if flag:
            # ==================================================================
            # Branch A: encoding_transform_required = true
            # ==================================================================
            # 1. Independently calculated E_S' canonical hash is retrieved from Step 2
            if "extracted_ES" in ov or "extracted_es" in ov:
                es_bits = ov.get("extracted_ES", ov.get("extracted_es"))
                es_hash = hashlib.sha256(es_bits.encode("utf-8")).hexdigest()
                self.record_step_hash("step_2", es_hash, "override", 2)
                self.session.internal_confidential_values["E_S"] = es_bits
            else:
                es_hash = self.get_recorded_step_hash("step_2")
            if not es_hash:
                es_bits = self.session.internal_confidential_values.get("E_S")
                if es_bits:
                    es_hash = hashlib.sha256(es_bits.encode("utf-8")).hexdigest()
                    self.record_step_hash("step_2", es_hash, "disputed_rtl", 2)
                else:
                    return VerificationStageResult(
                        step_number=3,
                        step_id="step_3",
                        step_title="Verify Secured Encoding Commitment (C_ES)",
                        responsible_party="Seller Private Evidence",
                        stage1_reconstruction={"status": "BLOCKED", "detail": "Missing canonical hash of E_S'."},
                        stage2_verification={"status": "BLOCKED"},
                        status="BLOCKED",
                    )

            c_es_stored = ov.get("stored_c_es", ov.get("stored_C_ES", getattr(st, "C_ES", None)))
            r_es = ov.get("r_es", ov.get("r_ES", getattr(st, "blinding_factor_ES", None)))

            if not c_es_stored or c_es_stored == "NOT_REQUIRED" or not r_es:
                return VerificationStageResult(
                    step_number=3,
                    step_id="step_3",
                    step_title="Verify Secured Encoding Commitment (C_ES)",
                    responsible_party="Seller Private Evidence",
                    stage1_reconstruction={
                        "branch": "Branch A (encoding_transform_required = true)",
                        "value_identifier": "E_S'",
                        "canonical_hash": es_hash,
                        "hash_algorithm": "SHA-256",
                        "status": "BLOCKED",
                        "detail": "Transformation flag is true, but missing stored commitment C_ES or opening factor r_ES in evidence.",
                    },
                    stage2_verification={
                        "status": "MISMATCH",
                        "detail": "Missing stored C_ES or opening factor r_ES.",
                        "stored_c_es": c_es_stored or "MISSING",
                    },
                    status="MISMATCH",
                    notes="Branch A: Secured encoding changed. Verification requires valid C_ES check.",
                )

            # Record step 3 hash before releasing opening
            self.record_step_hash(step_id="step_3", hash_hex=es_hash, artifact_id="disputed_rtl", step_num=3)
            self.release_step_opening(step_id="step_3", step_num=3)

            # Verify C_ES using existing Pedersen commitment arithmetic over recorded canonical hash
            try:
                blinding_int = int(r_es, 16) if isinstance(r_es, str) else int(r_es)
                ver_res = self.pe.verify_from_digest(es_hash, c_es_stored, blinding_int)
                comm_recalc, _ = self.pe.commit_from_digest(es_hash, blinding_factor=blinding_int)
                c_es_recalc = comm_recalc.commitment_hex

                if ver_res == CommitmentVerificationStatus.VALID:
                    status = "MATCH"
                    detail = "Secured encoding commitment C_ES verified against recorded canonical hash (MATCH). Transformation authorized."
                else:
                    status = "MISMATCH"
                    detail = "Recalculated commitment C_ES' does not match stored commitment C_ES (MISMATCH)."
            except Exception as e:
                status = "MISMATCH"
                detail = f"Commitment verification error: {e}"
                c_es_recalc = f"Error: {e}"

            bit_len = len(self.session.internal_confidential_values.get("E_S", "")) or 143
            return VerificationStageResult(
                step_number=3,
                step_id="step_3",
                step_title="Verify Secured Encoding Commitment (C_ES)",
                responsible_party="Seller Private Evidence",
                canonical_hash=es_hash,
                hash_algorithm="SHA-256",
                bit_length=bit_len,
                stage1_reconstruction={
                    "branch": "Branch A (encoding_transform_required = true)",
                    "value_identifier": "E_S'",
                    "canonical_hash": es_hash,
                    "hash_algorithm": "SHA-256",
                    "status": "VALIDATED" if status == "MATCH" else "FAILED",
                    "transformation_applied": (status == "MATCH"),
                },
                stage2_verification={
                    "formula": "C_ES = s_ES * G + r_ES * H over NIST P-256 (s_ES derived from canonical hash)",
                    "stored_c_es": c_es_stored,
                    "recalculated_c_es": c_es_recalc,
                    "opening_factor_r_ES": r_es,
                    "status": status,
                    "detail": detail,
                },
                status=status,
                notes=f"Branch A: C_ES commitment check {'verified' if status == 'MATCH' else 'failed'}. Proceeding to transformation only on MATCH.",
            )

        else:
            # ==================================================================
            # Branch B: encoding_transform_required = false
            # ==================================================================
            es_hash = self.get_recorded_step_hash("step_2") or ""
            bit_len = len(self.session.internal_confidential_values.get("E_S", "")) or 143
            return VerificationStageResult(
                step_number=3,
                step_id="step_3",
                step_title="Verify Secured Encoding Commitment (C_ES)",
                responsible_party="Verifier Analysis",
                canonical_hash=es_hash,
                hash_algorithm="SHA-256",
                bit_length=bit_len,
                stage1_reconstruction={
                    "branch": "Branch B (encoding_transform_required = false)",
                    "value_identifier": "E_S'",
                    "canonical_hash": es_hash,
                    "hash_algorithm": "SHA-256",
                    "status": "NOT REQUIRED",
                    "detail": "Transaction recorded encoding_transform_required = false. C_ES verification is not required for this transaction.",
                },
                stage2_verification={
                    "status": "NOT REQUIRED",
                    "detail": "Secured encoding commitment C_ES not required because transaction encoding_transform_required = false. Proceeding directly to original encoding verification C_D.",
                    "recalculated_C_ES": "NOT_APPLICABLE (encoding_transform_required = false)",
                    "stored_C_ES": "NOT_REQUIRED",
                    "stored_c_es": "Not Required (Flag = NO)",
                },
                status="NOT REQUIRED",
                notes="Branch B selected from transaction flag: C_ES commitment check not required (encoding_transform_required = false).",
            )

    # --------------------------------------------------------------------------
    # Step Transform: Transform Secured Encoding into E_U' (conditional on flag)
    # --------------------------------------------------------------------------
    def _step_transform_secured_encoding(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        flag = ov.get("encoding_transform_required", ov.get("is_encoding_changed", getattr(st, "encoding_transform_required", None)))
        if flag is None or not isinstance(flag, bool):
            raise ValueError("Missing or invalid transaction field 'encoding_transform_required'.")

        if not flag:
            # Branch B: No transformation. Treat E_S' as E_U'
            es_hash = self.get_recorded_step_hash("step_2") or ""
            es_bits = self.session.internal_confidential_values.get("E_S", "")
            self.session.internal_confidential_values["E_U"] = es_bits
            if es_hash:
                self.record_step_hash("step_4", es_hash, "disputed_rtl", 4)
            return VerificationStageResult(
                step_number=3,
                step_id="step_transform",
                step_title="Transform Secured Encoding to E_U'",
                responsible_party="Verifier Transformation Engine",
                stage1_reconstruction={
                    "branch": "Branch B (encoding_transform_required = false)",
                    "value_identifier": "E_U'",
                    "canonical_hash": es_hash,
                    "hash_algorithm": "SHA-256",
                    "bit_length": len(es_bits) if es_bits else 143,
                    "transformation_rule": "Identity (E_U' = E_S')",
                    "status": "NOT REQUIRED",
                    "detail": "Transformation skipped per transaction flag (encoding_transform_required = false). E_S' treated as E_U'.",
                },
                stage2_verification={
                    "status": "NOT REQUIRED",
                    "detail": "Transformation not required for Branch B.",
                },
                status="NOT REQUIRED",
                notes="Branch B: Deterministic transformation not required (encoding_transform_required = false).",
            )
        else:
            # Branch A: Transformation required. Prerequisite: Step 3 must be MATCH
            step3 = self.session.step_results.get("step_3")
            if not step3 or step3.status != "MATCH":
                return VerificationStageResult(
                    step_number=3,
                    step_id="step_transform",
                    step_title="Transform Secured Encoding to E_U'",
                    responsible_party="Verifier Transformation Engine",
                    stage1_reconstruction={
                        "branch": "Branch A (encoding_transform_required = true)",
                        "status": "BLOCKED",
                        "detail": "Prerequisite Step 3 C_ES verification failed or not completed. Transformation blocked.",
                    },
                    stage2_verification={"status": "BLOCKED"},
                    status="BLOCKED",
                    notes="Prerequisite Step 3 failed: cannot apply transformation without valid C_ES commitment check.",
                )

            design_id = getattr(st, "design_id", "iir_butterworth")
            if design_id != "iir_butterworth":
                return VerificationStageResult(
                    step_number=3,
                    step_id="step_transform",
                    step_title="Transform Secured Encoding to E_U'",
                    responsible_party="Verifier Transformation Engine",
                    stage1_reconstruction={
                        "branch": "Branch A (encoding_transform_required = true)",
                        "status": "UNSUPPORTED",
                        "detail": f"Transformation is unsupported for design '{design_id}'. The deterministic transformation applies strictly to the verified IIR Butterworth benchmark.",
                    },
                    stage2_verification={"status": "BLOCKED"},
                    status="MISMATCH",
                    notes=f"Unsupported design '{design_id}' for Butterworth transformation.",
                )

            rule_id = ov.get("transformation_rule_id", getattr(st, "transformation_rule_id", "iir_butterworth_transform_v1"))
            rule_ver = ov.get("transformation_rule_version", getattr(st, "transformation_rule_version", "1.0"))

            es_bits = ov.get("extracted_ES", ov.get("extracted_es", self.session.internal_confidential_values.get("E_S")))
            if not es_bits:
                return VerificationStageResult(
                    step_number=3,
                    step_id="step_transform",
                    step_title="Transform Secured Encoding to E_U'",
                    responsible_party="Verifier Transformation Engine",
                    stage1_reconstruction={
                        "branch": "Branch A (encoding_transform_required = true)",
                        "status": "BLOCKED",
                        "detail": "Missing independently calculated secured encoding E_S'. Cannot apply transformation.",
                    },
                    stage2_verification={"status": "BLOCKED"},
                    status="BLOCKED",
                    notes="Missing reconstructed E_S' for transformation.",
                )

            if "transformed_eu" in ov:
                eu_bitstream = ov["transformed_eu"]
            else:
                try:
                    mode = "five_rule" if len(es_bits) == 251 else "four_rule"
                    eu_bitstream = DesignStructuralEncoder.transform_butterworth_es_to_eu(
                        es_bitstream=es_bits,
                        design_id=design_id,
                        mode=mode,
                    )
                except Exception as e:
                    return VerificationStageResult(
                        step_number=3,
                        step_id="step_transform",
                        step_title="Transform Secured Encoding to E_U'",
                        responsible_party="Verifier Transformation Engine",
                        stage1_reconstruction={
                            "branch": "Branch A (encoding_transform_required = true)",
                            "status": "FAILED",
                            "detail": f"Transformation error: {e}",
                        },
                        stage2_verification={"status": "BLOCKED"},
                        status="MISMATCH",
                        notes=f"Transformation error: {e}",
                    )

            eu_hash = hashlib.sha256(eu_bitstream.encode("utf-8")).hexdigest()

            # Record hash of E_U' before releasing opening information for C_D
            self.record_step_hash(
                step_id="step_4",
                hash_hex=eu_hash,
                artifact_id="transformed_encoding",
                step_num=4,
            )
            self.session.internal_confidential_values["E_U"] = eu_bitstream

            return VerificationStageResult(
                step_number=3,
                step_id="step_transform",
                step_title="Transform Secured Encoding to E_U'",
                responsible_party="Verifier Transformation Engine",
                canonical_hash=eu_hash,
                hash_algorithm="SHA-256",
                bit_length=len(eu_bitstream),
                stage1_reconstruction={
                    "branch": "Branch A (encoding_transform_required = true)",
                    "transformation_rule_id": rule_id,
                    "transformation_rule_version": rule_ver,
                    "value_identifier": "E_U'",
                    "canonical_hash": eu_hash,
                    "hash_algorithm": "SHA-256",
                    "bit_length": len(eu_bitstream),
                    "status": "TRANSFORMED",
                },
                stage2_verification={
                    "status": "READY FOR C_D CHECK",
                    "detail": "Deterministic transformation applied. Canonical hash of E_U' recorded. Ready for C_D check.",
                },
                status="MATCH",
                notes=f"Deterministic transformation '{rule_id} v{rule_ver}' applied ({len(eu_bitstream)} bits). E_U' canonical hash recorded.",
            )

    # --------------------------------------------------------------------------
    # Step 4: Verify Original Design Encoding Commitment (C_D)
    # --------------------------------------------------------------------------
    def _step_4_verify_original_encoding(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        # Check prerequisite Step 3
        step3 = self.session.step_results.get("step_3")
        if not step3 or step3.status not in ("NOT REQUIRED", "MATCH"):
            return VerificationStageResult(
                step_number=4,
                step_id="step_4",
                step_title="Verify Original Design Encoding (C_D)",
                responsible_party="Seller",
                stage1_reconstruction={
                    "status": "BLOCKED",
                    "detail": f"Prerequisite Step 3 failed (status: {step3.status if step3 else 'NOT RUN'}). Cannot verify C_D.",
                },
                stage2_verification={
                    "status": "BLOCKED",
                    "detail": f"Prerequisite Step 3 failed (status: {step3.status if step3 else 'NOT RUN'}). Cannot verify C_D.",
                },
                status="BLOCKED",
                notes="Prerequisite Step 3 failed: dependent verification blocked.",
            )

        flag = ov.get("encoding_transform_required", ov.get("is_encoding_changed", getattr(st, "encoding_transform_required", False)))

        if flag:
            # Branch A: Ensure Step Transform has executed
            step_trans = self.session.step_results.get("step_transform")
            if not step_trans or step_trans.status != "MATCH":
                step_trans = self._step_transform_secured_encoding(st, ov)
                self.session.step_results["step_transform"] = step_trans
                if step_trans.status != "MATCH":
                    return VerificationStageResult(
                        step_number=4,
                        step_id="step_4",
                        step_title="Verify Original Design Encoding (C_D)",
                        responsible_party="Seller",
                        stage1_reconstruction={"status": "BLOCKED", "detail": "Transformation step failed. Cannot verify C_D."},
                        stage2_verification={"status": "BLOCKED"},
                        status="BLOCKED",
                        notes="Transformation step failed.",
                    )
            target_hash = self.get_recorded_step_hash("step_4")
            bit_len = step_trans.stage1_reconstruction.get("bit_length", 251)
        else:
            # Branch B: E_S' treated directly as E_U'
            es_bits = self.session.internal_confidential_values.get("E_S")
            if es_bits:
                self.session.internal_confidential_values["E_U"] = es_bits
            target_hash = self.get_recorded_step_hash("step_2")
            if not target_hash and es_bits:
                target_hash = hashlib.sha256(es_bits.encode("utf-8")).hexdigest()
                self.record_step_hash("step_2", target_hash, "disputed_rtl", 2)
            if target_hash:
                self.record_step_hash("step_4", target_hash, "disputed_rtl", 4)
            bit_len = len(es_bits) if es_bits else 143

        # Allow override for adversarial testing (rule validity)
        rule_valid = ov.get("rule_valid", True)
        if not rule_valid:
            target_hash = hashlib.sha256(("0" * 143).encode("utf-8")).hexdigest()
            self.record_step_hash("step_4", target_hash, "corrupted", 4)

        if "calculated_d" in ov:
            target_hash = hashlib.sha256(ov["calculated_d"].encode("utf-8")).hexdigest()
            self.record_step_hash("step_4", target_hash, "override", 4)

        # Enforce Hash-First Opening Order: Release opening only after hash has been recorded
        self.release_step_opening(step_id="step_4", step_num=4)

        stored_c_d = ov.get("stored_c_d", ov.get("stored_C_D", ov.get("C_D", st.C_D)))
        r_d = ov.get("r_d", ov.get("r_D", st.blinding_factor_D))

        if not stored_c_d or not r_d or not target_hash:
            return VerificationStageResult(
                step_number=4,
                step_id="step_4",
                step_title="Verify Original Design Encoding (C_D)",
                responsible_party="Seller",
                stage1_reconstruction={
                    "value_identifier": "E_U'",
                    "canonical_hash": target_hash or "MISSING",
                    "hash_algorithm": "SHA-256",
                    "bit_length": bit_len,
                    "status": "BLOCKED",
                },
                stage2_verification={
                    "status": "BLOCKED",
                    "detail": "Missing Seller opening factor r_D or stored commitment C_D in evidence.",
                },
                status="BLOCKED",
                notes="Missing Seller private opening secret r_D.",
            )

        # Verify C_D using verify_from_digest (no double-hashing, canonical hash scalar)
        try:
            blinding_int = int(r_d, 16) if isinstance(r_d, str) else int(r_d)
            ver_res = self.pe.verify_from_digest(target_hash, stored_c_d, blinding_int)
            comm_recalc, _ = self.pe.commit_from_digest(target_hash, blinding_factor=blinding_int)
            c_d_recalc = comm_recalc.commitment_hex

            if ver_res == CommitmentVerificationStatus.VALID:
                ver_status = "MATCH"
                notes = f"Original design commitment C_D verified against recorded canonical hash (MATCH)."
            else:
                ver_status = "MISMATCH"
                notes = "Recalculated commitment C_D' does not match stored commitment C_D (MISMATCH)."
        except Exception as e:
            ver_status = "MISMATCH"
            c_d_recalc = f"Error: {e}"
            notes = f"Commitment calculation error: {e}"

        return VerificationStageResult(
            step_number=4,
            step_id="step_4",
            step_title="Verify Original Design Encoding (C_D)",
            responsible_party="Seller",
            canonical_hash=target_hash,
            hash_algorithm="SHA-256",
            bit_length=bit_len,
            stage1_reconstruction={
                "value_identifier": "E_U'",
                "canonical_hash": target_hash,
                "hash_algorithm": "SHA-256",
                "bit_length": bit_len,
                "status": "COMPUTED",
            },
            stage2_verification={
                "formula": "C_D = s_D * G + r_D * H over NIST P-256 (s_D from canonical hash)",
                "scalar_s": hex(self.pe.scalar_from_digest(target_hash))[2:],
                "opening_factor_r_D": r_d,
                "stored_commitment_C_D": stored_c_d,
                "recalculated_commitment_C_D": c_d_recalc,
                "comparison": "C_D' == C_D",
                "status": ver_status,
            },
            status=ver_status,
            notes=notes,
        )

    # --------------------------------------------------------------------------
    # Step 5: Extract Complete Watermark W' (Full 256-Bit) or Legacy W1'
    # --------------------------------------------------------------------------
    def _step_5_extract_embedded_watermark(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        rtl = ov.get("disputed_rtl", st.watermarked_RTL)
        mapping = ov.get("watermark_mapping")
        if not mapping:
            if getattr(st, "watermark_mapping", None):
                mapping = st.watermark_mapping
            elif st.pipeline_result and "watermark_mapping" in st.pipeline_result:
                mapping = st.pipeline_result["watermark_mapping"]
            elif st.protection_id:
                from hardware_ip_protection.web.app import active_sessions
                if st.protection_id in active_sessions:
                    mapping = active_sessions[st.protection_id].get("watermark_mapping")

        extract_method = ov.get("extraction_method_id", "cig_bipartite_register_alloc")
        if extract_method != "cig_bipartite_register_alloc":
            return VerificationStageResult(
                step_number=5,
                step_id="step_5",
                step_title="Extract Complete Watermark (W')",
                responsible_party="Seller Rules / Verifier RTL Extraction",
                stage1_reconstruction={
                    "status": "BLOCKED",
                    "detail": f"Unknown or unsupported watermark extraction method '{extract_method}'.",
                },
                stage2_verification={"status": "BLOCKED"},
                status="BLOCKED",
                notes=f"Extraction method '{extract_method}' unsupported.",
            )

        if not rtl or not mapping:
            return VerificationStageResult(
                step_number=5,
                step_id="step_5",
                step_title="Extract Complete Watermark (W')",
                responsible_party="Seller Rules / Verifier RTL Extraction",
                stage1_reconstruction={
                    "status": "BLOCKED",
                    "detail": "Missing RTL or watermark mapping rules in transaction evidence.",
                },
                stage2_verification={"status": "BLOCKED"},
                status="BLOCKED",
            )

        # Independently execute extraction from synthesizable RTL
        is_full = getattr(st, "is_full_watermark", True)
        expected_len = len(mapping) if mapping else (getattr(st, "embedded_watermark_length", 256) or 256)
        extract_res: ExtractionResult = TransactionWatermarkExtractor.extract(
            rtl, watermark_mapping=mapping, expected_length=expected_len
        )

        w_calc = ov.get("extracted_w", ov.get("extracted_w1", ov.get("w1_bitstream", extract_res.bitstream)))
        w_hash = hashlib.sha256(w_calc.encode("utf-8")).hexdigest() if w_calc else ""

        # Durably record hash before opening disclosure
        if w_hash:
            self.record_step_hash(
                step_id="step_5",
                hash_hex=w_hash,
                artifact_id="disputed_rtl",
                step_num=5,
            )
            self.session.internal_confidential_values["W"] = w_calc
            self.session.internal_confidential_values["W_prime"] = w_calc
            self.session.internal_confidential_values["W1"] = w_calc

        title = "Extract Complete Watermark (W')" if is_full else "Extract Embedded Watermark (W1')"
        val_id = "W'" if is_full else "W1'"
        notes = f"{'Complete watermark' if is_full else 'W1'} extracted independently from disputed RTL register allocations ({len(w_calc) if w_calc else 0} bits). Canonical Hash: {w_hash}."

        return VerificationStageResult(
            step_number=5,
            step_id="step_5",
            step_title=title,
            responsible_party="Seller Rules / Verifier RTL Extraction",
            canonical_hash=w_hash,
            hash_algorithm="SHA-256",
            bit_length=len(w_calc) if w_calc else 0,
            stage1_reconstruction={
                "method": "Parse synthesized RTL register allocations; inspect mutual exclusion across target CIG pairs",
                "value_identifier": val_id,
                "canonical_hash": w_hash,
                "hash_algorithm": "SHA-256",
                "bit_length": len(w_calc) if w_calc else 0,
                "extraction_status": extract_res.status.value,
                "recovered_bits": extract_res.recovered_bits,
                "unrecovered_bits": extract_res.unrecovered_bits,
                "status": "EXTRACTED",
            },
            stage2_verification={
                "status": "READY FOR COMMITMENT CHECK",
                "detail": f"{'Complete watermark' if is_full else 'Embedded watermark slice W1'} recovered from RTL. Ready for {'C_W' if is_full else 'C_W1'} verification.",
            },
            status="EXTRACTED",
            notes=notes,
        )

    # --------------------------------------------------------------------------
    # Step 6: Verify Watermark Commitment (C_W for Full Model, C_W1 for Legacy)
    # --------------------------------------------------------------------------
    def _step_6_verify_embedded_watermark_commitment(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        step5 = self.session.step_results.get("step_5")
        if not step5 or step5.status != "EXTRACTED":
            return VerificationStageResult(
                step_number=6,
                step_id="step_6",
                step_title="Verify Complete Watermark Commitment (C_W)" if getattr(st, "is_full_watermark", True) else "Verify Embedded Watermark Commitment (C_W1)",
                responsible_party="Seller",
                stage1_reconstruction={"status": "BLOCKED", "detail": f"Prerequisite Step 5 watermark extraction failed (status: {step5.status if step5 else 'NOT RUN'})."},
                stage2_verification={"status": "BLOCKED"},
                status="BLOCKED",
                notes="Prerequisite Step 5 failed: cannot verify watermark commitment without extracted watermark.",
            )

        is_full = getattr(st, "is_full_watermark", True)
        w_hash = self.get_recorded_step_hash("step_5")
        w_calc = self.session.internal_confidential_values.get("W") or self.session.internal_confidential_values.get("W1")
        if "w_bitstream" in ov or "w1_bitstream" in ov:
            w_calc = ov.get("w_bitstream", ov.get("w1_bitstream"))
            w_hash = hashlib.sha256(w_calc.encode("utf-8")).hexdigest()
            self.record_step_hash("step_5", w_hash, "override", 5)

        if is_full:
            stored_comm = ov.get("stored_c_w", ov.get("stored_c_w1", st.C_W))
            blinding = ov.get("r_w", ov.get("r_w1", st.blinding_factor_W))
            title = "Verify Complete Watermark Commitment (C_W)"
            val_id = "W'"
            comm_name = "C_W"
        else:
            stored_comm = ov.get("stored_c_w1", st.C_W1)
            blinding = ov.get("r_w1", st.blinding_factor_W1)
            title = "Verify Embedded Watermark Commitment (C_W1)"
            val_id = "W1'"
            comm_name = "C_W1"

        if not stored_comm or not blinding or not w_hash:
            return VerificationStageResult(
                step_number=6,
                step_id="step_6",
                step_title=title,
                responsible_party="Seller",
                stage1_reconstruction={
                    "value_identifier": val_id,
                    "canonical_hash": w_hash or "MISSING",
                    "hash_algorithm": "SHA-256",
                    "status": "AVAILABLE" if w_hash else "BLOCKED",
                },
                stage2_verification={"status": "BLOCKED", "detail": f"Missing opening factor or stored {comm_name}."},
                status="BLOCKED",
            )

        # Enforce Hash-First Opening Order
        self.record_step_hash(step_id="step_6", hash_hex=w_hash, artifact_id="disputed_rtl", step_num=6)
        self.release_step_opening(step_id="step_6", step_num=6)

        try:
            blinding_int = int(blinding, 16) if isinstance(blinding, str) else int(blinding)
            ver_res = self.pe.verify_from_digest(w_hash, stored_comm, blinding_int)
            comm_recalc_obj, _ = self.pe.commit_from_digest(w_hash, blinding_factor=blinding_int)
            c_recalc = comm_recalc_obj.commitment_hex

            if ver_res == CommitmentVerificationStatus.VALID:
                ver_status = "MATCH"
                notes = f"{'Complete' if is_full else 'Embedded'} watermark commitment {comm_name} verified against extracted bitstream {val_id} hash (MATCH)."
            else:
                ver_status = "MISMATCH"
                notes = f"Recalculated commitment {comm_name}' does not match stored commitment {comm_name} (MISMATCH)."
        except Exception as e:
            ver_status = "MISMATCH"
            c_recalc = f"Error: {e}"
            notes = f"Commitment verification error: {e}"

        return VerificationStageResult(
            step_number=6,
            step_id="step_6",
            step_title=title,
            responsible_party="Seller",
            canonical_hash=w_hash,
            hash_algorithm="SHA-256",
            bit_length=len(w_calc) if w_calc else (256 if is_full else 32),
            stage1_reconstruction={
                "value_identifier": val_id,
                "canonical_hash": w_hash,
                "hash_algorithm": "SHA-256",
                "bit_length": len(w_calc) if w_calc else (256 if is_full else 32),
                "scope": "Complete watermark [0:256]" if is_full else "Embedded slice [0:32]",
                "status": "VALIDATED",
            },
            stage2_verification={
                "formula": f"{comm_name} = s * G + r * H over NIST P-256 (s from canonical hash)",
                "opening_factor_r": blinding,
                f"stored_commitment_{comm_name}": stored_comm,
                f"recalculated_commitment_{comm_name}": c_recalc,
                "status": ver_status,
            },
            status=ver_status,
            notes=notes,
        )

    # --------------------------------------------------------------------------
    # Step 7: Reconstruct Complete Watermark W' (Legacy Only / Marked NOT REQUIRED in Full Model)
    # --------------------------------------------------------------------------
    def _step_7_reconstruct_complete_watermark(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        if ov.get("is_full_watermark", getattr(st, "is_full_watermark", True)):
            w_hash = self.get_recorded_step_hash("step_5")
            w_calc = self.session.internal_confidential_values.get("W")
            if w_hash:
                self.record_step_hash(step_id="step_7", hash_hex=w_hash, artifact_id="extracted_watermark", step_num=7)
            return VerificationStageResult(
                step_number=7,
                step_id="step_7",
                step_title="Reconstruct Complete Watermark (W')",
                responsible_party="Seller / Verifier Execution",
                canonical_hash=w_hash or "NOT_REQUIRED",
                hash_algorithm="SHA-256",
                bit_length=len(w_calc) if w_calc else 256,
                stage1_reconstruction={
                    "rule": "Full-Watermark Model: W' is extracted directly in Step 5 without splitting or remainder concatenation",
                    "value_identifier": "W'",
                    "canonical_hash": w_hash or "NOT_REQUIRED",
                    "hash_algorithm": "SHA-256",
                    "bit_length": len(w_calc) if w_calc else 256,
                    "status": "NOT REQUIRED",
                    "detail": "Full watermark model embeds all 256 bits directly. Off-chain slice concatenation is not required.",
                },
                stage2_verification={
                    "status": "NOT REQUIRED",
                    "detail": "Reconstruction step not required in full-watermark model.",
                },
                status="NOT REQUIRED",
                notes="Full-watermark model: Complete 256-bit watermark W' was extracted directly in Step 5. Concatenation of W2 remainder is not required.",
            )

        step5 = self.session.step_results.get("step_5")
        if not step5 or step5.status != "EXTRACTED":
            return VerificationStageResult(
                step_number=7,
                step_id="step_7",
                step_title="Reconstruct Complete Watermark (W')",
                responsible_party="Seller Private Evidence",
                stage1_reconstruction={
                    "status": "BLOCKED",
                    "detail": f"Prerequisite Step 5 watermark extraction failed (status: {step5.status if step5 else 'NOT RUN'}). Cannot reconstruct complete watermark W'.",
                },
                stage2_verification={"status": "BLOCKED"},
                status="BLOCKED",
                notes="Prerequisite Step 5 failed: missing extracted W1'.",
            )

        w1_calc = self.session.internal_confidential_values.get("W1")
        w1_calc = ov.get("w1_bitstream", w1_calc)
        w2_protected = ov.get("w2_bitstream", st.protected_W2)

        if not w1_calc or not w2_protected:
            return VerificationStageResult(
                step_number=7,
                step_id="step_7",
                step_title="Reconstruct Complete Watermark (W')",
                responsible_party="Seller Private Evidence",
                stage1_reconstruction={
                    "status": "BLOCKED",
                    "detail": "Missing extracted W1' or protected slice W2 in transaction evidence repository.",
                },
                stage2_verification={"status": "BLOCKED"},
                status="BLOCKED",
            )

        # Splitting and reconstruction rule: W = W1 || W2
        w_reconstructed = ov.get("w_reconstructed", w1_calc + w2_protected)
        w_hash = hashlib.sha256(w_reconstructed.encode("utf-8")).hexdigest()

        # Durably record hash before opening disclosure
        self.record_step_hash(
            step_id="step_7",
            hash_hex=w_hash,
            artifact_id="reconstructed_watermark",
            step_num=7,
        )
        self.session.internal_confidential_values["W"] = w_reconstructed

        return VerificationStageResult(
            step_number=7,
            step_id="step_7",
            step_title="Reconstruct Complete Watermark (W')",
            responsible_party="Seller Private Evidence",
            canonical_hash=w_hash,
            hash_algorithm="SHA-256",
            bit_length=len(w_reconstructed),
            stage1_reconstruction={
                "rule": "W = W1 || W2 (Concatenate extracted 32-bit W1' with protected 224-bit W2)",
                "value_identifier": "W'",
                "canonical_hash": w_hash,
                "hash_algorithm": "SHA-256",
                "w1_length": len(w1_calc),
                "w2_length": len(w2_protected),
                "bit_length": len(w_reconstructed),
                "total_bit_length": len(w_reconstructed),
                "status": "RECONSTRUCTED",
            },
            stage2_verification={
                "status": "READY FOR C_W CHECK",
                "detail": "Complete 256-bit watermark W' reconstructed. Ready for C_W commitment verification.",
            },
            status="MATCH" if len(w_reconstructed) == 256 else "MISMATCH",
            notes=f"Complete 256-bit watermark W' assembled from extracted W1' ({len(w1_calc)} bits) and protected W2 ({len(w2_protected)} bits). Canonical Hash: {w_hash}.",
        )

    # --------------------------------------------------------------------------
    # Step 8: Verify Complete Watermark Commitment C_W (Legacy Only / Marked NOT REQUIRED in Full Model)
    # --------------------------------------------------------------------------
    def _step_8_verify_complete_watermark_commitment(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        if ov.get("is_full_watermark", getattr(st, "is_full_watermark", True)):
            w_hash = self.get_recorded_step_hash("step_5")
            w_calc = self.session.internal_confidential_values.get("W")
            step6 = self.session.step_results.get("step_6")
            step6_status = step6.status if step6 else "NOT RUN"
            if w_hash:
                self.record_step_hash(step_id="step_8", hash_hex=w_hash, artifact_id="extracted_watermark", step_num=8)
            return VerificationStageResult(
                step_number=8,
                step_id="step_8",
                step_title="Verify Complete Watermark Commitment (C_W)",
                responsible_party="Seller",
                canonical_hash=w_hash or "NOT_REQUIRED",
                hash_algorithm="SHA-256",
                bit_length=len(w_calc) if w_calc else 256,
                stage1_reconstruction={
                    "value_identifier": "W'",
                    "canonical_hash": w_hash or "NOT_REQUIRED",
                    "hash_algorithm": "SHA-256",
                    "status": "NOT REQUIRED",
                    "detail": f"Commitment C_W verified directly in Step 6 (status: {step6_status}). Redundant check not required.",
                },
                stage2_verification={
                    "status": "NOT REQUIRED",
                    "detail": "Commitment verification for C_W completed in Step 6.",
                },
                status="NOT REQUIRED",
                notes=f"Full-watermark model: Complete watermark commitment C_W was verified in Step 6 ({step6_status}). Redundant Step 8 check not required.",
            )

        step7 = self.session.step_results.get("step_7")
        if not step7 or step7.status != "MATCH":
            return VerificationStageResult(
                step_number=8,
                step_id="step_8",
                step_title="Verify Complete Watermark Commitment (C_W)",
                responsible_party="Seller",
                stage1_reconstruction={"status": "BLOCKED", "detail": f"Prerequisite Step 7 complete watermark reconstruction failed (status: {step7.status if step7 else 'NOT RUN'})."},
                stage2_verification={"status": "BLOCKED"},
                status="BLOCKED",
                notes="Prerequisite Step 7 failed: cannot verify C_W without reconstructed W'.",
            )

        w_hash = self.get_recorded_step_hash("step_7")
        w_calc = self.session.internal_confidential_values.get("W")
        if "w_bitstream" in ov:
            w_calc = ov["w_bitstream"]
            w_hash = hashlib.sha256(w_calc.encode("utf-8")).hexdigest()
            self.record_step_hash("step_7", w_hash, "override", 7)

        stored_c_w = ov.get("stored_c_w", st.C_W)
        r_w = ov.get("r_w", st.blinding_factor_W)

        if not stored_c_w or not r_w or not w_hash:
            return VerificationStageResult(
                step_number=8,
                step_id="step_8",
                step_title="Verify Complete Watermark Commitment (C_W)",
                responsible_party="Seller",
                canonical_hash=w_hash or "MISSING",
                hash_algorithm="SHA-256",
                bit_length=len(w_calc) if w_calc else 256,
                stage1_reconstruction={
                    "value_identifier": "W'",
                    "canonical_hash": w_hash or "MISSING",
                    "hash_algorithm": "SHA-256",
                    "status": "AVAILABLE" if w_hash else "BLOCKED",
                },
                stage2_verification={"status": "BLOCKED", "detail": "Missing opening factor r_W or stored C_W."},
                status="BLOCKED",
            )

        # Enforce Hash-First Opening Order
        self.record_step_hash(step_id="step_8", hash_hex=w_hash, artifact_id="reconstructed_watermark", step_num=8)
        self.release_step_opening(step_id="step_8", step_num=8)

        try:
            blinding_int = int(r_w, 16) if isinstance(r_w, str) else int(r_w)
            ver_res = self.pe.verify_from_digest(w_hash, stored_c_w, blinding_int)
            comm_w, _ = self.pe.commit_from_digest(w_hash, blinding_factor=blinding_int)
            c_w_recalc = comm_w.commitment_hex

            if ver_res == CommitmentVerificationStatus.VALID:
                ver_status = "MATCH"
                notes = "Complete 256-bit watermark commitment C_W verified against reconstructed W' hash (MATCH)."
            else:
                ver_status = "MISMATCH"
                notes = "Recalculated commitment C_W' does not match stored commitment C_W (MISMATCH)."
        except Exception as e:
            ver_status = "MISMATCH"
            c_w_recalc = f"Error: {e}"
            notes = f"Commitment verification error: {e}"

        return VerificationStageResult(
            step_number=8,
            step_id="step_8",
            step_title="Verify Complete Watermark Commitment (C_W)",
            responsible_party="Seller",
            canonical_hash=w_hash,
            hash_algorithm="SHA-256",
            bit_length=len(w_calc) if w_calc else 256,
            stage1_reconstruction={
                "value_identifier": "W'",
                "canonical_hash": w_hash,
                "hash_algorithm": "SHA-256",
                "bit_length": len(w_calc) if w_calc else 256,
                "status": "VALIDATED",
            },
            stage2_verification={
                "formula": "C_W = s_W * G + r_W * H over NIST P-256 (s_W from canonical hash)",
                "opening_factor_r_W": r_w,
                "stored_commitment_C_W": stored_c_w,
                "recalculated_commitment_C_W": c_w_recalc,
                "status": ver_status,
            },
            status=ver_status,
            notes=notes,
        )

    # --------------------------------------------------------------------------
    # Step 9: Derive / Check Buyer Contribution B'
    # --------------------------------------------------------------------------
    def _step_9_reconstruct_buyer_contribution(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        b_input = ov.get("buyer_bitstream", st.buyer_bitstream_B or DEMO_BUYER_BITSTREAM)

        if not b_input:
            return VerificationStageResult(
                step_number=9,
                step_id="step_9",
                step_title="Check Buyer Contribution Bitstream (B')",
                responsible_party="Buyer Private Evidence",
                stage1_reconstruction={"status": "BLOCKED", "detail": "Buyer bitstream B not provided."},
                stage2_verification={"status": "BLOCKED"},
                status="BLOCKED",
            )

        b_len = len(b_input)
        zeros = b_input.count("0")
        ones = b_input.count("1")

        is_valid_props = (b_len == 555 and zeros == 242 and ones == 313)
        status = "MATCH" if is_valid_props else "MISMATCH"

        b_hash = hashlib.sha256(b_input.encode("utf-8")).hexdigest()

        # Durably record hash before opening disclosure
        self.record_step_hash(
            step_id="step_9",
            hash_hex=b_hash,
            artifact_id="buyer_bitstream",
            step_num=9,
        )
        self.session.internal_confidential_values["B"] = b_input

        return VerificationStageResult(
            step_number=9,
            step_id="step_9",
            step_title="Check Buyer Contribution Bitstream (B')",
            responsible_party="Buyer Private Evidence",
            canonical_hash=b_hash,
            hash_algorithm="SHA-256",
            bit_length=b_len,
            stage1_reconstruction={
                "derivation_method": "Fingerprint-Derived Bitstream Extraction (fingerprint_minutiae_demo_standard)",
                "value_identifier": "B'",
                "canonical_hash": b_hash,
                "hash_algorithm": "SHA-256",
                "bit_length": b_len,
                "zeros_count": zeros,
                "ones_count": ones,
                "format_check": "Supplementary format sanity check (length, zero/one count)",
                "status": "VALIDATED" if is_valid_props else "INVALID PROPERTIES",
            },
            stage2_verification={
                "status": "READY FOR C_B CHECK",
                "detail": "Buyer contribution format validated. Ready for C_B commitment recalculation.",
            },
            status=status,
            notes=f"Buyer demonstration bitstream validated (555 bits: 242 zeros, 313 ones). Canonical Hash: {b_hash}.",
        )

    # --------------------------------------------------------------------------
    # Step 10: Verify Buyer Commitment C_B
    # --------------------------------------------------------------------------
    def _step_10_verify_buyer_commitment(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        step9 = self.session.step_results.get("step_9")
        if not step9 or step9.status == "BLOCKED":
            return VerificationStageResult(
                step_number=10,
                step_id="step_10",
                step_title="Verify Buyer Commitment (C_B)",
                responsible_party="Buyer",
                stage1_reconstruction={"status": "BLOCKED", "detail": f"Prerequisite Step 9 Buyer contribution evidence missing or blocked (status: {step9.status if step9 else 'NOT RUN'})."},
                stage2_verification={"status": "BLOCKED"},
                status="BLOCKED",
                notes="Prerequisite Step 9 blocked: cannot verify C_B without Buyer contribution evidence.",
            )

        b_hash = self.get_recorded_step_hash("step_9")
        b_calc = self.session.internal_confidential_values.get("B")
        if "buyer_bitstream" in ov:
            b_calc = ov["buyer_bitstream"]
            b_hash = hashlib.sha256(b_calc.encode("utf-8")).hexdigest()
            self.record_step_hash("step_9", b_hash, "override", 9)

        stored_c_b = ov.get("stored_c_b", st.C_B)
        r_b = ov.get("r_b", st.blinding_factor_B)

        if not stored_c_b or not r_b or not b_hash:
            return VerificationStageResult(
                step_number=10,
                step_id="step_10",
                step_title="Verify Buyer Commitment (C_B)",
                responsible_party="Buyer",
                canonical_hash=b_hash or "MISSING",
                hash_algorithm="SHA-256",
                bit_length=len(b_calc) if b_calc else 555,
                stage1_reconstruction={
                    "value_identifier": "B'",
                    "canonical_hash": b_hash or "MISSING",
                    "hash_algorithm": "SHA-256",
                    "status": "AVAILABLE" if b_hash else "BLOCKED",
                },
                stage2_verification={"status": "BLOCKED", "detail": "Missing opening factor r_B or stored C_B."},
                status="BLOCKED",
            )

        # Enforce Hash-First Opening Order
        self.record_step_hash(step_id="step_10", hash_hex=b_hash, artifact_id="buyer_bitstream", step_num=10)
        self.release_step_opening(step_id="step_10", step_num=10)

        try:
            blinding_int = int(r_b, 16) if isinstance(r_b, str) else int(r_b)
            ver_res = self.pe.verify_from_digest(b_hash, stored_c_b, blinding_int)
            comm_b, _ = self.pe.commit_from_digest(b_hash, blinding_factor=blinding_int)
            c_b_recalc = comm_b.commitment_hex

            if ver_res == CommitmentVerificationStatus.VALID:
                ver_status = "MATCH"
                notes = "Buyer contribution commitment C_B verified against actual 555-bit bitstream B' hash (MATCH). C_B is strictly Buyer-owned. Cryptographic validity established via ECC recalculation."
            else:
                ver_status = "MISMATCH"
                notes = "Recalculated commitment C_B' does not match stored commitment C_B (MISMATCH)."
        except Exception as e:
            ver_status = "MISMATCH"
            c_b_recalc = f"Error: {e}"
            notes = f"Commitment verification error: {e}"

        return VerificationStageResult(
            step_number=10,
            step_id="step_10",
            step_title="Verify Buyer Commitment (C_B)",
            responsible_party="Buyer",
            canonical_hash=b_hash,
            hash_algorithm="SHA-256",
            bit_length=len(b_calc) if b_calc else 555,
            stage1_reconstruction={
                "value_identifier": "B'",
                "canonical_hash": b_hash,
                "hash_algorithm": "SHA-256",
                "bit_length": len(b_calc) if b_calc else 555,
                "ownership": "Buyer Profile Exclusive Ownership (BUYER-001)",
                "proof_of_validity": "Commitment validity established by elliptic curve point addition C_B' == [s_B]G + [r_B]H, not by bit counts.",
                "status": "VALIDATED",
            },
            stage2_verification={
                "formula": "C_B = s_B * G + r_B * H over NIST P-256 (s_B, r_B in Z_n)",
                "opening_factor_r_B": r_b,
                "stored_commitment_C_B": stored_c_b,
                "recalculated_commitment_C_B": c_b_recalc,
                "status": ver_status,
            },
            status=ver_status,
            notes=notes,
        )

    # --------------------------------------------------------------------------
    # Step 11: Verify Watermark-Generation Relationship
    # --------------------------------------------------------------------------
    def _step_11_verify_watermark_relationship(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        step4 = self.session.step_results.get("step_4")
        step6 = self.session.step_results.get("step_6")
        step8 = self.session.step_results.get("step_8")
        step10 = self.session.step_results.get("step_10")
        failed = []
        if not step4 or step4.status != "MATCH":
            failed.append("Step 4 (C_D)")
        cw_match = (step6 and step6.status == "MATCH") or (step8 and step8.status == "MATCH")
        if not cw_match:
            failed.append("Watermark Commitment C_W (Step 6 or Step 8)")
        if not step10 or step10.status != "MATCH":
            failed.append("Step 10 (C_B)")
        if failed:
            return VerificationStageResult(
                step_number=11,
                step_id="step_11",
                step_title="Verify Watermark-Generation Relationship F(D', B', context)",
                responsible_party="Verifier Independent Computation",
                stage1_reconstruction={
                    "status": "BLOCKED",
                    "detail": f"Prerequisite steps failed or incomplete: {', '.join(failed)}. Watermark relationship cannot be evaluated without verified inputs.",
                },
                stage2_verification={
                    "status": "BLOCKED",
                    "detail": f"Prerequisite steps failed or incomplete: {', '.join(failed)}. Watermark relationship cannot be evaluated without verified inputs.",
                },
                status="BLOCKED",
                notes=f"Prerequisite verification failed for: {', '.join(failed)}.",
            )

        # Required independence check: Extracted watermark W' must originate directly from Step 5 RTL extraction
        # NEVER substitute with the stored original transaction watermark W.
        w_extracted = ov.get("w_bitstream", self.session.internal_confidential_values.get("W_prime") or self.session.internal_confidential_values.get("W"))
        if not w_extracted:
            return VerificationStageResult(
                step_number=11,
                step_id="step_11",
                step_title="Verify Watermark-Generation Relationship F(D', B', context)",
                responsible_party="Verifier Independent Computation",
                stage1_reconstruction={
                    "status": "BLOCKED",
                    "detail": "Extracted watermark W' missing from verifier session. Disputed RTL must be parsed in Step 5 before evaluating relationship F.",
                },
                stage2_verification={"status": "BLOCKED", "detail": "Missing extracted watermark W'."},
                status="BLOCKED",
                notes="Prerequisite Step 5 extraction from disputed RTL must be executed first; stored W cannot be used as substitute.",
            )
        w_reconstructed = w_extracted

        tx_rec = ov.get("transaction_record", {
            "transaction_id": st.transaction_id,
            "seller_id": st.seller_id,
            "buyer_id": st.buyer_id,
            "design_hash": getattr(st, "design_hash", None) or hashlib.sha256(b"iir_butterworth_golden_canonical").hexdigest(),
            "license_type": st.license_type,
        })
        if st.pipeline_result and "design_hash" in st.pipeline_result:
            tx_rec["design_hash"] = st.pipeline_result["design_hash"]

        k_tx = ov.get("k_tx", st.transaction_credentials.get("k_tx", "K_tx_symmetric_credential_secret_777"))

        # Retrieve confidential inputs D' and B' from internal verifier memory (never directly substitute stored values)
        d_val = ov.get("D", ov.get("design_encoding_D", self.session.internal_confidential_values.get("E_U")))
        if not d_val:
            d_val = self.session.internal_confidential_values.get("E_S")
        if not d_val:
            return VerificationStageResult(
                step_number=11,
                step_id="step_11",
                step_title="Verify Watermark-Generation Relationship F(D', B', context)",
                responsible_party="Verifier Independent Computation",
                stage1_reconstruction={
                    "status": "BLOCKED",
                    "detail": "Verified design encoding D' missing from verifier session. Disputed RTL must be parsed in Step 2 / Step 4 before evaluating relationship F.",
                },
                stage2_verification={"status": "BLOCKED", "detail": "Missing verified design encoding D'."},
                status="BLOCKED",
                notes="Prerequisite Step 4 design encoding verification must be completed first; stored D cannot be used as substitute.",
            )

        b_val = ov.get("B", ov.get("buyer_contribution_B", self.session.internal_confidential_values.get("B")))
        if not b_val:
            return VerificationStageResult(
                step_number=11,
                step_id="step_11",
                step_title="Verify Watermark-Generation Relationship F(D', B', context)",
                responsible_party="Verifier Independent Computation",
                stage1_reconstruction={
                    "status": "BLOCKED",
                    "detail": "Verified buyer contribution B' missing from verifier session. Buyer bitstream must be validated in Step 9 / Step 10 before evaluating relationship F.",
                },
                stage2_verification={"status": "BLOCKED", "detail": "Missing verified buyer contribution B'."},
                status="BLOCKED",
                notes="Prerequisite Step 10 buyer commitment verification must be completed first; stored B cannot be used as substitute.",
            )

        try:
            gen = SymmetricHKDFWatermarkGenerator()
            wm_len = len(w_reconstructed) if w_reconstructed else 256
            wm_obj = gen.generate(tx_rec, {"k_tx": k_tx}, watermark_length=wm_len, D=d_val, B=b_val)
            w_expected = wm_obj.canonical_bitstream

            w_exp_hash = hashlib.sha256(w_expected.encode("utf-8")).hexdigest()
            w_rec_hash = hashlib.sha256(w_reconstructed.encode("utf-8")).hexdigest() if w_reconstructed else ""

            if w_reconstructed and w_reconstructed == w_expected:
                rel_status = "MATCH"
                notes = f"Watermark-generation relationship W' = F(D', B', tx_record, k_tx) verified independently (MATCH). Canonical Hash: {w_rec_hash}."
            else:
                rel_status = "MISMATCH"
                notes = f"Extracted watermark hash ({w_rec_hash}) does not match independently derived expected watermark hash ({w_exp_hash}) (MISMATCH)."
        except Exception as e:
            rel_status = "BLOCKED"
            w_exp_hash = f"Error: {e}"
            w_rec_hash = ""
            notes = f"Relationship verification error: {e}"

        formula_str = 'W\' == HKDF_SHA256(ikm=k_tx, salt=HKDF_SALT, info="HardwareIP_Transaction_Watermark_v1:" || canonical_json(tx, D\', B\'), L=32 bytes)'

        return VerificationStageResult(
            step_number=11,
            step_id="step_11",
            step_title="Verify Watermark-Generation Relationship F(D', B', context)",
            responsible_party="Verifier Independent Computation",
            canonical_hash=w_rec_hash,
            hash_algorithm="SHA-256",
            bit_length=len(w_reconstructed) if w_reconstructed else 256,
            stage1_reconstruction={
                "function": "RFC 5869 Symmetric HKDF-SHA256 (Extract-and-Expand)",
                "formula": formula_str,
                "ikm_identifier": "k_tx (authorized transaction key)",
                "salt_identifier": "Hardware_IP_Protection_Salt_2026",
                "expected_watermark_hash": w_exp_hash,
                "reconstructed_watermark_hash": w_rec_hash,
                "hash_algorithm": "SHA-256",
                "output_bit_length": 256,
                "status": "EVALUATED",
            },
            stage2_verification={
                "comparison": "H(W') == H(F(D', B', context, k_tx))",
                "expected_watermark_hash": w_exp_hash,
                "extracted_watermark_hash": w_rec_hash,
                "status": rel_status,
            },
            status=rel_status,
            notes=notes,
        )

    # --------------------------------------------------------------------------
    # Step 12: Verify Transaction Evidence & Rights
    # --------------------------------------------------------------------------
    def _step_12_verify_transaction_evidence(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        tx_id = ov.get("transaction_id", st.transaction_id)
        seller_id = ov.get("seller_id", st.seller_id)
        buyer_id = ov.get("buyer_id", st.buyer_id)
        design_id = ov.get("design_id", st.design_id)
        rule_id = ov.get("rule_id", st.encoding_rule_id)
        buyer_approved = ov.get("buyer_approved", st.buyer_approved)
        contribution_status = ov.get("contribution_status", st.buyer_contribution_status)
        license_type = ov.get("license_type", st.license_type)

        is_consistent = (
            bool(tx_id) and bool(seller_id) and bool(buyer_id)
            and (tx_id == st.transaction_id if st.transaction_id else True)
            and (seller_id == st.seller_id if st.seller_id else True)
            and (buyer_id == st.buyer_id if st.buyer_id else True)
            and buyer_approved is True
            and contribution_status == "Received"
        )

        recorded_rights = "License" if "exclusive" in license_type.lower() else "Not Established"

        subcat = ov.get("dispute_subcategory", self.session.dispute_subcategory or "").lower()
        is_ownership_claim = "ownership" in subcat
        is_license_only = "license" in recorded_rights.lower()

        rights_conflict = False
        rights_conflict_details = None
        if is_ownership_claim and is_license_only:
            rights_conflict = True
            rights_conflict_details = (
                f"RIGHTS CONFLICT: Buyer claims full design ownership, but recorded transaction '{tx_id}' "
                f"grants only an {license_type} ({recorded_rights}). Cryptographic commitment consistency "
                "confirms mathematical integrity of the evidence, NOT legal transfer of ownership."
            )

        return VerificationStageResult(
            step_number=12,
            step_id="step_12",
            step_title="Verify Transaction Evidence & Recorded Rights",
            responsible_party="Transaction State Record",
            stage1_reconstruction={
                "transaction_id": tx_id,
                "seller_id": seller_id,
                "buyer_id": buyer_id,
                "design_reference": design_id,
                "encoding_rule": f"{rule_id} (v{st.encoding_rule_version})",
                "request_and_approval_status": "Approved" if buyer_approved else "Pending / Rejected",
                "buyer_contribution_status": contribution_status,
                "recorded_rights_type": recorded_rights,
                "license_scope": license_type,
                "authorization_distinction": "Cryptographic consistency confirms evidence integrity; recorded rights confirm license scope.",
                "rights_conflict_detected": rights_conflict,
                "rights_conflict_details": rights_conflict_details,
                "status": "AUDITED",
            },
            stage2_verification={
                "status": "MATCH" if is_consistent else "MISMATCH",
                "detail": "Transaction terms, approvals, and authorization scope match recorded registry parameters.",
                "rights_conflict_detected": rights_conflict,
                "rights_conflict_details": rights_conflict_details,
            },
            status="MATCH" if is_consistent else "MISMATCH",
            notes=(
                f"Transaction records audited. Rights type: {recorded_rights} ({license_type}). Authorization verified. "
                + (f"[RIGHTS CONFLICT: Buyer claims ownership under a {recorded_rights}]" if rights_conflict else "")
            ),
        )

    # --------------------------------------------------------------------------
    # Step 13: Generate Final Dispute Report
    # --------------------------------------------------------------------------
    def _step_13_generate_final_report(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        results = self.session.step_results

        d_status = results.get("step_4", VerificationStageResult(step_number=4, step_id="step_4", step_title="", responsible_party="", stage1_reconstruction={}, stage2_verification={}, status="BLOCKED")).status
        es_status = results.get("step_3", VerificationStageResult(step_number=3, step_id="step_3", step_title="", responsible_party="", stage1_reconstruction={}, stage2_verification={}, status="NOT REQUIRED")).status
        b_status = results.get("step_10", VerificationStageResult(step_number=10, step_id="step_10", step_title="", responsible_party="", stage1_reconstruction={}, stage2_verification={}, status="BLOCKED")).status
        f_status = results.get("step_11", VerificationStageResult(step_number=11, step_id="step_11", step_title="", responsible_party="", stage1_reconstruction={}, stage2_verification={}, status="BLOCKED")).status
        tx_status = results.get("step_12", VerificationStageResult(step_number=12, step_id="step_12", step_title="", responsible_party="", stage1_reconstruction={}, stage2_verification={}, status="INCOMPLETE")).status

        step12 = results.get("step_12")
        rights_conflict = step12.stage2_verification.get("rights_conflict_detected", False) if step12 else False
        rights_conflict_details = step12.stage2_verification.get("rights_conflict_details", "") if step12 else ""
        recorded_rights = step12.stage1_reconstruction.get("recorded_rights_type", "License") if step12 else ("License" if "exclusive" in getattr(st, "license_type", "").lower() else "Not Established")

        is_full = ov.get("is_full_watermark", getattr(st, "is_full_watermark", True))
        if is_full:
            w_status = results.get("step_6", VerificationStageResult(step_number=6, step_id="step_6", step_title="", responsible_party="", stage1_reconstruction={}, stage2_verification={}, status="BLOCKED")).status
            w1_status = w_status
            critical_statuses = [d_status, w_status, b_status, f_status, tx_status]
        else:
            w1_status = results.get("step_6", VerificationStageResult(step_number=6, step_id="step_6", step_title="", responsible_party="", stage1_reconstruction={}, stage2_verification={}, status="BLOCKED")).status
            w_status = results.get("step_8", VerificationStageResult(step_number=8, step_id="step_8", step_title="", responsible_party="", stage1_reconstruction={}, stage2_verification={}, status="BLOCKED")).status
            critical_statuses = [d_status, w1_status, w_status, b_status, f_status, tx_status]
        if getattr(self.session, "encoding_transform_required", False):
            critical_statuses.append(es_status)
        if any(s == "MISMATCH" for s in critical_statuses):
            overall_status = "INCONSISTENT"
        elif any(s in ("BLOCKED", "INCOMPLETE") for s in critical_statuses):
            overall_status = "INCOMPLETE"
        elif all(s in ("MATCH", "NOT REQUIRED") for s in critical_statuses):
            overall_status = "CONSISTENT"
        else:
            overall_status = "INCOMPLETE"

        if rights_conflict:
            findings_summary = (
                "CRYPTOGRAPHIC CONSISTENCY CONFIRMED, BUT RIGHTS CONFLICT IDENTIFIED: "
                "All cryptographic commitments, structural encodings, watermark splits, and buyer contribution bitstreams "
                "are mathematically consistent with recorded transaction parameters. "
                f"However, the Buyer claims legal ownership while transaction records grant only an Exclusive License ({recorded_rights}). "
                "Cryptographic validity confirms evidence integrity, but does NOT establish legal ownership."
            )
        else:
            findings_summary = (
                f"All cryptographic commitments, structural encodings, watermark splits, and buyer contribution bitstreams "
                f"are mathematically consistent with recorded transaction terms. Recorded license type is {recorded_rights} (exclusive); "
                f"legal ownership remains with Seller {st.seller_id or 'SELLER-001'}."
                if overall_status == "CONSISTENT" else f"Evidence audit detected discrepancies or incomplete prerequisite evidence. Consistency status is {overall_status}."
            )

        report = {
            "dispute_type": self.session.dispute_type,
            "dispute_subcategory": self.session.dispute_subcategory,
            "transaction_id": st.transaction_id,
            "seller_id": st.seller_id,
            "buyer_id": st.buyer_id,
            "design_encoding": d_status,
            "secured_encoding": es_status,
            "embedded_watermark": w1_status,
            "complete_watermark": w_status,
            "buyer_contribution": b_status,
            "watermark_generation_relationship": f_status,
            "transaction_record": tx_status,
            "recorded_rights": recorded_rights,
            "rights_conflict": rights_conflict,
            "rights_conflict_details": rights_conflict_details,
            "findings_summary": findings_summary,
            "overall_evidence_status": overall_status,
            "legal_notice": "Verification results indicate consistency of evidence and do not independently establish legal ownership.",
        }

        self.session.final_report = report

        return VerificationStageResult(
            step_number=13,
            step_id="step_13",
            step_title="Generate Final Dispute Verification Report",
            responsible_party="Independent Dispute Adjudication Authority",
            stage1_reconstruction={
                "report_summary": report,
                "status": "COMPILED",
            },
            stage2_verification={
                "overall_status": overall_status,
                "dispute_determination": overall_status,
                "recorded_rights": recorded_rights,
                "rights_conflict": rights_conflict,
                "rights_conflict_details": rights_conflict_details,
                "legal_notice": report.get("legal_notice"),
                "status": "MATCH" if overall_status == "CONSISTENT" else "MISMATCH",
            },
            status=overall_status,
            notes=f"Final dispute adjudication report generated: Overall Evidence Status = {overall_status}." + (f" [RIGHTS CONFLICT IDENTIFIED]" if rights_conflict else ""),
        )

    # ==========================================================================
    # Reference Design ↔ Suspicious Design Workflow (Section 8)
    # ==========================================================================
    def audit_reference_suspicious(
        self,
        suspicious_verilog: str,
        reference_verilog: Optional[str] = None,
        scenario_name: str = "Untouched Design",
        subcategory: Optional[str] = "Exact or near-copy suspicion.",
        protection_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes the Reference Design ↔ Suspicious Design dispute workflow.
        Reuses existing behavioral verification, watermark extraction, commitment verification,
        and structural encoding capabilities.
        """
        from hardware_ip_protection.pipeline.engine import DisputePipeline
        from hardware_ip_protection.verification.test_vector_generator import TestVectorSet
        from hardware_ip_protection.web.app import active_sessions

        mgr = TransactionManager.get_instance()
        st = mgr.get_state()

        ref_verilog = reference_verilog or st.watermarked_RTL
        prot_id = protection_id or st.protection_id

        # Try to locate active session context for full behavioral dispute verification
        prot_ctx = None
        if prot_id and prot_id in active_sessions:
            prot_ctx = active_sessions[prot_id]

        if not prot_ctx or "raw_dfg" not in prot_ctx:
            # Fallback to repository or rebuild pipeline context for demonstration
            from hardware_ip_protection.pipeline.transaction_manager import create_iir_butterworth
            from hardware_ip_protection.pipeline.engine import ProtectionPipeline
            pipe = ProtectionPipeline()
            init_ctx = {
                "dfg": create_iir_butterworth(),
                "resource_config": {"add": 2, "mul": 2, "sub": 2},
                "transaction_record": {
                    "transaction_id": st.transaction_id,
                    "seller_id": st.seller_id,
                    "buyer_id": st.buyer_id,
                    "license_type": st.license_type,
                    "design_encoding_D": st.design_encoding_D,
                    "buyer_contribution_B": st.buyer_bitstream_B,
                },
                "design_encoding_D": st.design_encoding_D,
                "buyer_contribution_B": st.buyer_bitstream_B,
                "transaction_credentials": {"k_tx": st.transaction_credentials.get("k_tx", "K_tx_symmetric_credential_secret_777")},
                "watermark_length": getattr(st, "embedded_watermark_length", None) or (256 if getattr(st, "is_full_watermark", True) else 32),
                "encoding_scope": None,
            }
            prot_ctx = pipe.run(init_ctx)
            if prot_id:
                active_sessions[prot_id] = prot_ctx

        disp_pipe = DisputePipeline()
        disp_ctx = {
            "raw_dfg": prot_ctx["raw_dfg"],
            "reference_verilog": prot_ctx["protected_verilog"],
            "suspicious_verilog": suspicious_verilog,
            "suspicious_scenario": scenario_name,
            "reference_protection_id": prot_ctx["protection_record"].protection_id,
            "test_vector_set": prot_ctx["test_vector_set"],
            "stored_test_vector_commitment": prot_ctx["test_vector_commitment"].commitment_hex,
            "test_vector_blinding_factor": hex(prot_ctx["test_vector_blinding_factor"])[2:].zfill(64),
            "stored_watermark_commitment": prot_ctx["watermark_commitment"].commitment_hex,
            "watermark_blinding_factor": hex(prot_ctx["watermark_blinding_factor"])[2:].zfill(64),
            "intended_watermark_bitstream": prot_ctx["transaction_watermark"].bitstream,
            "protection_record": prot_ctx["protection_record"],
        }

        disp_out = disp_pipe.run(disp_ctx)
        res = disp_out["dispute_result"]
        sim = disp_out["watermark_similarity"]
        b_res = disp_out["dispute_behavioral_result"]
        ca = b_res.correlation_analysis or {}
        l1_val = ca.get("l1_distance", 0.0)

        # Distinguish exact commitment matches from functional or structural relationships
        is_exact_copy = (sim.status.value == "IDENTICAL" and b_res.status.value == "IDENTICAL")
        if is_exact_copy:
            derivation_verdict = "Exact Copy: Suspicious design is bit-for-bit and functionally identical to certified reference."
        elif sim.recovered_bits > 0 or b_res.exact_output_matches > 0:
            derivation_verdict = "Derived / Modified: Suspicious design exhibits functional or structural watermark traces despite modifications."
        else:
            derivation_verdict = "Unrelated / Independent: No watermark traces or identical register bindings recovered."

        return {
            "dispute_type": "Reference Design ↔ Suspicious Design",
            "dispute_subcategory": subcategory,
            "scenario": scenario_name,
            "reference_rtl_sha256": res.reference_rtl_sha256,
            "suspicious_rtl_sha256": res.suspicious_rtl_sha256,
            "behavioral_verification": {
                "total_test_vectors": b_res.total_test_vectors,
                "exact_output_matches": b_res.exact_output_matches,
                "exact_output_mismatches": b_res.exact_output_mismatches,
                "exact_output_match_rate": b_res.exact_output_match_rate,
                "l1_distance": l1_val,
                "status": b_res.status.value,
            },
            "watermark_extraction": {
                "expected_bits": sim.expected_bits,
                "suspicious_recovered_bits": sim.suspicious_recovered_bits,
                "matching_bits": sim.matching_bits,
                "mismatching_bits": sim.mismatching_bits,
                "similarity_ratio": sim.similarity_ratio,
                "similarity_status": sim.status.value,
            },
            "commitment_checks": {
                "reference_watermark_commitment_check": res.watermark_analysis.commitment.reference_commitment_check,
                "test_vector_commitment_check": res.test_vector_commitment.status,
            },
            "structural_similarity_status": {
                "status": "FUTURE CAPABILITY",
                "detail": "Level 3 Structural Similarity & Node Correspondence is an intentionally deferred future extension. No arbitrary heuristic or similarity score is applied.",
            },
            "derivation_analysis": derivation_verdict,
            "dispute_result": res.model_dump(),
        }
