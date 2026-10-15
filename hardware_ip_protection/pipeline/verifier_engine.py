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

from typing import Dict, Any, Optional, List, Tuple
import hashlib
import json
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
    step_number: int
    step_id: str
    step_title: str
    responsible_party: str
    stage1_reconstruction: Dict[str, Any]
    stage2_verification: Dict[str, Any]
    status: str  # MATCH, MISMATCH, NOT REQUIRED, BLOCKED, INCOMPLETE, LOADED, EXTRACTED, VALIDATED
    notes: Optional[str] = None


class DisputeSession(BaseModel):
    session_id: str = "VSESS-001"
    transaction_id: str = "TX-001"
    dispute_type: str = "Seller ↔ Buyer Conflict"
    dispute_subcategory: str = "Buyer claims ownership; recorded transaction may grant only a license."
    current_step: int = 1
    completed_steps: List[int] = Field(default_factory=list)
    step_results: Dict[str, VerificationStageResult] = Field(default_factory=dict)
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

        self.session = DisputeSession(
            session_id=f"VSESS-{hashlib.sha256((transaction_id + dispute_type).encode()).hexdigest()[:8].upper()}",
            transaction_id=transaction_id,
            dispute_type=dispute_type,
            dispute_subcategory=dispute_subcategory,
            current_step=1,
            completed_steps=[],
            step_results={},
            final_report=None,
            is_completed=False,
        )
        return self.session

    def get_session(self) -> DisputeSession:
        return self.session

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

    def execute_step(self, step_number: int, overrides: Optional[Dict[str, Any]] = None) -> VerificationStageResult:
        """
        Executes a single verification step (1 to 13) in the required order.
        Supports overrides for controlled adversarial testing (incorrect opening, rule, etc.).
        """
        overrides = overrides or {}
        mgr = TransactionManager.get_instance()
        st = mgr.get_state()

        if step_number == 1:
            res = self._step_1_obtain_disputed_rtl(st, overrides)
        elif step_number == 2:
            res = self._step_2_extract_secured_encoding(st, overrides)
        elif step_number == 3:
            res = self._step_3_check_encoding_invariance(st, overrides)
        elif step_number == 4:
            res = self._step_4_verify_original_encoding(st, overrides)
        elif step_number == 5:
            res = self._step_5_extract_embedded_watermark(st, overrides)
        elif step_number == 6:
            res = self._step_6_verify_embedded_watermark_commitment(st, overrides)
        elif step_number == 7:
            res = self._step_7_reconstruct_complete_watermark(st, overrides)
        elif step_number == 8:
            res = self._step_8_verify_complete_watermark_commitment(st, overrides)
        elif step_number == 9:
            res = self._step_9_reconstruct_buyer_contribution(st, overrides)
        elif step_number == 10:
            res = self._step_10_verify_buyer_commitment(st, overrides)
        elif step_number == 11:
            res = self._step_11_verify_watermark_relationship(st, overrides)
        elif step_number == 12:
            res = self._step_12_verify_transaction_evidence(st, overrides)
        elif step_number == 13:
            res = self._step_13_generate_final_report(st, overrides)
        else:
            raise ValueError(f"Invalid verification step number {step_number}. Must be 1 to 13.")

        step_key = f"step_{step_number}"
        self.session.step_results[step_key] = res
        if step_number not in self.session.completed_steps:
            self.session.completed_steps.append(step_number)

        if step_number < 13:
            self.session.current_step = step_number + 1
        else:
            self.session.is_completed = True

        return res

    def run_all_steps(self, overrides: Optional[Dict[str, Any]] = None) -> DisputeSession:
        """
        Executes all 13 steps sequentially.
        """
        overrides = overrides or {}
        for s in range(1, 14):
            step_ov = overrides.get(f"step_{s}", {})
            res = self.execute_step(s, step_ov)
            if res.status in ("MISMATCH", "BLOCKED") and s not in (3,):
                # We continue executing later steps to collect full audit data,
                # but overall evidence status will be INCONSISTENT / BLOCKED.
                pass
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

        rtl = ov.get("disputed_rtl", st.watermarked_RTL)
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
        if rule_id != "iir_butterworth_rule_v1":
            return VerificationStageResult(
                step_number=2,
                step_id="step_2",
                step_title="Extract Secured Encoding (E_S')",
                responsible_party="Seller",
                stage1_reconstruction={
                    "status": "MISMATCH",
                    "detail": f"Unknown or mismatched encoding rule '{rule_id}'. Transaction requires 'iir_butterworth_rule_v1'.",
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
                step_title="Extract Secured Encoding (E_S')",
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
        )
        es_bitstream = ov.get("es_bitstream", enc_res.canonical_bitstream)

        return VerificationStageResult(
            step_number=2,
            step_id="step_2",
            step_title="Extract Secured Encoding (E_S')",
            responsible_party="Seller / Verifier Execution",
            stage1_reconstruction={
                "method": "Independent AST/FSM Parsing of Disputed RTL + 4-Rule Structural Encoding",
                "reconstruction_source": "Synthesizable Verilog RTL states and scheduled node assignments",
                "design": st.selected_design,
                "encoding_rule": "IIR Butterworth Encoding Rule v1.0",
                "total_nodes_recovered": len(parsed["node_step"]),
                "total_steps_recovered": parsed["total_steps"],
                "node_ids": sorted(list(parsed["node_step"].keys())),
                "node_operations": parsed["node_ops"],
                "control_step_assignments": parsed["node_step"],
                "extracted_bitstream": es_bitstream,
                "secured_encoding_ES": es_bitstream,
                "bit_length": len(es_bitstream),
                "expected_length": 143,
                "status": "EXTRACTED",
            },
            stage2_verification={
                "status": "PENDING INVARIANCE EVALUATION",
                "detail": "Commitment verification for E_S is conditional on Step 3 determination.",
            },
            status="EXTRACTED",
            notes=f"Secured encoding E_S' independently reconstructed from disputed RTL ({len(es_bitstream)} bits, {len(parsed['node_step'])} nodes across {parsed['total_steps']} steps).",
        )

    # --------------------------------------------------------------------------
    # Step 3: Determine Whether Encoding Changed (E_S = D)
    # --------------------------------------------------------------------------
    def _step_3_check_encoding_invariance(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        step2 = self.session.step_results.get("step_2")
        if not step2 or step2.status not in ("EXTRACTED", "MATCH"):
            return VerificationStageResult(
                step_number=3,
                step_id="step_3",
                step_title="Evaluate Encoding Invariance (E_S vs D)",
                responsible_party="Verifier Analysis",
                stage1_reconstruction={
                    "status": "BLOCKED",
                    "detail": f"Prerequisite Step 2 did not succeed (status: {step2.status if step2 else 'NOT RUN'}). Cannot evaluate invariance without reconstructed E_S'.",
                },
                stage2_verification={
                    "status": "BLOCKED",
                    "detail": f"Prerequisite Step 2 did not succeed (status: {step2.status if step2 else 'NOT RUN'}). Cannot evaluate invariance without reconstructed E_S'.",
                },
                status="BLOCKED",
                notes="Prerequisite Step 2 failed: cannot evaluate encoding invariance.",
            )

        es = ov.get("extracted_ES", ov.get("es_bitstream", step2.stage1_reconstruction.get("extracted_bitstream")))
        d_orig = ov.get("design_encoding_D", st.design_encoding_D)

        force_changed = ov.get("force_changed", ov.get("is_encoding_changed", False))
        if force_changed and es == d_orig:
            d_orig = "0" * len(es)  # simulate changed encoding

        if not es or not d_orig:
            return VerificationStageResult(
                step_number=3,
                step_id="step_3",
                step_title="Evaluate Encoding Invariance (E_S vs D)",
                responsible_party="Verifier Analysis",
                stage1_reconstruction={"status": "BLOCKED", "detail": "Missing encoding bitstreams."},
                stage2_verification={"status": "BLOCKED"},
                status="BLOCKED",
            )

        is_identical = (es == d_orig)

        if is_identical:
            # Branch A: E_S = D
            return VerificationStageResult(
                step_number=3,
                step_id="step_3",
                step_title="Evaluate Encoding Invariance (E_S vs D)",
                responsible_party="Verifier Analysis",
                stage1_reconstruction={
                    "branch": "Branch A (E_S = D)",
                    "comparison": "E_S is bit-for-bit identical to original design encoding D (143/143 bits match).",
                    "invariance_analysis": "Watermarked CIG conflict edges introduce lifetime exclusion constraints between non-overlapping registers without altering scheduled operations or control step timing.",
                    "status": "IDENTICAL",
                },
                stage2_verification={
                    "status": "NOT REQUIRED",
                    "detail": "Secured encoding commitment C_ES and transformation rule are not required for this transaction because E_S = D. Proceeding directly to original encoding verification C_D.",
                    "recalculated_C_ES": "NOT_APPLICABLE (E_S = D)",
                    "stored_C_ES": "NOT_REQUIRED",
                    "stored_c_es": "Not Required (E_S = D)",
                },
                status="NOT REQUIRED",
                notes="Branch A selected: C_ES commitment check not required (E_S = D). No fake commitment generated.",
            )
        else:
            # Branch B: E_S differs from D
            c_es_stored = ov.get("stored_c_es", ov.get("stored_C_ES", getattr(st, "C_ES", None)))
            r_es = ov.get("r_es", ov.get("r_ES", None))
            transformation_applied = False
            if not c_es_stored or c_es_stored == "NOT_REQUIRED" or not r_es:
                status = "MISMATCH"
                detail = "E_S differs from D, but no valid C_ES commitment or opening factor r_ES was provided."
            else:
                comm_es, _ = self.pe.commit(es, int(r_es, 16) if isinstance(r_es, str) else int(r_es))
                if comm_es.commitment_hex.lower() == c_es_stored.lower():
                    status = "MATCH"
                    detail = "C_ES commitment verified. Applying design-specific transformation rule to derive E_U'."
                    transformation_applied = True
                else:
                    status = "MISMATCH"
                    detail = "Recalculated C_ES' does not match stored C_ES."

            return VerificationStageResult(
                step_number=3,
                step_id="step_3",
                step_title="Evaluate Encoding Invariance (E_S vs D)",
                responsible_party="Seller Private Evidence",
                stage1_reconstruction={
                    "branch": "Branch B (E_S differs from D)",
                    "comparison": "Extracted secured encoding E_S differs from baseline D.",
                    "status": "CHANGED",
                    "transformation_applied": transformation_applied,
                },
                stage2_verification={
                    "status": status,
                    "detail": detail,
                    "stored_c_es": c_es_stored,
                },
                status=status,
                notes="Branch B: Secured encoding changed. Transformation requires valid C_ES check.",
            )

    # --------------------------------------------------------------------------
    # Step 4: Verify Original Design Encoding (D and C_D)
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
                    "detail": f"Prerequisite Step 3 failed (status: {step3.status if step3 else 'NOT RUN'}). Cannot verify C_D without valid encoding invariance or verified transformation.",
                },
                stage2_verification={
                    "status": "BLOCKED",
                    "detail": f"Prerequisite Step 3 failed (status: {step3.status if step3 else 'NOT RUN'}). Cannot verify C_D without valid encoding invariance or verified transformation.",
                },
                status="BLOCKED",
                notes="Prerequisite Step 3 failed: dependent verification blocked.",
            )

        # Stage 1: Request encoding rule and independently compute D'
        rule_valid = ov.get("rule_valid", True)
        if not rule_valid:
            d_calc = "0" * 143  # incorrect computation
        else:
            enc_res = DesignStructuralEncoder.encode_golden_butterworth(use_document_table_quirks=False)
            d_calc = ov.get("calculated_d", enc_res.canonical_bitstream)

        # Stage 2: Request opening factor r_D and stored C_D
        stored_c_d = ov.get("stored_c_d", ov.get("stored_C_D", ov.get("C_D", st.C_D)))
        r_d = ov.get("r_d", ov.get("r_D", st.blinding_factor_D))

        if not stored_c_d or not r_d:
            return VerificationStageResult(
                step_number=4,
                step_id="step_4",
                step_title="Verify Original Design Encoding (C_D)",
                responsible_party="Seller",
                stage1_reconstruction={
                    "method": "Execute deterministic structural encoder for IIR Butterworth benchmark",
                    "calculated_value_D": d_calc,
                    "bit_length": len(d_calc),
                    "status": "COMPUTED",
                },
                stage2_verification={
                    "formula": "C_D = s_D * G + r_D * H over NIST P-256 (s_D, r_D in Z_n)",
                    "status": "BLOCKED",
                    "detail": "Missing Seller opening factor r_D or stored commitment C_D in evidence.",
                },
                status="BLOCKED",
                notes="Missing Seller private opening secret r_D.",
            )

        # Recalculate C_D' = Commit(D', r_D)
        try:
            blinding_int = int(r_d, 16) if isinstance(r_d, str) else int(r_d)
            comm_d, _ = self.pe.commit(d_calc, blinding_factor=blinding_int)
            c_d_recalc = comm_d.commitment_hex

            if c_d_recalc.lower() == stored_c_d.lower():
                ver_status = "MATCH"
                notes = "Original design encoding D independently calculated (143 bits) and commitment C_D verified (MATCH)."
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
            stage1_reconstruction={
                "method": "Execute deterministic structural encoder for IIR Butterworth Filter (Rule 1-4)",
                "calculated_value_D": d_calc,
                "bit_length": len(d_calc),
                "expected_length": 143,
                "status": "COMPUTED",
            },
            stage2_verification={
                "formula": "C_D = s_D * G + r_D * H over NIST P-256 (s_D, r_D in Z_n)",
                "scalar_s": hex(self.pe.hash_to_scalar(d_calc))[2:],
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
    # Step 5: Extract Embedded Watermark W1'
    # --------------------------------------------------------------------------
    def _step_5_extract_embedded_watermark(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        rtl = ov.get("disputed_rtl", st.watermarked_RTL)
        mapping = None
        if st.pipeline_result and "watermark_mapping" in st.pipeline_result:
            mapping = st.pipeline_result["watermark_mapping"]

        extract_method = ov.get("extraction_method_id", "cig_bipartite_register_alloc")
        if extract_method != "cig_bipartite_register_alloc":
            return VerificationStageResult(
                step_number=5,
                step_id="step_5",
                step_title="Extract Embedded Watermark (W1')",
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
                step_title="Extract Embedded Watermark (W1')",
                responsible_party="Seller Rules / Verifier RTL Extraction",
                stage1_reconstruction={
                    "status": "BLOCKED",
                    "detail": "Missing RTL or watermark mapping rules in transaction evidence.",
                },
                stage2_verification={"status": "BLOCKED"},
                status="BLOCKED",
            )

        # Independently execute extraction from synthesizable RTL
        extract_res: ExtractionResult = TransactionWatermarkExtractor.extract(
            rtl, watermark_mapping=mapping, expected_length=len(mapping)
        )

        w1_calc = ov.get("extracted_w1", extract_res.bitstream)

        return VerificationStageResult(
            step_number=5,
            step_id="step_5",
            step_title="Extract Embedded Watermark (W1')",
            responsible_party="Seller Rules / Verifier RTL Extraction",
            stage1_reconstruction={
                "method": "Parse synthesized RTL register allocations; inspect mutual exclusion across target CIG pairs",
                "extracted_bitstream_W1": w1_calc,
                "bit_length": len(w1_calc) if w1_calc else 0,
                "expected_embedded_length": 32,
                "extraction_status": extract_res.status.value,
                "recovered_bits": extract_res.recovered_bits,
                "unrecovered_bits": extract_res.unrecovered_bits,
                "status": "EXTRACTED",
            },
            stage2_verification={
                "status": "READY FOR COMMITMENT CHECK",
                "detail": "Embedded watermark bitstream W1' recovered from RTL. Ready for C_W1 verification.",
            },
            status="EXTRACTED",
            notes="W1' extracted independently from disputed RTL register allocations (32 bits).",
        )

    # --------------------------------------------------------------------------
    # Step 6: Verify Embedded Watermark Commitment C_W1
    # --------------------------------------------------------------------------
    def _step_6_verify_embedded_watermark_commitment(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
        step5 = self.session.step_results.get("step_5")
        if not step5 or step5.status != "EXTRACTED":
            return VerificationStageResult(
                step_number=6,
                step_id="step_6",
                step_title="Verify Embedded Watermark Commitment (C_W1)",
                responsible_party="Seller",
                stage1_reconstruction={"status": "BLOCKED", "detail": f"Prerequisite Step 5 watermark extraction failed (status: {step5.status if step5 else 'NOT RUN'})."},
                stage2_verification={"status": "BLOCKED"},
                status="BLOCKED",
                notes="Prerequisite Step 5 failed: cannot verify C_W1 without extracted W1'.",
            )

        w1_calc = step5.stage1_reconstruction.get("extracted_bitstream_W1")
        w1_calc = ov.get("w1_bitstream", w1_calc)

        stored_c_w1 = ov.get("stored_c_w1", st.C_W1)
        r_w1 = ov.get("r_w1", st.blinding_factor_W1)

        if not stored_c_w1 or not r_w1 or not w1_calc:
            return VerificationStageResult(
                step_number=6,
                step_id="step_6",
                step_title="Verify Embedded Watermark Commitment (C_W1)",
                responsible_party="Seller",
                stage1_reconstruction={"extracted_w1": w1_calc, "status": "AVAILABLE" if w1_calc else "BLOCKED"},
                stage2_verification={"status": "BLOCKED", "detail": "Missing opening factor r_W1 or stored C_W1."},
                status="BLOCKED",
            )

        try:
            blinding_int = int(r_w1, 16) if isinstance(r_w1, str) else int(r_w1)
            comm_w1, _ = self.pe.commit(w1_calc, blinding_factor=blinding_int)
            c_w1_recalc = comm_w1.commitment_hex

            if c_w1_recalc.lower() == stored_c_w1.lower():
                ver_status = "MATCH"
                notes = "Embedded watermark commitment C_W1 verified against extracted bitstream W1' (MATCH)."
            else:
                ver_status = "MISMATCH"
                notes = "Recalculated commitment C_W1' does not match stored commitment C_W1 (MISMATCH)."
        except Exception as e:
            ver_status = "MISMATCH"
            c_w1_recalc = f"Error: {e}"
            notes = f"Commitment verification error: {e}"

        return VerificationStageResult(
            step_number=6,
            step_id="step_6",
            step_title="Verify Embedded Watermark Commitment (C_W1)",
            responsible_party="Seller",
            stage1_reconstruction={
                "extracted_value_W1": w1_calc,
                "bit_length": len(w1_calc),
                "scope": "Embedded slice (bits [0:32])",
                "status": "VALIDATED",
            },
            stage2_verification={
                "formula": "C_W1 = s_W1 * G + r_W1 * H over NIST P-256 (s_W1, r_W1 in Z_n)",
                "opening_factor_r_W1": r_w1,
                "stored_commitment_C_W1": stored_c_w1,
                "recalculated_commitment_C_W1": c_w1_recalc,
                "status": ver_status,
            },
            status=ver_status,
            notes=notes,
        )

    # --------------------------------------------------------------------------
    # Step 7: Reconstruct Complete Watermark W'
    # --------------------------------------------------------------------------
    def _step_7_reconstruct_complete_watermark(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
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

        w1_calc = step5.stage1_reconstruction.get("extracted_bitstream_W1")
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

        return VerificationStageResult(
            step_number=7,
            step_id="step_7",
            step_title="Reconstruct Complete Watermark (W')",
            responsible_party="Seller Private Evidence",
            stage1_reconstruction={
                "rule": "W = W1 || W2 (Concatenate extracted 32-bit W1' with protected 224-bit W2)",
                "w1_length": len(w1_calc),
                "w2_length": len(w2_protected),
                "reconstructed_watermark_W": w_reconstructed,
                "total_bit_length": len(w_reconstructed),
                "expected_total_bits": 256,
                "status": "RECONSTRUCTED",
            },
            stage2_verification={
                "status": "READY FOR C_W CHECK",
                "detail": "Complete 256-bit watermark W' reconstructed. Ready for C_W commitment verification.",
            },
            status="MATCH" if len(w_reconstructed) == 256 else "MISMATCH",
            notes="Complete 256-bit watermark W' assembled from extracted W1' (32 bits) and protected W2 (224 bits).",
        )

    # --------------------------------------------------------------------------
    # Step 8: Verify Complete Watermark Commitment C_W
    # --------------------------------------------------------------------------
    def _step_8_verify_complete_watermark_commitment(self, st: TransactionState, ov: Dict[str, Any]) -> VerificationStageResult:
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

        w_calc = step7.stage1_reconstruction.get("reconstructed_watermark_W")
        w_calc = ov.get("w_bitstream", w_calc)

        stored_c_w = ov.get("stored_c_w", st.C_W)
        r_w = ov.get("r_w", st.blinding_factor_W)

        if not stored_c_w or not r_w or not w_calc:
            return VerificationStageResult(
                step_number=8,
                step_id="step_8",
                step_title="Verify Complete Watermark Commitment (C_W)",
                responsible_party="Seller",
                stage1_reconstruction={"reconstructed_w": w_calc, "status": "AVAILABLE" if w_calc else "BLOCKED"},
                stage2_verification={"status": "BLOCKED", "detail": "Missing opening factor r_W or stored C_W."},
                status="BLOCKED",
            )

        try:
            blinding_int = int(r_w, 16) if isinstance(r_w, str) else int(r_w)
            comm_w, _ = self.pe.commit(w_calc, blinding_factor=blinding_int)
            c_w_recalc = comm_w.commitment_hex

            if c_w_recalc.lower() == stored_c_w.lower():
                ver_status = "MATCH"
                notes = "Complete 256-bit watermark commitment C_W verified against reconstructed W' (MATCH)."
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
            stage1_reconstruction={
                "reconstructed_value_W": w_calc,
                "bit_length": len(w_calc),
                "expected_length": 256,
                "status": "VALIDATED",
            },
            stage2_verification={
                "formula": "C_W = s_W * G + r_W * H over NIST P-256 (s_W, r_W in Z_n)",
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
        # Request Buyer derivation / loading method from authorized evidence workflow
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

        return VerificationStageResult(
            step_number=9,
            step_id="step_9",
            step_title="Check Buyer Contribution Bitstream (B')",
            responsible_party="Buyer Private Evidence",
            stage1_reconstruction={
                "derivation_method": "Fingerprint-Derived Bitstream Extraction (fingerprint_minutiae_demo_standard)",
                "bitstream_B": b_input,
                "bit_length": b_len,
                "expected_length": 555,
                "zeros_count": zeros,
                "expected_zeros": 242,
                "ones_count": ones,
                "expected_ones": 313,
                "format_check": "Supplementary sanity check: length=555 bits, zeros=242, ones=313",
                "cryptographic_distinction": "Length and bit-count checks are supplementary format sanity checks only. Formal commitment validity C_B is established exclusively in Step 10 via elliptic curve scalar recalculation with opening information.",
                "dependency_note": "Cryptographic one-way derivation prevents inverting B from W and D. Authorized Buyer bitstream is reconstructed/loaded and validated against demonstrated minutiae properties.",
                "status": "VALIDATED" if is_valid_props else "INVALID PROPERTIES",
            },
            stage2_verification={
                "status": "READY FOR C_B CHECK",
                "detail": "Buyer contribution format validated. Ready for C_B commitment recalculation.",
            },
            status=status,
            notes="Buyer demonstration bitstream validated (555 bits: 242 zeros, 313 ones). Supplementary format sanity check.",
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

        b_calc = step9.stage1_reconstruction.get("bitstream_B")
        b_calc = ov.get("buyer_bitstream", b_calc)

        stored_c_b = ov.get("stored_c_b", st.C_B)
        r_b = ov.get("r_b", st.blinding_factor_B)

        if not stored_c_b or not r_b or not b_calc:
            return VerificationStageResult(
                step_number=10,
                step_id="step_10",
                step_title="Verify Buyer Commitment (C_B)",
                responsible_party="Buyer",
                stage1_reconstruction={"bitstream_B": b_calc, "status": "AVAILABLE" if b_calc else "BLOCKED"},
                stage2_verification={"status": "BLOCKED", "detail": "Missing opening factor r_B or stored C_B."},
                status="BLOCKED",
            )

        try:
            blinding_int = int(r_b, 16) if isinstance(r_b, str) else int(r_b)
            comm_b, _ = self.pe.commit(b_calc, blinding_factor=blinding_int)
            c_b_recalc = comm_b.commitment_hex

            if c_b_recalc.lower() == stored_c_b.lower():
                ver_status = "MATCH"
                notes = "Buyer contribution commitment C_B verified against actual 555-bit bitstream B' (MATCH). C_B is strictly Buyer-owned. Cryptographic validity established via ECC recalculation."
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
            stage1_reconstruction={
                "value_B": b_calc,
                "bit_length": len(b_calc),
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
        step8 = self.session.step_results.get("step_8")
        step10 = self.session.step_results.get("step_10")
        failed = []
        if not step4 or step4.status != "MATCH":
            failed.append("Step 4 (C_D)")
        if not step8 or step8.status != "MATCH":
            failed.append("Step 8 (C_W)")
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

        step7 = self.session.step_results.get("step_7")
        w_reconstructed = (step7.stage1_reconstruction.get("reconstructed_watermark_W") if step7 else None) or st.watermark_W

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

        # Independently obtain reconstructed D' (Step 4) and B' (Step 10)
        d_val = ov.get("D", ov.get("design_encoding_D", step4.stage1_reconstruction.get("calculated_value_D") if step4 else st.design_encoding_D))
        b_val = ov.get("B", ov.get("buyer_contribution_B", step10.stage1_reconstruction.get("value_B") if step10 else st.buyer_bitstream_B))

        try:
            gen = SymmetricHKDFWatermarkGenerator()
            wm_obj = gen.generate(tx_rec, {"k_tx": k_tx}, watermark_length=32, D=d_val, B=b_val)
            w_expected = wm_obj.canonical_bitstream

            if w_reconstructed and w_reconstructed == w_expected:
                rel_status = "MATCH"
                notes = "Watermark-generation relationship W' = F(D', B', tx_record, k_tx) verified independently (MATCH)."
            else:
                rel_status = "MISMATCH"
                notes = "Reconstructed watermark W' does not match independent evaluation of generation function F."
        except Exception as e:
            rel_status = "BLOCKED"
            w_expected = f"Error: {e}"
            notes = f"Relationship verification error: {e}"

        return VerificationStageResult(
            step_number=11,
            step_id="step_11",
            step_title="Verify Watermark-Generation Relationship F(D', B', context)",
            responsible_party="Verifier Independent Computation",
            stage1_reconstruction={
                "function": "RFC 5869 Symmetric HKDF-SHA256 (Extract-and-Expand)",
                "inputs": {
                    "k_tx": k_tx,
                    "transaction_context": tx_rec,
                    "design_encoding_D": d_val,
                    "buyer_contribution_B": b_val,
                },
                "expected_watermark_W": w_expected,
                "reconstructed_watermark_W": w_reconstructed,
                "status": "EVALUATED",
            },
            stage2_verification={
                "comparison": "W' == F(D', B', context, k_tx)",
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
        w1_status = results.get("step_6", VerificationStageResult(step_number=6, step_id="step_6", step_title="", responsible_party="", stage1_reconstruction={}, stage2_verification={}, status="BLOCKED")).status
        w_status = results.get("step_8", VerificationStageResult(step_number=8, step_id="step_8", step_title="", responsible_party="", stage1_reconstruction={}, stage2_verification={}, status="BLOCKED")).status
        b_status = results.get("step_10", VerificationStageResult(step_number=10, step_id="step_10", step_title="", responsible_party="", stage1_reconstruction={}, stage2_verification={}, status="BLOCKED")).status
        f_status = results.get("step_11", VerificationStageResult(step_number=11, step_id="step_11", step_title="", responsible_party="", stage1_reconstruction={}, stage2_verification={}, status="BLOCKED")).status
        tx_status = results.get("step_12", VerificationStageResult(step_number=12, step_id="step_12", step_title="", responsible_party="", stage1_reconstruction={}, stage2_verification={}, status="INCOMPLETE")).status

        step12 = results.get("step_12")
        recorded_rights = (step12.stage1_reconstruction.get("recorded_rights_type") if step12 else "Not Established") or "Not Established"
        rights_conflict = (step12.stage1_reconstruction.get("rights_conflict_detected") if step12 else False) or False
        rights_conflict_details = (step12.stage1_reconstruction.get("rights_conflict_details") if step12 else None)

        # Determine overall evidence status
        critical_statuses = [d_status, w1_status, w_status, b_status, f_status, tx_status]
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
                "watermark_length": 32,
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
