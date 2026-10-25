"""
Session and Persistence Manager for Judge-Led Interrogation (143-Bit Stage).

Provides:
- SQLite persistence in `protection_records.db` under table `judge_interrogation_sessions`.
- Progressive question sequencing (one question at a time).
- Append-only audit history ledger preserving original answers and corrections.
- Non-destructive correction mechanism.
- P1 soft-hypothesis failure handling with 4 fallback questions.
- Optional Block 5b toggle.
- Bit-level candidate reconstruction and provenance.
"""

import sqlite3
import json
import os
import uuid
from typing import Dict, Any, List, Optional, Tuple, Union
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from hardware_ip_protection.verification.interrogation_engine import (
    InterrogationEngine,
    QuestionDefinition,
    QuestionType,
    LedgerEntry,
    FactStatus,
)
from hardware_ip_protection.pipeline.repository import ProtectionRepository


class InterrogationSessionRecord(BaseModel):
    session_id: str
    transaction_id: str
    claimant_id: str
    workflow: str = "unsecured_design_encoding"
    branch: str = "E_U"
    block5b_enabled: bool = False
    stage_name: str = "143-bit four-rule encoding"
    status: str = "IN PROGRESS"
    answers: Dict[str, Any] = Field(default_factory=dict)
    history_ledger: List[LedgerEntry] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class InterrogationManager:
    """
    Manages Judge-Led Interrogation sessions and audit ledgers.
    """

    _instance = None

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.db_path = os.path.join(base_dir, "protection_records.db")
        else:
            self.db_path = db_path
        self._init_db()

    @classmethod
    def get_instance(cls, db_path: Optional[str] = None) -> "InterrogationManager":
        if cls._instance is None:
            cls._instance = cls(db_path)
        return cls._instance

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS judge_interrogation_sessions (
                    session_id TEXT PRIMARY KEY,
                    transaction_id TEXT NOT NULL,
                    claimant_id TEXT NOT NULL,
                    workflow TEXT NOT NULL DEFAULT 'unsecured_design_encoding',
                    branch TEXT NOT NULL DEFAULT 'E_U',
                    block5b_enabled INTEGER NOT NULL DEFAULT 0,
                    stage_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    answers_json TEXT NOT NULL,
                    history_ledger_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            cursor.execute("PRAGMA table_info(judge_interrogation_sessions)")
            cols = [col[1] for col in cursor.fetchall()]
            if "workflow" not in cols:
                cursor.execute("ALTER TABLE judge_interrogation_sessions ADD COLUMN workflow TEXT NOT NULL DEFAULT 'unsecured_design_encoding'")
            conn.commit()

    def _save_session(self, session: InterrogationSessionRecord) -> None:
        session.updated_at = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO judge_interrogation_sessions (
                    session_id, transaction_id, claimant_id, workflow, branch, block5b_enabled,
                    stage_name, status, answers_json, history_ledger_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    transaction_id = excluded.transaction_id,
                    claimant_id = excluded.claimant_id,
                    workflow = excluded.workflow,
                    branch = excluded.branch,
                    block5b_enabled = excluded.block5b_enabled,
                    stage_name = excluded.stage_name,
                    status = excluded.status,
                    answers_json = excluded.answers_json,
                    history_ledger_json = excluded.history_ledger_json,
                    updated_at = excluded.updated_at
            """, (
                session.session_id,
                session.transaction_id,
                session.claimant_id,
                session.workflow,
                session.branch,
                1 if session.block5b_enabled else 0,
                session.stage_name,
                session.status,
                json.dumps(session.answers),
                json.dumps([e.model_dump() for e in session.history_ledger]),
                session.created_at,
                session.updated_at,
            ))
            conn.commit()

    def get_session(
        self,
        session_id: Optional[str] = None,
        transaction_id: Optional[str] = None,
        workflow: Optional[str] = None,
    ) -> Optional[InterrogationSessionRecord]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if session_id:
                cursor.execute("SELECT * FROM judge_interrogation_sessions WHERE session_id = ?", (session_id,))
            elif transaction_id and workflow:
                cursor.execute(
                    "SELECT * FROM judge_interrogation_sessions WHERE transaction_id = ? AND workflow = ? ORDER BY updated_at DESC LIMIT 1",
                    (transaction_id, workflow),
                )
            elif transaction_id:
                cursor.execute("SELECT * FROM judge_interrogation_sessions WHERE transaction_id = ? ORDER BY updated_at DESC LIMIT 1", (transaction_id,))
            else:
                cursor.execute("SELECT * FROM judge_interrogation_sessions ORDER BY updated_at DESC LIMIT 1")
            row = cursor.fetchone()
            if not row:
                return None

            row_keys = row.keys()
            wf = row["workflow"] if "workflow" in row_keys else "unsecured_design_encoding"

            return InterrogationSessionRecord(
                session_id=row["session_id"],
                transaction_id=row["transaction_id"],
                claimant_id=row["claimant_id"],
                workflow=wf,
                branch=row["branch"],
                block5b_enabled=bool(row["block5b_enabled"]),
                stage_name=row["stage_name"],
                status=row["status"],
                answers=json.loads(row["answers_json"]),
                history_ledger=[LedgerEntry(**item) for item in json.loads(row["history_ledger_json"])],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

    def _get_commitment_params(self, transaction_id: str, workflow: str) -> Tuple[Optional[str], Optional[int]]:
        """
        Retrieves stored C_ES and blinding factor r_ES for commitment verification.
        Confidential: blinding factor is used internally and never exposed in claimant views.
        """
        stored_c_es = None
        blinding_int = None
        if workflow == "secured_design_encoding":
            try:
                from hardware_ip_protection.pipeline.transaction_manager import TransactionManager
                tm = TransactionManager.get_instance()
                st = tm.get_state()
                if st.C_ES and st.C_ES != "NOT_REQUIRED":
                    stored_c_es = st.C_ES
                    if st.blinding_factor_ES:
                        blinding_int = int(st.blinding_factor_ES, 16)
                else:
                    from hardware_ip_protection.crypto.pedersen import PedersenEngine
                    from hardware_ip_protection.verification.interrogation_engine import EXPECTED_251_SECURED_BITSTREAM
                    pe = PedersenEngine()
                    comm_ES, r_ES = pe.commit(EXPECTED_251_SECURED_BITSTREAM)
                    st.C_ES = comm_ES.commitment_hex
                    st.blinding_factor_ES = hex(r_ES)[2:].zfill(64)
                    stored_c_es = st.C_ES
                    blinding_int = r_ES
            except Exception:
                pass
        return stored_c_es, blinding_int

    def start_session(
        self,
        transaction_id: str,
        claimant_id: str = "BUYER-001",
        workflow: str = "unsecured_design_encoding",
        branch: str = "E_U",
        block5b_enabled: bool = False,
    ) -> InterrogationSessionRecord:
        """
        Starts a new interrogation session or resumes an existing one for the transaction and workflow.
        """
        existing = self.get_session(transaction_id=transaction_id, workflow=workflow)
        if existing:
            return existing

        session_id = f"JIS-{uuid.uuid4().hex[:12].upper()}"
        stage_name = (
            "251-bit secured design encoding (Rule 1-5)"
            if workflow == "secured_design_encoding"
            else "143-bit four-rule encoding"
        )
        session = InterrogationSessionRecord(
            session_id=session_id,
            transaction_id=transaction_id,
            claimant_id=claimant_id,
            workflow=workflow,
            branch=branch,
            block5b_enabled=block5b_enabled,
            stage_name=stage_name,
            status="IN PROGRESS",
            answers={},
            history_ledger=[],
        )
        self._save_session(session)
        return session

    def create_session(
        self,
        transaction_id: Optional[str] = None,
        claimant_id: str = "BUYER-001",
        workflow: str = "unsecured_design_encoding",
        branch: str = "E_U",
        block5b_enabled: bool = False,
    ) -> InterrogationSessionRecord:
        """
        Creates a new interrogation session with an auto-generated transaction ID if none is supplied.
        """
        if not transaction_id:
            transaction_id = f"TX-ADAPTIVE-{uuid.uuid4().hex[:8].upper()}"
        return self.start_session(
            transaction_id=transaction_id,
            claimant_id=claimant_id,
            workflow=workflow,
            branch=branch,
            block5b_enabled=block5b_enabled,
        )

    def reset_session(self, session_id: str) -> Optional[InterrogationSessionRecord]:
        session = self.get_session(session_id=session_id)
        if not session:
            return None
        session.answers = {}
        session.history_ledger = []
        session.status = "IN PROGRESS"
        self._save_session(session)
        return session

    def toggle_block5b(self, session_id: str, enabled: bool) -> Optional[InterrogationSessionRecord]:
        session = self.get_session(session_id=session_id)
        if not session:
            return None
        session.block5b_enabled = enabled
        c_es, b_int = self._get_commitment_params(session.transaction_id, session.workflow)
        eval_res = InterrogationEngine.evaluate_state(
            session.answers,
            workflow=session.workflow,
            block5b_enabled=enabled,
            stored_c_es=c_es,
            blinding_int=b_int,
        )
        session.status = eval_res["outcome"]
        self._save_session(session)
        return session

    def submit_answer(
        self,
        session_id: str,
        question_id: str,
        raw_answer: Any,
    ) -> Dict[str, Any]:
        session = self.get_session(session_id=session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found.")

        # Find question definition for this workflow
        q_bank = InterrogationEngine.build_question_bank(
            workflow=session.workflow,
            block5b_enabled=session.block5b_enabled,
        )
        q_map = {q.id: q for q in q_bank}
        if question_id not in q_map:
            raise ValueError(f"Question {question_id} is not a valid question in the active schema.")

        q_def = q_map[question_id]
        c_es, b_int = self._get_commitment_params(session.transaction_id, session.workflow)

        # Check if already in contradiction
        curr_eval = InterrogationEngine.evaluate_state(
            session.answers,
            workflow=session.workflow,
            block5b_enabled=session.block5b_enabled,
            stored_c_es=c_es,
            blinding_int=b_int,
        )
        if curr_eval["outcome"] == "CONTRADICTION":
            raise ValueError("Interrogation has encountered a contradiction. You must correct an inconsistent answer before proceeding.")

        # Check if this question is the expected next active question
        next_q = InterrogationEngine.get_next_question(
            session.answers,
            workflow=session.workflow,
            p1_failed=curr_eval["p1_failed"],
            block5b_enabled=session.block5b_enabled,
        )
        if next_q and next_q.id != question_id and question_id not in session.answers:
            # Enforce progressive order for new answers
            raise ValueError(f"Progressive interrogation order violated: Expected {next_q.id}, got {question_id}.")

        # Validate answer type
        parsed_answer, val_err = self._parse_and_validate_answer(q_def, raw_answer)
        if val_err:
            raise ValueError(val_err)

        # Update answers dict
        session.answers[question_id] = parsed_answer

        # Run deterministic evaluation
        eval_res = InterrogationEngine.evaluate_state(
            session.answers,
            workflow=session.workflow,
            block5b_enabled=session.block5b_enabled,
            stored_c_es=c_es,
            blinding_int=b_int,
        )
        session.status = eval_res["outcome"]

        # Append to audit ledger
        entry_status = "CONTRADICTION" if eval_res["contradictions"] else "OBSERVED"
        msg = "These answers cannot both be true." if eval_res["contradictions"] else "Answer accepted and verified against active structural constraints."
        if eval_res.get("p1_failed") and question_id in ("Q5.8", "Q5.9"):
            msg = "Soft hypothesis P1 (Field D Constancy) failed. Retracting inferred values for units 2, 5, 7, 10 and activating fallback questions."

        entry_id = len(session.history_ledger) + 1
        ledger_entry = LedgerEntry(
            entry_id=entry_id,
            question_id=question_id,
            question_prompt=q_def.prompt,
            submitted_answer=raw_answer,
            effective_answer=parsed_answer,
            status=entry_status,
            message=msg,
            is_correction=False,
            corrected_entry_id=None,
        )
        session.history_ledger.append(ledger_entry)

        self._save_session(session)
        return self.get_session_view(session.session_id)

    def submit_correction(
        self,
        session_id: str,
        question_id: str,
        corrected_answer: Any,
    ) -> Dict[str, Any]:
        """
        Non-destructive correction: appends a new ledger entry with is_correction=True,
        updates effective_answers, and recomputes all constraints and provenance from scratch.
        """
        session = self.get_session(session_id=session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found.")

        q_bank = InterrogationEngine.build_question_bank(
            workflow=session.workflow,
            block5b_enabled=session.block5b_enabled,
        )
        q_map = {q.id: q for q in q_bank}
        if question_id not in q_map:
            raise ValueError(f"Question {question_id} is not recognized.")

        q_def = q_map[question_id]

        parsed_answer, val_err = self._parse_and_validate_answer(q_def, corrected_answer)
        if val_err:
            raise ValueError(val_err)

        # Find prior entry ID for this question
        prior_entry_id = None
        for entry in reversed(session.history_ledger):
            if entry.question_id == question_id:
                prior_entry_id = entry.entry_id
                break

        # Update answers
        session.answers[question_id] = parsed_answer

        # Prune downstream answers whose preconditions are no longer satisfied
        changed = True
        while changed:
            changed = False
            temp_eval = InterrogationEngine.evaluate_state(
                session.answers,
                workflow=session.workflow,
                block5b_enabled=session.block5b_enabled,
            )
            curr_facts = set(temp_eval["facts"].keys())

            for ans_qid in list(session.answers.keys()):
                if ans_qid in (question_id, "Q0.1", "Q0.2"):
                    continue
                if ans_qid in q_map:
                    preconds = q_map[ans_qid].preconditions or []
                    all_met = True
                    for p in preconds:
                        if "=" in p:
                            k, expected_v = p.split("=", 1)
                            actual_fact = temp_eval["facts"].get(k, {})
                            if str(actual_fact.get("val", "")).lower() != expected_v.lower():
                                all_met = False
                                break
                        else:
                            if p not in curr_facts:
                                all_met = False
                                break
                    if not all_met:
                        del session.answers[ans_qid]
                        changed = True

        # Re-evaluate all constraints
        c_es, b_int = self._get_commitment_params(session.transaction_id, session.workflow)
        eval_res = InterrogationEngine.evaluate_state(
            session.answers,
            workflow=session.workflow,
            block5b_enabled=session.block5b_enabled,
            stored_c_es=c_es,
            blinding_int=b_int,
        )
        session.status = eval_res["outcome"]

        entry_status = "CONTRADICTION" if eval_res["contradictions"] else "OBSERVED"
        msg = "These answers cannot both be true." if eval_res["contradictions"] else f"Answer corrected and verified. Dependent constraints re-evaluated."

        entry_id = len(session.history_ledger) + 1
        ledger_entry = LedgerEntry(
            entry_id=entry_id,
            question_id=question_id,
            question_prompt=q_def.prompt,
            submitted_answer=corrected_answer,
            effective_answer=parsed_answer,
            status=entry_status,
            message=msg,
            is_correction=True,
            corrected_entry_id=prior_entry_id,
        )
        session.history_ledger.append(ledger_entry)

        self._save_session(session)
        return self.get_session_view(session.session_id)

    def _parse_and_validate_answer(self, q_def: QuestionDefinition, raw: Any) -> Tuple[Any, Optional[str]]:
        if raw is None or str(raw).strip() == "":
            return None, "Answer cannot be empty."

        if q_def.question_type == QuestionType.BOOLEAN:
            s = str(raw).strip().lower()
            if s in ("yes", "y", "true", "1"):
                return "yes", None
            elif s in ("no", "n", "false", "0"):
                return "no", None
            else:
                return None, f"Invalid binary selection: Expected 'yes' or 'no', got '{raw}'."

        elif q_def.question_type == QuestionType.INTEGER:
            try:
                val = int(str(raw).strip())
            except ValueError:
                return None, f"Invalid integer value: '{raw}'."
            if q_def.min_val is not None and val < q_def.min_val:
                return None, f"Value out of bounds: Minimum is {q_def.min_val}, got {val}."
            if q_def.max_val is not None and val > q_def.max_val:
                return None, f"Value out of bounds: Maximum is {q_def.max_val}, got {val}."
            return val, None

        elif q_def.question_type == QuestionType.CHOICE:
            s = str(raw).strip()
            # Special case Q0.3 backward compatibility: numeric part count
            if q_def.id == "Q0.3":
                if (s.isdigit() and int(s) >= 2) or (isinstance(raw, int) and raw >= 2):
                    return "yes", None
                if s == "1" or (isinstance(raw, int) and raw == 1):
                    return "no", None

            if q_def.choices:
                lower_choices = {c.lower(): c for c in q_def.choices}
                s_low = s.lower()
                if s_low in lower_choices:
                    return lower_choices[s_low], None
                if "yes" in lower_choices and s_low in ("yes", "y", "true", "1"):
                    return lower_choices["yes"], None
                if "no" in lower_choices and s_low in ("no", "n", "false", "0"):
                    return lower_choices["no"], None
                if "unknown" in lower_choices and s_low in ("unknown", "u", "cannot determine", "null"):
                    return lower_choices["unknown"], None
                return None, f"Invalid choice: Must be one of {q_def.choices}."
            return s, None

        return str(raw).strip(), None

    def get_session_view(self, session_id: str) -> Dict[str, Any]:
        session = self.get_session(session_id=session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found.")

        # Evaluate engine state with stored commitment parameters (confidential blinding factor used internally)
        c_es, b_int = self._get_commitment_params(session.transaction_id, session.workflow)
        eval_res = InterrogationEngine.evaluate_state(
            session.answers,
            workflow=session.workflow,
            block5b_enabled=session.block5b_enabled,
            stored_c_es=c_es,
            blinding_int=b_int,
        )

        # Get active questions
        active_q = InterrogationEngine.get_active_questions(
            workflow=session.workflow,
            p1_failed=eval_res["p1_failed"],
            block5b_enabled=session.block5b_enabled,
        )
        active_count = len(active_q)

        # Count answered in active list
        answered_count = sum(1 for q in active_q if q.id in session.answers and session.answers[q.id] is not None)

        # Completion status check
        is_finished = (
            eval_res["is_complete_251"]
            if session.workflow == "secured_design_encoding"
            else eval_res["is_complete_143"]
        )
        if eval_res["outcome"].startswith("COMPLETE"):
            is_finished = True

        # Get current question if in progress and not contradiction / unsupported / incomplete
        current_question = None
        is_halted = (
            eval_res["outcome"] in ("CONTRADICTION", "UNSUPPORTED_BRANCH")
            or eval_res["outcome"].startswith("INCOMPLETE")
            or eval_res["outcome"] == "COMMITMENT_MISMATCH"
        )
        if not is_halted and not is_finished:
            next_q = InterrogationEngine.get_next_question(
                session.answers,
                workflow=session.workflow,
                p1_failed=eval_res["p1_failed"],
                block5b_enabled=session.block5b_enabled,
            )
            if next_q:
                # Return question to judge/claimant without reference_answer!
                current_question = {
                    "id": next_q.id,
                    "block_id": next_q.block_id,
                    "block_title": next_q.block_title,
                    "prompt": next_q.prompt,
                    "question_type": next_q.question_type.value,
                    "min_val": next_q.min_val,
                    "max_val": next_q.max_val,
                    "choices": next_q.choices,
                    "is_probe": next_q.is_probe,
                    "is_fallback": next_q.is_fallback,
                }

        candidate_space = eval_res.get("candidate_space") or (eval_res.get("reconstruction_state") or {}).get("candidate_space", {})
        res_percentage = candidate_space.get("resolution_percentage", round((answered_count / active_count) * 100, 1) if active_count > 0 else 0)

        return {
            "session_id": session.session_id,
            "transaction_id": session.transaction_id,
            "claimant_id": session.claimant_id,
            "workflow": session.workflow,
            "branch": session.branch,
            "stage_name": session.stage_name,
            "block5b_enabled": session.block5b_enabled,
            "status": eval_res["outcome"],
            "progress": {
                "answered_count": answered_count,
                "total_active_questions": active_count,
                "percentage": res_percentage,
                "candidate_space": candidate_space,
            },
            "candidate_space": candidate_space,
            "current_question": current_question,
            "history_ledger": [e.model_dump() for e in session.history_ledger],
            "answers": session.answers,
            "effective_answers": session.answers,
            "evaluation": {
                "outcome": eval_res["outcome"],
                "contradictions": eval_res["contradictions"],
                "facts": eval_res["facts"],
                "retracted_facts": eval_res["retracted_facts"],
                "soft_hypotheses": eval_res["soft_hypotheses"],
                "p1_failed": eval_res["p1_failed"],
                "unit_candidates": eval_res["unit_candidates"],
                "pair_candidates": eval_res.get("pair_candidates", []),
                "reconstructed_bitstream": eval_res["reconstructed_bitstream"],
                "reconstructed_part1_143": eval_res.get("reconstructed_part1_143", ""),
                "reconstructed_part2_108": eval_res.get("reconstructed_part2_108", ""),
                "bit_provenance": eval_res["bit_provenance"],
                "bit_statistics": eval_res["bit_statistics"],
                "is_complete_143": eval_res["is_complete_143"],
                "is_complete_rule5": eval_res.get("is_complete_rule5", False),
                "is_complete_251": eval_res.get("is_complete_251", False),
                "reconstruction_state": eval_res.get("reconstruction_state"),
                "stages": eval_res.get("stages", {}),
                "commitment_verification": eval_res.get("commitment_verification", {}),
            },
            "reconstruction_state": eval_res.get("reconstruction_state"),
            "stages": eval_res.get("stages", {}),
            "pair_candidates": eval_res.get("pair_candidates", []),
            "commitment_verification": eval_res.get("commitment_verification", {}),
            "created_at": session.created_at,
            "updated_at": session.updated_at,
        }
