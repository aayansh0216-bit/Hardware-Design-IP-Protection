"""
Minimal SQLite Persistence Layer for Hardware IP Protection Records.

Distinguishes protection_id and transaction_id, supports record versioning,
and stores full canonical provenance, cryptographic commitments, and reconstruction metadata.
"""

import sqlite3
import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


class ProtectionRepository:
    """
    SQLite repository for storing and querying protection records.
    """

    _instance = None

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            # Default to local database file in workspace
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.db_path = os.path.join(base_dir, "protection_records.db")
        else:
            self.db_path = db_path
        self._init_db()

    @classmethod
    def get_instance(cls, db_path: Optional[str] = None) -> "ProtectionRepository":
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
                CREATE TABLE IF NOT EXISTS protection_records (
                    protection_id TEXT PRIMARY KEY,
                    transaction_id TEXT NOT NULL,
                    design_hash TEXT NOT NULL,
                    seller_id TEXT NOT NULL,
                    buyer_id TEXT NOT NULL,
                    license_type TEXT NOT NULL,
                    canonical_watermark_length INTEGER NOT NULL,
                    embedded_watermark_length INTEGER NOT NULL,
                    remaining_watermark_length INTEGER NOT NULL,
                    watermark_hash TEXT NOT NULL,
                    watermark_commitment TEXT NOT NULL,
                    watermark_blinding_factor TEXT,
                    watermark_mapping_json TEXT,
                    cig_constraints_json TEXT,
                    register_bindings_json TEXT,
                    test_vector_hash TEXT,
                    test_vector_commitment TEXT,
                    original_rtl_hash TEXT,
                    protected_rtl_hash TEXT,
                    created_at TEXT NOT NULL,
                    protocol_version TEXT NOT NULL,
                    full_record_json TEXT NOT NULL
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tx_id ON protection_records(transaction_id)")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS verifier_step_hashes (
                    session_id TEXT NOT NULL,
                    transaction_id TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    attempt_id INTEGER NOT NULL DEFAULT 1,
                    canonical_hash TEXT NOT NULL,
                    hash_algorithm TEXT NOT NULL,
                    artifact_id TEXT,
                    recorded_at TEXT NOT NULL,
                    opening_released INTEGER NOT NULL DEFAULT 0,
                    opening_released_at TEXT,
                    PRIMARY KEY (session_id, step_id, attempt_id)
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS seller_securing_reports (
                    report_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    transaction_id TEXT NOT NULL,
                    design_id TEXT NOT NULL,
                    design_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    duration_ms REAL NOT NULL,
                    report_json TEXT NOT NULL
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rep_tx ON seller_securing_reports(transaction_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rep_run ON seller_securing_reports(run_id)")
            conn.commit()


    def save(self, record: Any) -> str:
        """
        Saves or updates a protection record in SQLite.
        Accepts dict or Pydantic model. Returns protection_id.
        """
        if hasattr(record, "model_dump"):
            data = record.model_dump()
        elif isinstance(record, dict):
            data = dict(record)
        else:
            raise ValueError("Record must be a dict or Pydantic model")

        protection_id = data.get("protection_id", "")
        tx_data = data.get("transaction", {})
        tx_id = tx_data.get("transaction_id", "")
        design_data = data.get("design", {})
        design_hash = design_data.get("design_hash", tx_data.get("design_hash", ""))
        seller_id = tx_data.get("seller_id", "")
        buyer_id = tx_data.get("buyer_id", "")
        license_type = tx_data.get("license_type", "exclusive")
        protocol_version = tx_data.get("protocol_version", "1.0")

        canonical_len = data.get("canonical_watermark_length", 256)
        embedded_len = data.get("embedded_watermark_length", data.get("transaction_watermark", {}).get("bit_length", 16))
        remaining_len = data.get("remaining_watermark_length", max(0, canonical_len - embedded_len))

        wm_data = data.get("transaction_watermark", {})
        wm_hash = wm_data.get("watermark_hash", "")
        wm_comm = wm_data.get("commitment", "")
        wm_blind = wm_data.get("blinding_factor_hex", data.get("watermark_blinding_factor", ""))

        tv_data = data.get("test_vectors", {})
        tv_hash = tv_data.get("vector_hash", "")
        tv_comm = tv_data.get("commitment", "")

        wm_mapping_json = json.dumps(data.get("watermark_mapping", []))
        cig_constraints_json = json.dumps(data.get("cig_constraints", []))
        reg_bindings_json = json.dumps(data.get("register_bindings", {}))

        orig_rtl_hash = data.get("original_rtl_sha256", "")
        prot_rtl_hash = data.get("protected_rtl_sha256", "")

        created_at = data.get("provenance", {}).get("timestamp", datetime.now(timezone.utc).isoformat())
        full_json = json.dumps(data)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO protection_records (
                    protection_id, transaction_id, design_hash, seller_id, buyer_id,
                    license_type, canonical_watermark_length, embedded_watermark_length,
                    remaining_watermark_length, watermark_hash, watermark_commitment,
                    watermark_blinding_factor, watermark_mapping_json, cig_constraints_json,
                    register_bindings_json, test_vector_hash, test_vector_commitment,
                    original_rtl_hash, protected_rtl_hash, created_at, protocol_version,
                    full_record_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                protection_id, tx_id, design_hash, seller_id, buyer_id,
                license_type, canonical_len, embedded_len,
                remaining_len, wm_hash, wm_comm,
                wm_blind, wm_mapping_json, cig_constraints_json,
                reg_bindings_json, tv_hash, tv_comm,
                orig_rtl_hash, prot_rtl_hash, created_at, protocol_version,
                full_json
            ))
            conn.commit()

        return protection_id

    def get(self, protection_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a protection record by protection_id.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT full_record_json FROM protection_records WHERE protection_id = ?", (protection_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row["full_record_json"])
        return None

    def find_by_transaction_id(self, transaction_id: str) -> List[Dict[str, Any]]:
        """
        Finds all protection records matching a transaction_id (e.g. multiple versions).
        """
        records = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT full_record_json FROM protection_records WHERE transaction_id = ? ORDER BY created_at DESC",
                (transaction_id,)
            )
            for row in cursor.fetchall():
                records.append(json.loads(row["full_record_json"]))
        return records

    def list_all(self) -> List[Dict[str, Any]]:
        """
        Lists summary of all stored protection records.
        """
        results = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT protection_id, transaction_id, design_hash, seller_id, buyer_id, "
                "canonical_watermark_length, embedded_watermark_length, watermark_hash, created_at "
                "FROM protection_records ORDER BY created_at DESC"
            )
            for row in cursor.fetchall():
                results.append(dict(row))
        return results

    def record_step_hash(
        self,
        session_id: str,
        transaction_id: str,
        step_id: str,
        canonical_hash: str,
        hash_algorithm: str = "SHA-256",
        artifact_id: str = "",
        attempt_id: int = 1,
    ) -> Dict[str, Any]:
        """
        Durably records a calculated canonical hash before opening release.
        Guarantees that once opening has been released, the hash cannot be replaced.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT canonical_hash, opening_released FROM verifier_step_hashes WHERE session_id = ? AND step_id = ? AND attempt_id = ?",
                (session_id, step_id, attempt_id)
            )
            row = cursor.fetchone()
            now_iso = datetime.now(timezone.utc).isoformat()
            if row:
                if row["opening_released"]:
                    if row["canonical_hash"].lower() != canonical_hash.lower():
                        raise ValueError(
                            f"Security violation: Cannot replace recorded hash for step '{step_id}' "
                            f"after opening information has already been released."
                        )
                    return dict(row)
                cursor.execute(
                    "UPDATE verifier_step_hashes SET canonical_hash = ?, recorded_at = ? WHERE session_id = ? AND step_id = ? AND attempt_id = ?",
                    (canonical_hash, now_iso, session_id, step_id, attempt_id)
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO verifier_step_hashes (
                        session_id, transaction_id, step_id, attempt_id,
                        canonical_hash, hash_algorithm, artifact_id, recorded_at, opening_released
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                    """,
                    (session_id, transaction_id, step_id, attempt_id, canonical_hash, hash_algorithm, artifact_id, now_iso)
                )
            conn.commit()
        return {
            "session_id": session_id,
            "transaction_id": transaction_id,
            "step_id": step_id,
            "attempt_id": attempt_id,
            "canonical_hash": canonical_hash,
            "hash_algorithm": hash_algorithm,
            "opening_released": False,
        }

    def release_step_opening(self, session_id: str, step_id: str, attempt_id: int = 1) -> bool:
        """
        Authorizes opening factor release only after canonical hash has been recorded.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT canonical_hash, opening_released FROM verifier_step_hashes WHERE session_id = ? AND step_id = ? AND attempt_id = ?",
                (session_id, step_id, attempt_id)
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError(
                    f"Security violation: Opening information for step '{step_id}' "
                    f"cannot be released before its canonical hash is recorded."
                )
            now_iso = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                "UPDATE verifier_step_hashes SET opening_released = 1, opening_released_at = ? WHERE session_id = ? AND step_id = ? AND attempt_id = ?",
                (now_iso, session_id, step_id, attempt_id)
            )
            conn.commit()
            return True

    def get_step_hash_record(self, session_id: str, step_id: str, attempt_id: int = 1) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM verifier_step_hashes WHERE session_id = ? AND step_id = ? AND attempt_id = ?",
                (session_id, step_id, attempt_id)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def save_securing_report(self, report_data: Dict[str, Any]) -> str:
        """
        Persists a structured seller securing report into SQLite.
        """
        report_id = report_data.get("report_id") or f"REP-{report_data.get('run_id', 'UNKNOWN')}"
        run_id = report_data.get("run_id") or f"RUN-{report_data.get('transaction_id', 'TX-001')}"
        tx_id = report_data.get("transaction_id") or "TX-001"
        des_id = report_data.get("design_id") or "iir_butterworth"
        des_name = report_data.get("design_name") or "IIR Butterworth Filter"
        status = report_data.get("overall_status") or "SUCCESS"
        created_at = report_data.get("created_at") or datetime.now(timezone.utc).isoformat()
        duration_ms = float(report_data.get("total_securing_time_ms", 0.0))
        report_json = json.dumps(report_data)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO seller_securing_reports (
                    report_id, run_id, transaction_id, design_id, design_name,
                    status, created_at, duration_ms, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (report_id, run_id, tx_id, des_id, des_name, status, created_at, duration_ms, report_json)
            )
            conn.commit()
        return report_id

    def get_securing_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT report_json FROM seller_securing_reports WHERE report_id = ?", (report_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row["report_json"])
        return None

    def get_latest_securing_report_for_transaction(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT report_json FROM seller_securing_reports WHERE transaction_id = ? ORDER BY created_at DESC LIMIT 1",
                (transaction_id,)
            )
            row = cursor.fetchone()
            if row:
                return json.loads(row["report_json"])
        return None

    def list_securing_reports_for_transaction(self, transaction_id: str) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT report_id, run_id, transaction_id, design_id, design_name, status, created_at, duration_ms FROM seller_securing_reports WHERE transaction_id = ? ORDER BY created_at DESC",
                (transaction_id,)
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

