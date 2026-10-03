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
