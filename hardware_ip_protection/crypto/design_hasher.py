"""
Design Canonicalization and Cryptographic Hashing.

Generates a stable, reproducible SHA-256 identifier for a specific hardware
design representation (DFG structure, operation list, and I/O specifications).

Invariant:
    design -> design_hash -> transaction_record -> transaction_watermark
The design_hash is NOT the watermark itself.
"""

import hashlib
import json
from typing import Dict, Any, List


class DesignHasher:
    """
    Deterministic canonicalizer and hasher for hardware designs.
    """

    @staticmethod
    def canonicalize_dfg(dfg_dict: Dict[str, Any]) -> str:
        """
        Creates a sorted, whitespace-normalized canonical JSON representation of a DFG.
        """
        canonical_struct = {
            "name": dfg_dict.get("name", "unknown_design").strip().lower(),
            "inputs": sorted(dfg_dict.get("inputs", [])),
            "outputs": sorted(dfg_dict.get("outputs", [])),
            "operations": sorted(
                dfg_dict.get("operations", []),
                key=lambda op: (op.get("id", 0), op.get("op", "")),
            ),
            "data_dependencies": sorted(
                dfg_dict.get("data_dependencies", []),
                key=lambda d: (d.get("from_var", ""), d.get("to_var", "")),
            ),
        }
        return json.dumps(canonical_struct, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def canonicalize_verilog(verilog_source: str) -> str:
        """
        Strips comments, trailing whitespace, and normalizes blank lines for deterministic hashing.
        """
        cleaned_lines = []
        for line in verilog_source.splitlines():
            # Strip inline comments
            line_no_comment = line.split("//")[0].strip()
            if line_no_comment:
                cleaned_lines.append(line_no_comment)
        return "\n".join(cleaned_lines)

    @classmethod
    def hash_design(cls, design_repr: Dict[str, Any] | str) -> str:
        """
        Computes SHA-256 digest of canonical design representation.
        """
        if isinstance(design_repr, dict):
            canonical_text = cls.canonicalize_dfg(design_repr)
        else:
            canonical_text = cls.canonicalize_verilog(design_repr)
        return hashlib.sha256(canonical_text.encode("utf-8")).hexdigest()
