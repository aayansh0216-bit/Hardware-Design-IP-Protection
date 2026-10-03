"""
Deterministic Stratified Test Vector Generator.

Generates reproducible, stratified test vectors from the original unwatermarked design:
- All-zero patterns
- All-one patterns
- Walking-one patterns
- Walking-zero patterns
- Boundary values (0, 1, 0x7FFF, 0x8000, 0xFFFF)
- Alternating bit patterns (0x5555, 0xAAAA)
- Carry/overflow sensitive values

Invariants:
    1. Generated from original/unwatermarked design.
    2. Committed before verification to prevent post-hoc cherry-picking.
    3. Never regenerated merely to force a failed verification attempt to pass.
"""

import hashlib
import json
from typing import Dict, List, Any
from ..hls.dfg import DFG


class TestVectorSet:
    """
    Finalized set of test vectors with cryptographic hash digest.
    """
    __test__ = False

    def __init__(self, vectors: List[Dict[str, int]], vector_set_id: str = "TVS-V1"):
        self.vectors = vectors
        self.vector_set_id = vector_set_id
        self.canonical_json = json.dumps(
            [dict(sorted(v.items())) for v in vectors],
            separators=(",", ":"),
        )
        self.vector_hash = hashlib.sha256(self.canonical_json.encode("utf-8")).hexdigest()

    def __len__(self) -> int:
        return len(self.vectors)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vector_set_id": self.vector_set_id,
            "vector_count": len(self.vectors),
            "vector_hash": self.vector_hash,
            "vectors": self.vectors,
        }


class TestVectorGenerator:
    """
    Deterministic generator of stratified test vectors for hardware DFGs.
    """

    @classmethod
    def generate_stratified(cls, dfg: DFG, count: int = 32) -> TestVectorSet:
        inputs = sorted(dfg.inputs)
        vectors: List[Dict[str, int]] = []

        # 1. All-zero
        vectors.append({inp: 0 for inp in inputs})

        # 2. All-one (16-bit)
        vectors.append({inp: 0xFFFF for inp in inputs})

        # 3. Alternating 0x5555 and 0xAAAA
        vectors.append({inp: 0x5555 for inp in inputs})
        vectors.append({inp: 0xAAAA for inp in inputs})

        # 4. Boundary values
        boundary_vals = [1, 2, 0x7FFF, 0x8000, 0xFFFE]
        for bval in boundary_vals:
            vectors.append({inp: bval for inp in inputs})

        # 5. Walking-one across inputs
        for bit in range(16):
            val = 1 << bit
            vec = {}
            for idx, inp in enumerate(inputs):
                vec[inp] = (val << (idx % 4)) & 0xFFFF
            vectors.append(vec)

        # 6. Walking-zero across inputs
        for bit in range(16):
            val = (~(1 << bit)) & 0xFFFF
            vec = {}
            for idx, inp in enumerate(inputs):
                vec[inp] = val
            vectors.append(vec)

        # 7. Carry-sensitive / mixed arithmetic values
        for i in range(10):
            vec = {}
            for idx, inp in enumerate(inputs):
                base = (0x1000 * (i + 1) + idx * 0x31) & 0xFFFF
                vec[inp] = base
            vectors.append(vec)

        # Truncate or use all up to requested count (minimum at least all boundary cases)
        final_vectors = vectors[:max(count, len(vectors))]

        return TestVectorSet(
            vectors=final_vectors,
            vector_set_id=f"TVS-{dfg.name.upper()}-V1",
        )
