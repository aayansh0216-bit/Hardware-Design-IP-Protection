"""
Behavioral Verification Module.

Compares the input-output functional behavior of two hardware designs
under an identical committed test-vector set.

Invariant:
    Answers: "Do these designs produce the same observed behavior under the selected test vectors?"
    Does NOT prove or establish legal ownership.
"""

from typing import Dict, List, Any, Optional
from enum import Enum
from ..hls.dfg import DFG
from .test_vector_generator import TestVectorSet
from .simulator import HardwareSimulator


import math


class BehavioralStatus(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"


class BehavioralResult:
    """
    Structured result of behavioral verification.
    """

    def __init__(
        self,
        status: BehavioralStatus,
        test_count: int,
        matching_outputs: int,
        mismatching_outputs: int,
        match_ratio: float,
        discrepancies: Optional[List[Dict[str, Any]]] = None,
        total_output_bits: int = 0,
        differing_output_bits: int = 0,
        hamming_distance: int = 0,
        hamming_similarity: float = 1.0,
        correlation_analysis: Optional[Dict[str, Any]] = None,
    ):
        self.status = status
        self.test_count = test_count
        self.matching_outputs = matching_outputs
        self.mismatching_outputs = mismatching_outputs
        self.match_ratio = match_ratio
        self.discrepancies = discrepancies or []

        # Refinement Requirement 3 & 5: explicit output-bit and output-match metrics
        self.total_test_vectors = test_count
        self.exact_output_matches = matching_outputs
        self.exact_output_mismatches = mismatching_outputs
        self.exact_output_match_rate = match_ratio

        # Backward compatibility aliases
        self.exact_vector_matches = matching_outputs
        self.exact_vector_mismatches = mismatching_outputs
        self.exact_match_rate = match_ratio

        self.total_output_bits = total_output_bits
        self.differing_output_bits = differing_output_bits
        self.hamming_distance = hamming_distance
        self.hamming_similarity = hamming_similarity

        # Refinement Requirement 4: correlation analysis view
        self.correlation_analysis = correlation_analysis or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "test_count": self.test_count,
            "matching_outputs": self.matching_outputs,
            "mismatching_outputs": self.mismatching_outputs,
            "match_ratio": round(self.match_ratio, 6),
            "discrepancies_count": len(self.discrepancies),
            "discrepancies": self.discrepancies[:10],  # show first 10
            "total_test_vectors": self.total_test_vectors,
            "exact_output_matches": self.exact_output_matches,
            "exact_output_mismatches": self.exact_output_mismatches,
            "exact_output_match_rate": round(self.exact_output_match_rate, 6),
            "exact_vector_matches": self.exact_vector_matches,
            "exact_vector_mismatches": self.exact_vector_mismatches,
            "exact_match_rate": round(self.exact_match_rate, 6),
            "total_output_bits": self.total_output_bits,
            "differing_output_bits": self.differing_output_bits,
            "hamming_distance": self.hamming_distance,
            "hamming_similarity": round(self.hamming_similarity, 6),
            "correlation_analysis": self.correlation_analysis,
        }


class BehavioralVerifier:
    """
    Performs behavioral verification by simulating reference and candidate designs.
    """

    @classmethod
    def _compute_pearson(cls, x: List[float], y: List[float]) -> float:
        n = len(x)
        if n < 2:
            return 1.0 if x == y else 0.0
        mx = sum(x) / n
        my = sum(y) / n
        var_x = sum((xi - mx) ** 2 for xi in x)
        var_y = sum((yi - my) ** 2 for yi in y)
        if var_x == 0.0 and var_y == 0.0:
            return 1.0 if x == y else 0.0
        if var_x == 0.0 or var_y == 0.0:
            return 0.0
        cov = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y))
        r = cov / math.sqrt(var_x * var_y)
        return max(-1.0, min(1.0, r))

    @classmethod
    def verify(
        cls,
        dfg: DFG,
        test_vector_set: TestVectorSet,
        reference_design: str | DFG,
        candidate_design: str | DFG,
    ) -> BehavioralResult:
        """
        Executes test vectors on reference and candidate designs and compares outputs.
        """
        test_count = len(test_vector_set)
        matching = 0
        mismatching = 0
        discrepancies = []

        total_output_bits = 0
        differing_output_bits = 0

        # Trace collection for correlation analysis
        signal_names = list(dfg.inputs) + list(dfg.outputs)
        ref_traces: Dict[str, List[float]] = {s: [] for s in signal_names}
        cand_traces: Dict[str, List[float]] = {s: [] for s in signal_names}

        for idx, vec in enumerate(test_vector_set.vectors):
            # Simulate reference
            if isinstance(reference_design, DFG):
                ref_out = HardwareSimulator.simulate_dfg(reference_design, vec)
            else:
                ref_out = HardwareSimulator.simulate_verilog(reference_design, dfg, vec)

            # Simulate candidate
            if isinstance(candidate_design, DFG):
                cand_out = HardwareSimulator.simulate_dfg(candidate_design, vec)
            else:
                cand_out = HardwareSimulator.simulate_verilog(candidate_design, dfg, vec)

            # Record signal traces for correlation
            for inp in dfg.inputs:
                v = float(vec.get(inp, 0))
                ref_traces[inp].append(v)
                cand_traces[inp].append(v)
            for out in dfg.outputs:
                ref_traces[out].append(float(ref_out.get(out, 0)))
                cand_traces[out].append(float(cand_out.get(out, 0)))

            # Compare complete output for one test vector
            if ref_out == cand_out:
                matching += 1
            else:
                mismatching += 1
                discrepancies.append({
                    "vector_index": idx,
                    "inputs": vec,
                    "reference_output": ref_out,
                    "candidate_output": cand_out,
                })

            # Bitwise comparison across all outputs
            for out in dfg.outputs:
                r_val = ref_out.get(out, 0) & HardwareSimulator.MASK_32
                c_val = cand_out.get(out, 0) & HardwareSimulator.MASK_32
                xor_diff = r_val ^ c_val
                differing_output_bits += bin(xor_diff).count("1")
                total_output_bits += 32

        status = BehavioralStatus.MATCH if mismatching == 0 else BehavioralStatus.MISMATCH
        ratio = matching / test_count if test_count > 0 else 0.0

        hamming_distance = differing_output_bits
        hamming_similarity = 1.0 - (differing_output_bits / total_output_bits) if total_output_bits > 0 else 1.0

        # Behavioral Analysis: Correlation matrices (Requirement 4)
        num_sig = len(signal_names)
        ref_matrix: List[List[float]] = []
        cand_matrix: List[List[float]] = []
        diff_matrix: List[List[float]] = []
        total_diff = 0.0

        for i, s1 in enumerate(signal_names):
            row_ref = []
            row_cand = []
            row_diff = []
            for j, s2 in enumerate(signal_names):
                r_ref = cls._compute_pearson(ref_traces[s1], ref_traces[s2])
                r_cand = cls._compute_pearson(cand_traces[s1], cand_traces[s2])
                d = abs(r_ref - r_cand)
                row_ref.append(round(r_ref, 4))
                row_cand.append(round(r_cand, 4))
                row_diff.append(round(d, 4))
                total_diff += d
            ref_matrix.append(row_ref)
            cand_matrix.append(row_cand)
            diff_matrix.append(row_diff)

        l1_distance = round(total_diff / (num_sig * num_sig), 6) if num_sig > 0 else 0.0

        correlation_analysis = {
            "signals": signal_names,
            "reference_correlation_matrix": ref_matrix,
            "suspicious_correlation_matrix": cand_matrix,
            "correlation_difference_matrix": diff_matrix,
            "l1_distance": l1_distance,
            "normalized_l1_distance": l1_distance,
        }

        return BehavioralResult(
            status=status,
            test_count=test_count,
            matching_outputs=matching,
            mismatching_outputs=mismatching,
            match_ratio=ratio,
            discrepancies=discrepancies,
            total_output_bits=total_output_bits,
            differing_output_bits=differing_output_bits,
            hamming_distance=hamming_distance,
            hamming_similarity=hamming_similarity,
            correlation_analysis=correlation_analysis,
        )
