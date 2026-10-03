"""
Structural Watermark Similarity Analysis.

Quantifies the structural/forensic survival, partial modification, or corruption
of a transaction watermark between a reference protected design and a suspicious design.

Invariants:
    1. Deliberately separate from cryptographic Pedersen commitment verification.
    2. Supports variable watermark length N.
    3. Extraction failure is NOT reported as 0% similarity; it is reported as NOT_AVAILABLE.
    4. Distinguishes unavailable positions from mismatches.
    5. Structural evidence only; does not claim cryptographic or legal ownership proof.
"""

from typing import Dict, Any, Optional
from enum import Enum
from .watermark_extractor import ExtractionResult, ExtractionStatus


class SimilarityStatus(str, Enum):
    EXACT = "EXACT"
    PARTIAL = "PARTIAL"
    MISMATCH = "MISMATCH"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class WatermarkSimilarity:
    """
    Forensic comparison metrics between reference and suspicious extracted watermarks.
    """

    def __init__(
        self,
        status: SimilarityStatus,
        total_expected_bits: int,
        reference_recovered_bits: int,
        suspicious_recovered_bits: int,
        matching_bits: int,
        mismatching_bits: int,
        unavailable_positions: int,
        compared_bits: int,
        similarity_ratio: Optional[float],
        policy_note: str,
    ):
        self.status = status
        self.total_expected_bits = total_expected_bits
        self.reference_recovered_bits = reference_recovered_bits
        self.suspicious_recovered_bits = suspicious_recovered_bits
        self.matching_bits = matching_bits
        self.mismatching_bits = mismatching_bits
        self.unavailable_positions = unavailable_positions
        self.compared_bits = compared_bits
        self.similarity_ratio = similarity_ratio
        self.percentage_str = f"{self.similarity_ratio * 100:.2f}%" if self.similarity_ratio is not None else "N/A"
        self.policy_note = policy_note
        self.recovered_bits = suspicious_recovered_bits
        self.total_bits = total_expected_bits

        # Refinement Requirement 6: Structural Watermark Extraction metrics
        self.expected_bits = total_expected_bits
        self.missing_bits = max(0, total_expected_bits - suspicious_recovered_bits)
        self.matching_positions = matching_bits
        self.mismatching_positions = mismatching_bits
        self.extraction_coverage = (suspicious_recovered_bits / total_expected_bits) if total_expected_bits > 0 else 0.0
        self.recovered_bit_agreement = (matching_bits / suspicious_recovered_bits) if suspicious_recovered_bits > 0 else None
        self.coverage_str = f"{self.extraction_coverage * 100:.2f}%"
        self.agreement_str = f"{self.recovered_bit_agreement * 100:.2f}%" if self.recovered_bit_agreement is not None else "N/A"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "total_expected_bits": self.total_expected_bits,
            "expected_bits": self.expected_bits,
            "reference_recovered_bits": self.reference_recovered_bits,
            "suspicious_recovered_bits": self.suspicious_recovered_bits,
            "recovered_bits": self.recovered_bits,
            "missing_bits": self.missing_bits,
            "matching_bits": self.matching_bits,
            "mismatching_bits": self.mismatching_bits,
            "matching_positions": self.matching_positions,
            "mismatching_positions": self.mismatching_positions,
            "unavailable_positions": self.unavailable_positions,
            "compared_bits": self.compared_bits,
            "extraction_coverage": round(self.extraction_coverage, 6),
            "recovered_bit_agreement": round(self.recovered_bit_agreement, 6) if self.recovered_bit_agreement is not None else None,
            "coverage_str": self.coverage_str,
            "agreement_str": self.agreement_str,
            "similarity_ratio": round(self.similarity_ratio, 6) if self.similarity_ratio is not None else None,
            "percentage_str": self.percentage_str,
            "policy_note": self.policy_note,
        }


class WatermarkSimilarityCalculator:
    """
    Calculates structural forensic similarity between reference and suspicious watermark bitstreams.
    """

    DEFAULT_POLICY_NOTE = (
        "Similarity ratio is calculated strictly over mutually recovered positions "
        "(matching / compared_bits). Unrecovered positions are reported explicitly "
        "as unavailable and not assumed to be zero."
    )

    @classmethod
    def calculate(
        cls,
        reference_extraction: ExtractionResult,
        suspicious_extraction: ExtractionResult,
        policy_note: Optional[str] = None,
    ) -> WatermarkSimilarity:
        note = policy_note or cls.DEFAULT_POLICY_NOTE
        total_expected = reference_extraction.bit_length or suspicious_extraction.bit_length or 16

        # Invariant 9: Extraction failure means similarity is NOT_AVAILABLE, not 0%
        if (
            reference_extraction.status == ExtractionStatus.FAILED
            or suspicious_extraction.status == ExtractionStatus.FAILED
            or not reference_extraction.bitstream
            or not suspicious_extraction.bitstream
        ):
            return WatermarkSimilarity(
                status=SimilarityStatus.NOT_AVAILABLE,
                total_expected_bits=total_expected,
                reference_recovered_bits=reference_extraction.recovered_bits,
                suspicious_recovered_bits=suspicious_extraction.recovered_bits,
                matching_bits=0,
                mismatching_bits=0,
                unavailable_positions=total_expected,
                compared_bits=0,
                similarity_ratio=None,
                policy_note=note + " (Extraction failed; structural similarity cannot be computed)",
            )

        ref_str = reference_extraction.bitstream
        sus_str = suspicious_extraction.bitstream

        matching = 0
        mismatching = 0
        unavailable = 0

        eval_len = min(len(ref_str), len(sus_str), total_expected)
        for i in range(eval_len):
            r_ch = ref_str[i]
            s_ch = sus_str[i]

            if r_ch in ("0", "1") and s_ch in ("0", "1"):
                if r_ch == s_ch:
                    matching += 1
                else:
                    mismatching += 1
            elif r_ch == "X" or s_ch == "X":
                # Structural constraint violation is a forensic mismatch
                mismatching += 1
            else:
                # Missing or unrecovered position ('?')
                unavailable += 1

        unavailable += abs(total_expected - eval_len)
        compared = matching + mismatching

        if compared == 0:
            return WatermarkSimilarity(
                status=SimilarityStatus.NOT_AVAILABLE,
                total_expected_bits=total_expected,
                reference_recovered_bits=reference_extraction.recovered_bits,
                suspicious_recovered_bits=suspicious_extraction.recovered_bits,
                matching_bits=0,
                mismatching_bits=0,
                unavailable_positions=total_expected,
                compared_bits=0,
                similarity_ratio=None,
                policy_note=note + " (Zero mutually valid positions compared)",
            )

        ratio = matching / compared

        if matching == total_expected and unavailable == 0 and mismatching == 0:
            status = SimilarityStatus.EXACT
        elif ratio > 0.5:
            status = SimilarityStatus.PARTIAL
        else:
            status = SimilarityStatus.MISMATCH

        return WatermarkSimilarity(
            status=status,
            total_expected_bits=total_expected,
            reference_recovered_bits=reference_extraction.recovered_bits,
            suspicious_recovered_bits=suspicious_extraction.recovered_bits,
            matching_bits=matching,
            mismatching_bits=mismatching,
            unavailable_positions=unavailable,
            compared_bits=compared,
            similarity_ratio=ratio,
            policy_note=note,
        )
