"""
Judge-Led Interrogation Engine for 143-Bit Design Encoding (v1.1 Specification).

Implements:
- Indirect question bank for 143-bit four-rule encoding (Blocks 0 - 7).
- Hard arithmetic constraints (H1 - H7).
- Soft hypotheses (P1 - P4) with provenance tracking and failure retraction.
- Progressive question reveal (one question at a time).
- Append-only history ledger with non-destructive corrections.
- Canonical 143-bit candidate reconstruction with bit-level provenance.
- Clear separation: stops at 143-bit stage, does NOT ask Rule 5 questions,
  and does NOT perform commitment checks at this stage.
"""

from typing import Dict, Any, List, Optional, Tuple, Union
from enum import Enum
import hashlib
import math
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from hardware_ip_protection.crypto.pedersen import PedersenEngine, CommitmentVerificationStatus


class FactStatus(str, Enum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    INFERRED = "INFERRED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


class QuestionType(str, Enum):
    INTEGER = "INTEGER"
    BOOLEAN = "BOOLEAN"
    CHOICE = "CHOICE"


class QuestionDefinition(BaseModel):
    id: str
    block_id: str
    block_title: str
    prompt: str
    question_type: QuestionType
    min_val: Optional[int] = None
    max_val: Optional[int] = None
    choices: Optional[List[str]] = None
    reference_answer: Any
    workflow: Optional[str] = None
    stage: Optional[str] = None
    preconditions: List[str] = Field(default_factory=list)
    facts_established: List[str] = Field(default_factory=list)
    hard_constraints: List[str] = Field(default_factory=list)
    soft_hypotheses: List[str] = Field(default_factory=list)
    downstream_enabled: List[str] = Field(default_factory=list)
    downstream_invalidated: List[str] = Field(default_factory=list)
    is_reference_path: bool = True
    is_probe: bool = False
    is_fallback: bool = False
    is_recovery: bool = False
    explanation: Optional[str] = None


class LedgerEntry(BaseModel):
    entry_id: int
    question_id: str
    question_prompt: str
    submitted_answer: Any
    effective_answer: Any
    status: str  # OBSERVED, DERIVED, INFERRED, REJECTED, CONTRADICTION, VALIDATION_ERROR
    message: str
    is_correction: bool = False
    corrected_entry_id: Optional[int] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ReconstructionStage(str, Enum):
    STAGE_A = "STAGE_A"  # Uninitialized: before total length is established
    STAGE_B = "STAGE_B"  # Total length established
    STAGE_C = "STAGE_C"  # Total zero and one counts established
    STAGE_D = "STAGE_D"  # Stream divided into two parts (Part 1: 143b, Part 2: 108b)
    STAGE_E = "STAGE_E"  # Part 1 divided into units (13 units of 11b)
    STAGE_F = "STAGE_F"  # Each unit divided into fields (A:4b, B:4b, C:1b, D:2b)
    STAGE_G = "STAGE_G"  # Rule 5 interrogation active (Part 2 pairs)
    STAGE_H = "STAGE_H"  # Full 251-bit stream assembled (E_S = E4 || R5)
    STAGE_I = "STAGE_I"  # Cryptographic commitment verified (C_ES checked)
    STAGE_MONOLITHIC = "STAGE_MONOLITHIC"  # Single unsegmented stream branch
    STAGE_UNSUPPORTED = "STAGE_UNSUPPORTED"  # Branch architecture outside supported schema
    STAGE_INCOMPLETE = "STAGE_INCOMPLETE"  # Unknown/ambiguous structural parameters


class CellFill(str, Enum):
    NEUTRAL = "NEUTRAL"
    RED = "RED"
    GREEN = "GREEN"
    INFERRED = "INFERRED"


class ReconstructionCell(BaseModel):
    bit_index: int
    canonical_pos: int
    segment: str  # "part1", "part2", "entire"
    unit_index: Optional[int] = None
    node_id: Optional[int] = None
    node_label: Optional[str] = None
    cs_step: Optional[int] = None
    cs_label: Optional[str] = None
    field_name: Optional[str] = None
    field_bit_offset: Optional[int] = None
    value: Optional[str] = None
    display_char: str = "?"
    is_fixed: bool = False
    fill: CellFill = CellFill.NEUTRAL
    provenance: str = "UNKNOWN"
    source: str = "none"


class UnitCandidate(BaseModel):
    unit_index: int
    node_id: int
    position: int = 1
    cs_step: int = 1
    cs_label: str = "T1"
    node_label: str = "N1"
    a_val: Optional[int] = None
    b_val: Optional[int] = None
    c_val: Optional[int] = None
    d_val: Optional[int] = None
    a_bits: str = "????"
    b_bits: str = "????"
    c_bits: str = "?"
    d_bits: str = "??"
    assembled_bits: str = "???????????"
    ones_count: Optional[int] = None
    status: str = "UNKNOWN"


class PairCandidate(BaseModel):
    pair_index: int
    variable_name: str
    variable_index: int
    variable_parity: str
    variable_parity_code: str
    register_name: Optional[str] = None
    register_index: Optional[int] = None
    register_parity: Optional[str] = None
    register_parity_code: Optional[str] = None
    four_bit_code: str = "????"
    bit_offset_part2: int = 0
    bit_offset_global: int = 143
    bit_range: str = "Bit 143..146"
    is_fixed: bool = False
    status: str = "UNRESOLVED"
    provenance: str = "UNKNOWN"


class BitProvenance(BaseModel):
    bit_index: int
    value: Optional[str] = None
    status: str = "UNKNOWN"
    source_constraint: str = "none"
    source_facts: List[str] = Field(default_factory=list)


class CandidateSpaceState(BaseModel):
    status: str  # "UNBOUNDED", "ESTIMATE", "EXACT", "UNIQUE", "CONTRADICTION"
    exact_count: Optional[int] = None
    estimate_display: Optional[str] = None
    log10_candidates: Optional[float] = None
    description: str
    total_positions: int = 0
    resolved_positions: int = 0
    observed_positions: int = 0
    derived_positions: int = 0
    inferred_positions: int = 0
    unresolved_positions: int = 0
    entropy_bits: Optional[float] = None
    resolution_percentage: float = 0.0


class ConstraintModel:
    """
    Formal bit-level constraint propagation and candidate-space evaluation model.
    Tracks bit domains b[i] in {0, 1}, propagates hard structural relationships,
    and calculates exact or defensible candidate-space bounds.
    """
    @staticmethod
    def compute_candidate_space(
        total_bits: Optional[int],
        total_ones: Optional[int],
        total_zeros: Optional[int],
        fixed_ones: int,
        fixed_zeros: int,
        total_unfixed: int,
        contradictions: List[str],
        observed_count: int = 0,
        derived_count: int = 0,
        inferred_count: int = 0,
    ) -> CandidateSpaceState:
        if contradictions:
            return CandidateSpaceState(
                status="CONTRADICTION",
                exact_count=0,
                estimate_display="0",
                description="Contradiction detected: No satisfying candidate bitstream assignments exist.",
                total_positions=total_bits or 0,
                resolved_positions=0,
                unresolved_positions=total_unfixed,
                resolution_percentage=0.0,
            )

        if total_bits is None or total_bits <= 0:
            return CandidateSpaceState(
                status="UNBOUNDED",
                exact_count=None,
                estimate_display=None,
                description="Candidate space unbounded: Total structural bit length is unestablished.",
                total_positions=0,
                resolved_positions=0,
                unresolved_positions=0,
                resolution_percentage=0.0,
            )

        resolved_positions = fixed_ones + fixed_zeros
        resolution_pct = round((resolved_positions / total_bits) * 100, 1)

        if total_unfixed == 0:
            return CandidateSpaceState(
                status="UNIQUE",
                exact_count=1,
                estimate_display="1",
                log10_candidates=0.0,
                description="Unique candidate: Exactly 1 complete bitstream satisfies all established constraints.",
                total_positions=total_bits,
                resolved_positions=total_bits,
                observed_positions=observed_count,
                derived_positions=derived_count,
                inferred_positions=inferred_count,
                unresolved_positions=0,
                entropy_bits=0.0,
                resolution_percentage=100.0,
            )

        # Total ones and zeros established?
        if total_ones is not None and total_zeros is not None:
            unfixed_ones = max(0, total_ones - fixed_ones)
            unfixed_zeros = max(0, total_zeros - fixed_zeros)
            m = total_unfixed
            k = unfixed_ones

            if k > m or unfixed_zeros > m or (k + unfixed_zeros != m):
                return CandidateSpaceState(
                    status="CONTRADICTION",
                    exact_count=0,
                    estimate_display="0",
                    description=f"Popcount contradiction: Unplaced ones ({k}) and zeros ({unfixed_zeros}) do not match unallocated positions ({m}).",
                    total_positions=total_bits,
                    resolved_positions=resolved_positions,
                    unresolved_positions=m,
                    resolution_percentage=resolution_pct,
                )

            comb_val = math.comb(m, k)
            entropy_bits = round(math.log2(comb_val), 2) if comb_val > 0 else 0.0

            if comb_val <= 1_000_000:
                return CandidateSpaceState(
                    status="EXACT",
                    exact_count=comb_val,
                    estimate_display=f"{comb_val:,}",
                    log10_candidates=round(math.log10(comb_val), 2) if comb_val > 0 else 0.0,
                    description=f"Exact candidate count: {comb_val:,} candidate assignments satisfying popcount ({k} ones in {m} positions).",
                    total_positions=total_bits,
                    resolved_positions=resolved_positions,
                    observed_positions=observed_count,
                    derived_positions=derived_count,
                    inferred_positions=inferred_count,
                    unresolved_positions=m,
                    entropy_bits=entropy_bits,
                    resolution_percentage=resolution_pct,
                )
            else:
                log10_val = math.log10(comb_val)
                exp_int = int(round(log10_val))
                return CandidateSpaceState(
                    status="ESTIMATE",
                    exact_count=None,
                    estimate_display=f"~10^{exp_int}",
                    log10_candidates=round(log10_val, 2),
                    description=f"Defensible estimate: ~10^{exp_int} candidate bitstreams (based on {k} unplaced ones across {m} unresolved bit positions).",
                    total_positions=total_bits,
                    resolved_positions=resolved_positions,
                    observed_positions=observed_count,
                    derived_positions=derived_count,
                    inferred_positions=inferred_count,
                    unresolved_positions=m,
                    entropy_bits=entropy_bits,
                    resolution_percentage=resolution_pct,
                )

        # Length known, but total popcount not yet established
        m = total_unfixed
        if m <= 20:
            exact_val = 1 << m
            return CandidateSpaceState(
                status="EXACT",
                exact_count=exact_val,
                estimate_display=f"{exact_val:,}",
                log10_candidates=round(math.log10(exact_val), 2),
                description=f"Exact candidate space: {exact_val:,} unconstrained assignments across {m} unresolved positions.",
                total_positions=total_bits,
                resolved_positions=resolved_positions,
                observed_positions=observed_count,
                derived_positions=derived_count,
                inferred_positions=inferred_count,
                unresolved_positions=m,
                entropy_bits=float(m),
                resolution_percentage=resolution_pct,
            )
        else:
            log10_val = m * math.log10(2)
            exp_int = int(round(log10_val))
            return CandidateSpaceState(
                status="ESTIMATE",
                exact_count=None,
                estimate_display=f"~10^{exp_int}",
                log10_candidates=round(log10_val, 2),
                description=f"Defensible estimate: ~10^{exp_int} unconstrained assignments across {m} unresolved positions prior to popcount constraints.",
                total_positions=total_bits,
                resolved_positions=resolved_positions,
                observed_positions=observed_count,
                derived_positions=derived_count,
                inferred_positions=inferred_count,
                unresolved_positions=m,
                entropy_bits=float(m),
                resolution_percentage=resolution_pct,
            )

    @staticmethod
    def brute_force_small_model(
        total_bits: int,
        total_ones: int,
        fixed_bits: Dict[int, int],
    ) -> List[str]:
        """
        Exhaustive brute-force model counter for small bitstreams (<= 16 bits).
        Used for formal unit testing and exact verification against mathematical formulas.
        """
        if total_bits > 16:
            raise ValueError("Brute force enumeration limited to <= 16 bits for safety.")
        candidates: List[str] = []
        for i in range(1 << total_bits):
            b_str = bin(i)[2:].zfill(total_bits)
            if b_str.count("1") != total_ones:
                continue
            match = True
            for pos, val in fixed_bits.items():
                if int(b_str[pos]) != val:
                    match = False
                    break
            if match:
                candidates.append(b_str)
        return candidates


# Reference Schedule: 13 nodes, 7 control steps, canonical time-step order
CANONICAL_REFERENCE_NODES = [1, 2, 8, 3, 4, 9, 5, 6, 10, 7, 11, 12, 13]

CANONICAL_REFERENCE_UNITS: Dict[int, Dict[str, Any]] = {
    1:  {"node": 1,  "cs": 1, "A": 4, "B": 1,  "C": 1, "D": 2, "ones": 4, "A_bits": "0100", "B_bits": "0001", "C_bits": "1", "D_bits": "10"},
    2:  {"node": 2,  "cs": 1, "A": 4, "B": 2,  "C": 1, "D": 2, "ones": 4, "A_bits": "0100", "B_bits": "0010", "C_bits": "1", "D_bits": "10"},
    3:  {"node": 8,  "cs": 2, "A": 1, "B": 8,  "C": 0, "D": 3, "ones": 4, "A_bits": "0001", "B_bits": "1000", "C_bits": "0", "D_bits": "11"},
    4:  {"node": 3,  "cs": 2, "A": 1, "B": 3,  "C": 1, "D": 3, "ones": 6, "A_bits": "0001", "B_bits": "0011", "C_bits": "1", "D_bits": "11"},
    5:  {"node": 4,  "cs": 2, "A": 1, "B": 4,  "C": 1, "D": 3, "ones": 5, "A_bits": "0001", "B_bits": "0100", "C_bits": "1", "D_bits": "11"},
    6:  {"node": 9,  "cs": 3, "A": 5, "B": 9,  "C": 0, "D": 3, "ones": 6, "A_bits": "0101", "B_bits": "1001", "C_bits": "0", "D_bits": "11"},
    7:  {"node": 5,  "cs": 3, "A": 5, "B": 5,  "C": 1, "D": 3, "ones": 7, "A_bits": "0101", "B_bits": "0101", "C_bits": "1", "D_bits": "11"},
    8:  {"node": 6,  "cs": 3, "A": 5, "B": 6,  "C": 1, "D": 3, "ones": 7, "A_bits": "0101", "B_bits": "0110", "C_bits": "1", "D_bits": "11"},
    9:  {"node": 10, "cs": 4, "A": 0, "B": 10, "C": 0, "D": 2, "ones": 3, "A_bits": "0000", "B_bits": "1010", "C_bits": "0", "D_bits": "10"},
    10: {"node": 7,  "cs": 4, "A": 0, "B": 7,  "C": 1, "D": 2, "ones": 5, "A_bits": "0000", "B_bits": "0111", "C_bits": "1", "D_bits": "10"},
    11: {"node": 11, "cs": 5, "A": 5, "B": 11, "C": 0, "D": 1, "ones": 6, "A_bits": "0101", "B_bits": "1011", "C_bits": "0", "D_bits": "01"},
    12: {"node": 12, "cs": 6, "A": 1, "B": 12, "C": 0, "D": 1, "ones": 4, "A_bits": "0001", "B_bits": "1100", "C_bits": "0", "D_bits": "01"},
    13: {"node": 13, "cs": 7, "A": 5, "B": 13, "C": 0, "D": 1, "ones": 6, "A_bits": "0101", "B_bits": "1101", "C_bits": "0", "D_bits": "01"},
}

# Reference Post-Embedding Register Allocations for Rule 5 (Secured Stream)
CANONICAL_SECURED_RULE5_REGISTERS: Dict[str, str] = {
    "V1": "R1", "V2": "R2", "V3": "R3", "V4": "R4",
    "V5": "R2", "V6": "R3", "V7": "R5", "V8": "R6", "V9": "R7", "V10": "R8",
    "V11": "R4", "V12": "R5", "V13": "R8", "V14": "R9", "V15": "R10", "V16": "R11", "V17": "R12",
    "V18": "R1", "V19": "R9", "V20": "R7", "V21": "R13", "V22": "R14",
    "V23": "R6", "V24": "R13", "V25": "R11", "V26": "R12", "V27": "R14",
}

EXPECTED_143_BITSTREAM = (
    "010000011100100001011000011000011000100111110001010011101011001011010101011"
    "11010101101110000101001000000111110010110110010001110000101011101001"
)

EXPECTED_RULE5_BITSTREAM = (
    "010100000101000000010100010100000101000000010100000101000001010000010100010101000101000000010100010100000001"
)

EXPECTED_251_SECURED_BITSTREAM = EXPECTED_143_BITSTREAM + EXPECTED_RULE5_BITSTREAM


def get_popcount(val: int) -> int:
    return bin(val).count("1")


class InterrogationEngine:
    """
    Deterministic rule-based constraint engine for the 143-bit four-rule encoding.
    """

    @classmethod
    def build_question_bank(
        cls,
        workflow: str = "unsecured_design_encoding",
        block5b_enabled: bool = False,
    ) -> List[QuestionDefinition]:
        questions: List[QuestionDefinition] = []

        # ------------------------------------------------------------------
        # Block 0: Structure (Q0.1 - Q0.14)
        # ------------------------------------------------------------------
        b0 = "Block 0: Structure"
        q0_2_ref = 156 if workflow == "secured_design_encoding" else 149
        questions.extend([
            QuestionDefinition(
                id="Q0.1",
                block_id="b0",
                block_title=b0,
                prompt="How many total bits comprise the complete hardware structural encoding?",
                question_type=QuestionType.INTEGER,
                min_val=1,
                max_val=10000,
                reference_answer=251,
                preconditions=[],
                facts_established=["total_bits"],
                downstream_enabled=["Q0.2"],
                explanation="Establishes candidate stream length. Allocates the candidate bitstream grid.",
            ),
            QuestionDefinition(
                id="Q0.2",
                block_id="b0",
                block_title=b0,
                prompt="How many zero bits are present across the entire encoding stream?",
                question_type=QuestionType.INTEGER,
                min_val=0,
                max_val=10000,
                reference_answer=q0_2_ref,
                preconditions=["total_bits"],
                facts_established=["total_zeros", "total_ones"],
                hard_constraints=["H1: total_zeros <= total_bits"],
                downstream_enabled=["Q0.3"],
                explanation="Establishes aggregate zero and one population counts across the workspace.",
            ),
            QuestionDefinition(
                id="Q0.3",
                block_id="b0",
                block_title=b0,
                prompt="Is the complete encoding divided into independent structural parts?",
                question_type=QuestionType.CHOICE,
                choices=["yes", "no", "unknown"],
                reference_answer="yes",
                preconditions=["total_bits", "total_zeros"],
                facts_established=["parts_divided"],
                downstream_enabled=["Q0.3_count", "Q0.6_has_units"],
                explanation="Determines whether the stream partitions into multiple structural segments or remains a single monolithic stream.",
            ),
            QuestionDefinition(
                id="Q0.3_count",
                block_id="b0",
                block_title=b0,
                prompt="Into how many independent structural parts is the complete encoding divided?",
                question_type=QuestionType.INTEGER,
                min_val=2,
                max_val=10,
                reference_answer=2,
                preconditions=["parts_divided=yes"],
                facts_established=["parts_count"],
                downstream_enabled=["Q0.3_equal"],
                explanation="Quantifies independent structural segments.",
            ),
            QuestionDefinition(
                id="Q0.3_equal",
                block_id="b0",
                block_title=b0,
                prompt="Do all independent structural parts have equal bit lengths?",
                question_type=QuestionType.BOOLEAN,
                choices=["yes", "no"],
                reference_answer="no",
                preconditions=["parts_divided=yes", "parts_count"],
                facts_established=["parts_equal_length"],
                downstream_enabled=["Q0.4"],
                explanation="If yes, part length is derived if total_bits is divisible by parts_count; if no, individual part lengths must be queried.",
            ),
            QuestionDefinition(
                id="Q0.4",
                block_id="b0",
                block_title=b0,
                prompt="What is the bit length of the first structural segment?",
                question_type=QuestionType.INTEGER,
                min_val=1,
                max_val=10000,
                reference_answer=143,
                preconditions=["parts_divided=yes", "parts_equal_length=no"],
                facts_established=["part1_len", "part2_len"],
                hard_constraints=["H2: part1_len < total_bits"],
                downstream_enabled=["Q0.5"],
            ),
            QuestionDefinition(
                id="Q0.5",
                block_id="b0",
                block_title=b0,
                prompt="How many zero bits are contained in this first segment?",
                question_type=QuestionType.INTEGER,
                min_val=0,
                max_val=10000,
                reference_answer=76,
                preconditions=["parts_divided=yes", "part1_len"],
                facts_established=["part1_zeros", "part1_ones"],
                hard_constraints=["H2: part1_zeros <= total_zeros", "H1: part1_zeros <= part1_len"],
                downstream_enabled=["Q0.6_has_units"],
            ),
            QuestionDefinition(
                id="Q0.6_has_units",
                block_id="b0",
                block_title=b0,
                prompt="Is this structural segment divided into discrete repeated units?",
                question_type=QuestionType.CHOICE,
                choices=["yes", "no", "unknown"],
                reference_answer="yes",
                preconditions=["part1_len"],
                facts_established=["has_units"],
                downstream_enabled=["Q0.6"],
            ),
            QuestionDefinition(
                id="Q0.6",
                block_id="b0",
                block_title=b0,
                prompt="How many discrete repeated units comprise this segment?",
                question_type=QuestionType.INTEGER,
                min_val=1,
                max_val=100,
                reference_answer=13,
                preconditions=["has_units=yes"],
                facts_established=["num_units"],
                downstream_enabled=["Q0.7"],
            ),
            QuestionDefinition(
                id="Q0.7",
                block_id="b0",
                block_title=b0,
                prompt="Are all units in this segment uniform in bit length?",
                question_type=QuestionType.BOOLEAN,
                choices=["yes", "no"],
                reference_answer="yes",
                preconditions=["num_units"],
                facts_established=["units_uniform"],
                downstream_enabled=["Q0.8"],
            ),
            QuestionDefinition(
                id="Q0.8",
                block_id="b0",
                block_title=b0,
                prompt="What is the bit length of each individual unit?",
                question_type=QuestionType.INTEGER,
                min_val=1,
                max_val=100,
                reference_answer=11,
                is_probe=True,
                preconditions=["units_uniform=yes"],
                facts_established=["unit_len"],
                hard_constraints=["H3: num_units * unit_len == part1_len"],
                downstream_enabled=["Q0.9_has_fields"],
            ),
            QuestionDefinition(
                id="Q0.9_has_fields",
                block_id="b0",
                block_title=b0,
                prompt="Does each unit comprise distinct informational fields?",
                question_type=QuestionType.CHOICE,
                choices=["yes", "no", "unknown"],
                reference_answer="yes",
                preconditions=["unit_len"],
                facts_established=["has_fields"],
                downstream_enabled=["Q0.9"],
            ),
            QuestionDefinition(
                id="Q0.9",
                block_id="b0",
                block_title=b0,
                prompt="How many distinct informational fields comprise each unit?",
                question_type=QuestionType.INTEGER,
                min_val=1,
                max_val=10,
                reference_answer=4,
                preconditions=["has_fields=yes"],
                facts_established=["fields_per_unit"],
                downstream_enabled=["Q0.10"],
            ),
            QuestionDefinition(
                id="Q0.10",
                block_id="b0",
                block_title=b0,
                prompt="Is the internal field layout identical across all units?",
                question_type=QuestionType.BOOLEAN,
                choices=["yes", "no"],
                reference_answer="yes",
                preconditions=["fields_per_unit"],
                facts_established=["layout_uniform"],
                downstream_enabled=["Q0.10b"],
            ),
            QuestionDefinition(
                id="Q0.10b",
                block_id="b0",
                block_title=b0,
                prompt="Do all informational fields within a unit have identical bit widths?",
                question_type=QuestionType.BOOLEAN,
                choices=["yes", "no"],
                reference_answer="no",
                preconditions=["layout_uniform=yes"],
                facts_established=["fields_equal_width"],
                downstream_enabled=["Q0.11"],
            ),
            QuestionDefinition(
                id="Q0.11",
                block_id="b0",
                block_title=b0,
                prompt="What is the bit width of the first field (Field A) in each unit?",
                question_type=QuestionType.INTEGER,
                min_val=1,
                max_val=32,
                reference_answer=4,
                preconditions=["fields_equal_width=no"],
                facts_established=["f_a_len"],
                downstream_enabled=["Q0.12"],
            ),
            QuestionDefinition(
                id="Q0.12",
                block_id="b0",
                block_title=b0,
                prompt="What is the bit width of the second field (Field B) in each unit?",
                question_type=QuestionType.INTEGER,
                min_val=1,
                max_val=32,
                reference_answer=4,
                preconditions=["f_a_len"],
                facts_established=["f_b_len"],
                downstream_enabled=["Q0.13"],
            ),
            QuestionDefinition(
                id="Q0.13",
                block_id="b0",
                block_title=b0,
                prompt="What is the bit width of the third field (Field C) in each unit?",
                question_type=QuestionType.INTEGER,
                min_val=1,
                max_val=32,
                reference_answer=1,
                preconditions=["f_b_len"],
                facts_established=["f_c_len"],
                downstream_enabled=["Q0.14"],
            ),
            QuestionDefinition(
                id="Q0.14",
                block_id="b0",
                block_title=b0,
                prompt="What is the bit width of the final field (Field D) in each unit?",
                question_type=QuestionType.INTEGER,
                min_val=1,
                max_val=32,
                reference_answer=2,
                is_probe=True,
                preconditions=["f_c_len"],
                facts_established=["f_d_len"],
                hard_constraints=["H4: f_a_len + f_b_len + f_c_len + f_d_len == unit_len"],
                downstream_enabled=["Q1.1"],
            ),
        ])

        # ------------------------------------------------------------------
        # Block 1: Ones per unit (Q1.1 - Q1.12)
        # ------------------------------------------------------------------
        b1 = "Block 1: Ones per Unit"
        ref_ones = [4, 4, 4, 6, 5, 6, 7, 7, 3, 5, 6, 4]
        for i in range(1, 13):
            questions.append(QuestionDefinition(
                id=f"Q1.{i}",
                block_id="b1",
                block_title=b1,
                prompt=f"What is the total count of one bits in unit {i}?",
                question_type=QuestionType.INTEGER,
                min_val=0,
                max_val=11,
                reference_answer=ref_ones[i - 1],
            ))

        # ------------------------------------------------------------------
        # Block 2: Field totals (Q2.1 - Q2.4)
        # ------------------------------------------------------------------
        b2 = "Block 2: Field Totals"
        questions.extend([
            QuestionDefinition(id="Q2.1", block_id="b2", block_title=b2, prompt="What is the total number of one bits in field A across all units?", question_type=QuestionType.INTEGER, min_val=0, max_val=143, reference_answer=16),
            QuestionDefinition(id="Q2.2", block_id="b2", block_title=b2, prompt="What is the total number of one bits in field B across all units?", question_type=QuestionType.INTEGER, min_val=0, max_val=143, reference_answer=25),
            QuestionDefinition(id="Q2.3", block_id="b2", block_title=b2, prompt="What is the total number of one bits in field C across all units?", question_type=QuestionType.INTEGER, min_val=0, max_val=143, reference_answer=7),
            QuestionDefinition(
                id="Q2.4",
                block_id="b2",
                block_title=b2,
                prompt="Is the total number of one bits in the complete stream an even integer?",
                question_type=QuestionType.BOOLEAN,
                choices=["yes", "no"],
                reference_answer=("no" if workflow == "secured_design_encoding" else "yes"),
                is_probe=True,
            ),
        ])

        # ------------------------------------------------------------------
        # Block 3: Equality chain on A (Q3.1 - Q3.12)
        # ------------------------------------------------------------------
        b3 = "Block 3: Field A Equalities"
        eq_refs = ["yes", "no", "yes", "yes", "no", "yes", "yes", "no", "yes", "no", "no", "no"]
        for i in range(1, 13):
            questions.append(QuestionDefinition(
                id=f"Q3.{i}",
                block_id="b3",
                block_title=b3,
                prompt=f"Is the value of field A in unit {i + 1} equal to the value in unit {i}?",
                question_type=QuestionType.BOOLEAN,
                choices=["yes", "no"],
                reference_answer=eq_refs[i - 1],
            ))

        # ------------------------------------------------------------------
        # Block 4: A value per run representative (Q4.1 - Q4.7)
        # Reps: Units 1, 3, 6, 9, 11, 12, 13
        # ------------------------------------------------------------------
        b4 = "Block 4: Field A Representative Values"
        rep_units = [1, 3, 6, 9, 11, 12, 13]
        rep_a_vals = [4, 1, 5, 0, 5, 1, 5]
        for idx, (u, val) in enumerate(zip(rep_units, rep_a_vals), start=1):
            questions.append(QuestionDefinition(
                id=f"Q4.{idx}",
                block_id="b4",
                block_title=b4,
                prompt=f"What is the integer value represented by field A in unit {u}?",
                question_type=QuestionType.INTEGER,
                min_val=0,
                max_val=15,
                reference_answer=val,
            ))

        # ------------------------------------------------------------------
        # Block 5: D values and P1 hypothesis (Q5.1 - Q5.9)
        # Reps: Units 1, 3, 6, 9, 11, 12, 13 + Spot checks for Units 4 and 8
        # ------------------------------------------------------------------
        b5 = "Block 5: Field D Values & Constancy Hypothesis"
        rep_d_vals = [2, 3, 3, 2, 1, 1, 1]
        for idx, (u, val) in enumerate(zip(rep_units, rep_d_vals), start=1):
            questions.append(QuestionDefinition(
                id=f"Q5.{idx}",
                block_id="b5",
                block_title=b5,
                prompt=f"What is the integer value represented by field D in unit {u}?",
                question_type=QuestionType.INTEGER,
                min_val=0,
                max_val=3,
                reference_answer=val,
            ))
        # Spot checks for P1 validation
        questions.append(QuestionDefinition(id="Q5.8", block_id="b5", block_title=b5, prompt="What is the integer value represented by field D in unit 4?", question_type=QuestionType.INTEGER, min_val=0, max_val=3, reference_answer=3, is_probe=True))
        questions.append(QuestionDefinition(id="Q5.9", block_id="b5", block_title=b5, prompt="What is the integer value represented by field D in unit 8?", question_type=QuestionType.INTEGER, min_val=0, max_val=3, reference_answer=3, is_probe=True))

        # Fallback questions if P1 fails (inactive unless P1 fails)
        fallback_targets = [(2, 2), (5, 3), (7, 3), (10, 2)]
        for f_idx, (u, f_val) in enumerate(fallback_targets, start=10):
            questions.append(QuestionDefinition(
                id=f"Q5.{f_idx}",
                block_id="b5",
                block_title=b5,
                prompt=f"What is the integer value represented by field D in unit {u}?",
                question_type=QuestionType.INTEGER,
                min_val=0,
                max_val=3,
                reference_answer=f_val,
                is_fallback=True,
            ))

        # ------------------------------------------------------------------
        # Optional Block 5b: Comparison chain on B (default OFF)
        # ------------------------------------------------------------------
        if block5b_enabled:
            b5b = "Block 5b: Field B Comparison Chain"
            comp_refs = ["yes", "yes", "no", "yes", "yes", "no", "yes", "yes", "no", "yes", "yes", "yes"]
            for i in range(1, 13):
                questions.append(QuestionDefinition(
                    id=f"Q5b.{i}",
                    block_id="b5b",
                    block_title=b5b,
                    prompt=f"Is field B in unit {i + 1} strictly greater than field B in unit {i}?",
                    question_type=QuestionType.BOOLEAN,
                    choices=["yes", "no"],
                    reference_answer=comp_refs[i - 1],
                ))

        # ------------------------------------------------------------------
        # Block 6: B values (Q6.1 - Q6.13)
        # ------------------------------------------------------------------
        b6 = "Block 6: Field B Values"
        questions.append(QuestionDefinition(id="Q6.1", block_id="b6", block_title=b6, prompt="What is the numerical sum of field B values across all 13 units?", question_type=QuestionType.INTEGER, min_val=0, max_val=200, reference_answer=91))
        b_ref_vals = [1, 2, 8, 3, 4, 9, 5, 6, 10, 7, 11, 12]
        for i in range(1, 13):
            questions.append(QuestionDefinition(
                id=f"Q6.{i + 1}",
                block_id="b6",
                block_title=b6,
                prompt=f"What is the integer value represented by field B in unit {i}?",
                question_type=QuestionType.INTEGER,
                min_val=0,
                max_val=15,
                reference_answer=b_ref_vals[i - 1],
            ))

        # ------------------------------------------------------------------
        # Block 7: C values Spot Checks (Q7.1 - Q7.2)
        # ------------------------------------------------------------------
        b7 = "Block 7: Field C Verification"
        questions.append(QuestionDefinition(id="Q7.1", block_id="b7", block_title=b7, prompt="What is the binary bit value of field C in unit 9?", question_type=QuestionType.INTEGER, min_val=0, max_val=1, reference_answer=0, is_probe=True))
        questions.append(QuestionDefinition(id="Q7.2", block_id="b7", block_title=b7, prompt="What is the binary bit value of field C in unit 10?", question_type=QuestionType.INTEGER, min_val=0, max_val=1, reference_answer=1, is_probe=True))

        # ------------------------------------------------------------------
        # SECURED RULE 5 ENCODING (Stage S2): Blocks 8 - 11
        # ------------------------------------------------------------------
        if workflow == "secured_design_encoding":
            b8 = "Block 8: Rule 5 Structure & Partition"
            questions.append(
                QuestionDefinition(
                    id="Q8.0",
                    block_id="b8",
                    block_title=b8,
                    prompt="Does the second structural segment encode Rule 5 register allocation pairs?",
                    question_type=QuestionType.BOOLEAN,
                    choices=["yes", "no"],
                    reference_answer="yes",
                    workflow="secured_design_encoding",
                    preconditions=["part1_complete", "parts_count>=2"],
                    facts_established=["has_rule5"],
                    downstream_enabled=["Q8.1"],
                    explanation="Establishes whether the second segment contains Rule 5 register allocation data.",
                )
            )
            questions.extend([
                QuestionDefinition(id="Q8.1", block_id="b8", block_title=b8, prompt="What is the total bit length of the second structural segment (Rule 5 register/storage-variable encoding)?", question_type=QuestionType.INTEGER, min_val=1, max_val=10000, reference_answer=108, workflow="secured_design_encoding", preconditions=["has_rule5=yes"], facts_established=["r5_len"], downstream_enabled=["Q8.2"]),
                QuestionDefinition(id="Q8.2", block_id="b8", block_title=b8, prompt="How many discrete (register, variable) allocation pairs comprise this Rule 5 segment?", question_type=QuestionType.INTEGER, min_val=1, max_val=1000, reference_answer=27, workflow="secured_design_encoding", preconditions=["r5_len"], facts_established=["r5_pair_count"], downstream_enabled=["Q8.3"]),
                QuestionDefinition(id="Q8.3", block_id="b8", block_title=b8, prompt="What is the bit length of each encoded allocation pair?", question_type=QuestionType.INTEGER, min_val=1, max_val=32, reference_answer=4, workflow="secured_design_encoding", preconditions=["r5_pair_count"], facts_established=["r5_pair_width"], downstream_enabled=["Q8.4"]),
                QuestionDefinition(id="Q8.4", block_id="b8", block_title=b8, prompt="What is the bit width of the register parity code within each pair?", question_type=QuestionType.INTEGER, min_val=1, max_val=16, reference_answer=2, workflow="secured_design_encoding", preconditions=["r5_pair_width"], downstream_enabled=["Q8.5"]),
                QuestionDefinition(id="Q8.5", block_id="b8", block_title=b8, prompt="What is the bit width of the storage variable parity code within each pair?", question_type=QuestionType.INTEGER, min_val=1, max_val=16, reference_answer=2, workflow="secured_design_encoding", preconditions=["r5_pair_width"], downstream_enabled=["Q8.6"]),
                QuestionDefinition(id="Q8.6", block_id="b8", block_title=b8, prompt="Are pairs arranged in deterministic sequential order of storage variables (V1 through V27)?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes", workflow="secured_design_encoding", preconditions=["r5_pair_width"], downstream_enabled=["Q8.7"]),
                QuestionDefinition(id="Q8.7", block_id="b8", block_title=b8, prompt="How many zero bits are present across the 108 bits of this Rule 5 segment?", question_type=QuestionType.INTEGER, min_val=0, max_val=108, reference_answer=80, workflow="secured_design_encoding", preconditions=["r5_len"], facts_established=["r5_zeros"], downstream_enabled=["Q9.1"]),
            ])

            b9 = "Block 9: Rule 5 Parity Rules & Allowed Encodings"
            questions.extend([
                QuestionDefinition(id="Q9.1", block_id="b9", block_title=b9, prompt="What 2-bit binary code represents an odd parity assignment (odd register index or odd variable index)?", question_type=QuestionType.CHOICE, choices=["01", "00"], reference_answer="01"),
                QuestionDefinition(id="Q9.2", block_id="b9", block_title=b9, prompt="What 2-bit binary code represents an even parity assignment (even register index or even variable index)?", question_type=QuestionType.CHOICE, choices=["00", "01"], reference_answer="00"),
                QuestionDefinition(id="Q9.3", block_id="b9", block_title=b9, prompt="What is the total count of one bits in the Rule 5 segment?", question_type=QuestionType.INTEGER, min_val=0, max_val=108, reference_answer=28),
                QuestionDefinition(id="Q9.4", block_id="b9", block_title=b9, prompt="Does every pair follow the concatenation format [Register Code (2b)] || [Variable Code (2b)]?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
            ])

            b10 = "Block 10: Aggregate & Chunk Parity Checks"
            questions.extend([
                QuestionDefinition(id="Q10.1", block_id="b10", block_title=b10, prompt="How many of the 27 pairs have odd storage variable parity (odd index V1, V3, ... V27)?", question_type=QuestionType.INTEGER, min_val=0, max_val=27, reference_answer=14),
                QuestionDefinition(id="Q10.2", block_id="b10", block_title=b10, prompt="How many of the 27 pairs have even storage variable parity (even index V2, V4, ... V26)?", question_type=QuestionType.INTEGER, min_val=0, max_val=27, reference_answer=13),
                QuestionDefinition(id="Q10.3", block_id="b10", block_title=b10, prompt="How many total odd-register assignments (register parity code '01') occur in this secured allocation?", question_type=QuestionType.INTEGER, min_val=0, max_val=27, reference_answer=14),
                QuestionDefinition(id="Q10.4", block_id="b10", block_title=b10, prompt="How many total even-register assignments (register parity code '00') occur in this secured allocation?", question_type=QuestionType.INTEGER, min_val=0, max_val=27, reference_answer=13),
                QuestionDefinition(id="Q10.5", block_id="b10", block_title=b10, prompt="In the first 9 pairs (V1 to V9, Chunk 1), how many one bits are present in total?", question_type=QuestionType.INTEGER, min_val=0, max_val=36, reference_answer=10, is_probe=True),
                QuestionDefinition(id="Q10.6", block_id="b10", block_title=b10, prompt="In the middle 9 pairs (V10 to V18, Chunk 2), how many one bits are present in total?", question_type=QuestionType.INTEGER, min_val=0, max_val=36, reference_answer=8, is_probe=True),
                QuestionDefinition(id="Q10.7", block_id="b10", block_title=b10, prompt="In the final 9 pairs (V19 to V27, Chunk 3), how many one bits are present in total?", question_type=QuestionType.INTEGER, min_val=0, max_val=36, reference_answer=10, is_probe=True),
            ])

            b11 = "Block 11: Register Parity Relationships & Structural Deductions"
            questions.extend([
                # Chunk 1: V1..V8 questions (V9 derived via Q10.5)
                QuestionDefinition(id="Q11.1", block_id="b11", block_title=b11, prompt="Does storage variable V1 have an odd register parity assignment (e.g. code '01')?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.2", block_id="b11", block_title=b11, prompt="Does storage variable V2 have an odd register parity assignment?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="no"),
                QuestionDefinition(id="Q11.3", block_id="b11", block_title=b11, prompt="Does storage variable V3 have an odd register parity assignment?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.4", block_id="b11", block_title=b11, prompt="Does storage variable V4 have an odd register parity assignment?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="no"),
                QuestionDefinition(id="Q11.5", block_id="b11", block_title=b11, prompt="Does storage variable V5 share register allocation parity with variable V2?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.6", block_id="b11", block_title=b11, prompt="Does storage variable V6 share register allocation parity with variable V3?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.7", block_id="b11", block_title=b11, prompt="Does storage variable V7 have an odd register parity assignment?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.8", block_id="b11", block_title=b11, prompt="Does storage variable V8 have an odd register parity assignment?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="no"),
                # Chunk 2: V10..V18
                QuestionDefinition(id="Q11.9", block_id="b11", block_title=b11, prompt="Does storage variable V10 have an odd register parity assignment?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="no"),
                QuestionDefinition(id="Q11.10", block_id="b11", block_title=b11, prompt="Does storage variable V11 share register allocation parity with variable V4?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.11", block_id="b11", block_title=b11, prompt="Does storage variable V12 share register allocation parity with variable V7?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.12", block_id="b11", block_title=b11, prompt="Does storage variable V13 share register allocation parity with variable V10?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.13", block_id="b11", block_title=b11, prompt="Does storage variable V14 have an odd register parity assignment?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.14", block_id="b11", block_title=b11, prompt="Do storage variables V14 through V17 exhibit strictly alternating register parity (Odd, Even, Odd, Even)?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.15", block_id="b11", block_title=b11, prompt="Does storage variable V18 share register allocation parity with variable V1?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                # Chunk 3: V19..V26 (V27 derived via Q10.7 and global count)
                QuestionDefinition(id="Q11.16", block_id="b11", block_title=b11, prompt="Does storage variable V19 share register allocation parity with variable V14?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.17", block_id="b11", block_title=b11, prompt="Does storage variable V20 share register allocation parity with variable V9?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.18", block_id="b11", block_title=b11, prompt="Does storage variable V21 have an odd register parity assignment?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.19", block_id="b11", block_title=b11, prompt="Does storage variable V22 have an odd register parity assignment?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="no"),
                QuestionDefinition(id="Q11.20", block_id="b11", block_title=b11, prompt="Does storage variable V23 share register allocation parity with variable V8?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.21", block_id="b11", block_title=b11, prompt="Does storage variable V24 share register allocation parity with variable V21?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.22", block_id="b11", block_title=b11, prompt="Does storage variable V25 share register allocation parity with variable V16?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
                QuestionDefinition(id="Q11.23", block_id="b11", block_title=b11, prompt="Does storage variable V26 share register allocation parity with variable V17?", question_type=QuestionType.BOOLEAN, choices=["yes", "no"], reference_answer="yes"),
            ])

        return questions

    @classmethod
    def get_eligible_questions(
        cls,
        effective_answers: Optional[Dict[str, Any]] = None,
        workflow: str = "unsecured_design_encoding",
        p1_failed: bool = False,
        block5b_enabled: bool = False,
        answers: Optional[Dict[str, Any]] = None,
    ) -> List[QuestionDefinition]:
        if effective_answers is None and answers is not None:
            effective_answers = answers
        if effective_answers is None:
            effective_answers = {}

        all_q = cls.build_question_bank(workflow=workflow, block5b_enabled=block5b_enabled)
        q_map = {q.id: q for q in all_q}

        # Analyze active branch facts from current answers
        tot_bits = effective_answers.get("Q0.1")
        tot_zeros = effective_answers.get("Q0.2")

        # Determine parts_divided and parts_count
        parts_divided = None
        parts_count = None
        q0_3_val = effective_answers.get("Q0.3")
        if q0_3_val is not None:
            if isinstance(q0_3_val, int):
                if q0_3_val >= 2:
                    parts_divided = "yes"
                    parts_count = q0_3_val
                elif q0_3_val == 1:
                    parts_divided = "no"
                    parts_count = 1
            elif str(q0_3_val).lower() in ("yes", "y", "true"):
                parts_divided = "yes"
                parts_count = effective_answers.get("Q0.3_count")
                if parts_count is None and "Q0.4" in effective_answers:
                    parts_count = 2
            elif str(q0_3_val).lower() in ("no", "n", "false"):
                parts_divided = "no"
                parts_count = 1
            elif str(q0_3_val).lower() in ("unknown", "cannot determine"):
                parts_divided = "unknown"

        if effective_answers.get("Q0.3_count") is not None:
            parts_count = effective_answers.get("Q0.3_count")
            if parts_divided is None:
                parts_divided = "yes"

        # Equal parts check
        parts_equal_length = None
        q0_3_eq = effective_answers.get("Q0.3_equal")
        if q0_3_eq is not None:
            parts_equal_length = "yes" if str(q0_3_eq).lower() in ("yes", "y", "true") else "no"
        elif "Q0.4" in effective_answers and tot_bits is not None:
            parts_equal_length = "no" if (effective_answers["Q0.4"] * (parts_count or 2) != tot_bits) else "yes"

        p1_len = effective_answers.get("Q0.4")
        if parts_divided == "no" and tot_bits is not None:
            p1_len = tot_bits

        # Units check
        has_units = None
        num_units = None
        q0_6_has = effective_answers.get("Q0.6_has_units")
        q0_6_val = effective_answers.get("Q0.6")
        if q0_6_has is not None:
            if str(q0_6_has).lower() in ("yes", "y", "true"):
                has_units = "yes"
                num_units = effective_answers.get("Q0.6")
            elif str(q0_6_has).lower() in ("no", "n", "false"):
                has_units = "no"
            elif str(q0_6_has).lower() in ("unknown", "cannot determine"):
                has_units = "unknown"
        elif q0_6_val is not None:
            if isinstance(q0_6_val, int):
                has_units = "yes"
                num_units = q0_6_val
            elif str(q0_6_val).lower() in ("yes", "y", "true"):
                has_units = "yes"
                num_units = 13
            elif str(q0_6_val).lower() in ("no", "n", "false"):
                has_units = "no"
            elif str(q0_6_val).lower() in ("unknown", "cannot determine"):
                has_units = "unknown"

        units_uniform = effective_answers.get("Q0.7")
        unit_len = effective_answers.get("Q0.8")

        # Fields check
        has_fields = None
        fields_per_unit = None
        q0_9_has = effective_answers.get("Q0.9_has_fields")
        q0_9_val = effective_answers.get("Q0.9")
        if q0_9_has is not None:
            if str(q0_9_has).lower() in ("yes", "y", "true"):
                has_fields = "yes"
                fields_per_unit = effective_answers.get("Q0.9")
            elif str(q0_9_has).lower() in ("no", "n", "false"):
                has_fields = "no"
            elif str(q0_9_has).lower() in ("unknown", "cannot determine"):
                has_fields = "unknown"
        elif q0_9_val is not None:
            if isinstance(q0_9_val, int):
                has_fields = "yes"
                fields_per_unit = q0_9_val
            elif str(q0_9_val).lower() in ("yes", "y", "true"):
                has_fields = "yes"
                fields_per_unit = 4
            elif str(q0_9_val).lower() in ("no", "n", "false"):
                has_fields = "no"
            elif str(q0_9_val).lower() in ("unknown", "cannot determine"):
                has_fields = "unknown"

        layout_uniform = effective_answers.get("Q0.10")
        fields_equal_width = effective_answers.get("Q0.10b")
        f_a_len = effective_answers.get("Q0.11")
        f_b_len = effective_answers.get("Q0.12")
        f_c_len = effective_answers.get("Q0.13")
        f_d_len = effective_answers.get("Q0.14")
        fields_est = (f_d_len is not None) or (fields_equal_width is not None and str(fields_equal_width).lower() in ("yes", "y", "true"))

        # Build list of eligible questions
        eligible: List[QuestionDefinition] = []

        def add_q(qid: str):
            if qid in q_map and q_map[qid] not in eligible:
                eligible.append(q_map[qid])

        add_q("Q0.1")
        if tot_bits is not None:
            add_q("Q0.2")

        if tot_zeros is not None:
            add_q("Q0.3")

        if parts_divided == "yes":
            if "Q0.3_count" in q_map and effective_answers.get("Q0.3_count") is None and not (isinstance(q0_3_val, int) and q0_3_val >= 2):
                add_q("Q0.3_count")
            if parts_count is not None and parts_count > 1:
                if parts_equal_length is None and "Q0.3_equal" in q_map:
                    add_q("Q0.3_equal")
                if parts_equal_length == "no":
                    add_q("Q0.4")
                    if p1_len is not None:
                        add_q("Q0.5")
                elif parts_equal_length == "yes":
                    if p1_len is not None:
                        add_q("Q0.5")

        if (parts_divided == "no") or (parts_divided == "yes" and (effective_answers.get("Q0.5") is not None or parts_equal_length == "yes")):
            add_q("Q0.6_has_units")

        if has_units == "yes":
            if "Q0.6" in q_map and effective_answers.get("Q0.6") is None and not (isinstance(q0_6_val, int) and q0_6_val >= 1):
                add_q("Q0.6")
            if num_units is not None:
                add_q("Q0.7")
                if units_uniform is not None and str(units_uniform).lower() in ("yes", "y", "true"):
                    add_q("Q0.8")
                    if unit_len is not None:
                        add_q("Q0.9_has_fields")

        if has_fields == "yes":
            if "Q0.9" in q_map and effective_answers.get("Q0.9") is None and not (isinstance(q0_9_val, int) and q0_9_val >= 1):
                add_q("Q0.9")
            if fields_per_unit is not None:
                add_q("Q0.10")
                if layout_uniform is not None and str(layout_uniform).lower() in ("yes", "y", "true"):
                    add_q("Q0.10b")
                    if fields_equal_width is not None and str(fields_equal_width).lower() in ("no", "n", "false"):
                        add_q("Q0.11")
                        if f_a_len is not None:
                            add_q("Q0.12")
                            if f_b_len is not None:
                                add_q("Q0.13")
                                if f_c_len is not None:
                                    add_q("Q0.14")

        # Blocks 1 to 7
        if fields_est and num_units is not None and num_units >= 12:
            # Block 1
            for i in range(1, 13):
                add_q(f"Q1.{i}")
            # Block 2
            if all(f"Q1.{i}" in effective_answers for i in range(1, 13)):
                for i in range(1, 5):
                    add_q(f"Q2.{i}")
            # Block 3
            if all(f"Q2.{i}" in effective_answers for i in range(1, 5)):
                for i in range(1, 13):
                    add_q(f"Q3.{i}")
            # Block 4
            if all(f"Q3.{i}" in effective_answers for i in range(1, 13)):
                for i in range(1, 8):
                    add_q(f"Q4.{i}")
            # Block 5
            if all(f"Q4.{i}" in effective_answers for i in range(1, 8)):
                for i in range(1, 10):
                    add_q(f"Q5.{i}")
                if p1_failed:
                    for i in range(10, 14):
                        add_q(f"Q5.{i}")
            # Block 5b
            if block5b_enabled and all(f"Q5.{i}" in effective_answers for i in range(1, 10)):
                for i in range(1, 13):
                    add_q(f"Q5b.{i}")
            # Block 6
            b5_done = all(f"Q5.{i}" in effective_answers for i in range(1, 10))
            if b5_done:
                add_q("Q6.1")
                for i in range(2, 14):
                    add_q(f"Q6.{i}")
            # Block 7
            if b5_done and all(f"Q6.{i}" in effective_answers for i in range(1, 14)):
                add_q("Q7.1")
                add_q("Q7.2")

        # Secured Rule 5
        if workflow == "secured_design_encoding" and fields_est and (parts_count is not None and parts_count > 1):
            add_q("Q8.0")
            has_r5_ans = effective_answers.get("Q8.0")
            is_r5_active = (has_r5_ans is None and "Q8.1" in effective_answers) or (has_r5_ans is not None and str(has_r5_ans).lower() in ("yes", "y", "true"))
            if is_r5_active:
                for i in range(1, 8):
                    add_q(f"Q8.{i}")
                if all(f"Q8.{i}" in effective_answers for i in range(1, 8)):
                    for i in range(1, 5):
                        add_q(f"Q9.{i}")
                if all(f"Q9.{i}" in effective_answers for i in range(1, 5)):
                    for i in range(1, 8):
                        add_q(f"Q10.{i}")
                if all(f"Q10.{i}" in effective_answers for i in range(1, 8)):
                    for i in range(1, 24):
                        add_q(f"Q11.{i}")

        return eligible

    @classmethod
    def get_active_questions(
        cls,
        workflow: str = "unsecured_design_encoding",
        p1_failed: bool = False,
        block5b_enabled: bool = False,
        effective_answers: Optional[Dict[str, Any]] = None,
        answers: Optional[Dict[str, Any]] = None,
    ) -> List[QuestionDefinition]:
        if effective_answers is None and answers is not None:
            effective_answers = answers
        if effective_answers is not None:
            return cls.get_eligible_questions(
                effective_answers,
                workflow=workflow,
                p1_failed=p1_failed,
                block5b_enabled=block5b_enabled,
            )
        all_q = cls.build_question_bank(workflow=workflow, block5b_enabled=block5b_enabled)
        active: List[QuestionDefinition] = []
        for q in all_q:
            if q.is_fallback and not p1_failed:
                continue
            active.append(q)
        return active

    @classmethod
    def score_question_impact(
        cls,
        q: QuestionDefinition,
        eval_res: Dict[str, Any],
        effective_answers: Dict[str, Any],
    ) -> float:
        """
        Heuristic information gain / candidate space reduction score.
        Scores questions based on expected constraint resolution, reduction of candidate space,
        hypotheses separation, and propagation enablement.
        """
        facts = eval_res.get("facts", {})

        # 1. Redundancy check: if all target facts are already established/derived, mark redundant
        if q.facts_established and all(f in facts for f in q.facts_established):
            return -1000.0

        score = 0.0

        # 2. Structural boundary questions: highest impact on bounding unconstrained space
        if q.id in ("Q0.1", "Q0.2", "Q0.3", "Q0.3_count", "Q0.3_equal", "Q0.6_has_units", "Q0.6", "Q0.9_has_fields", "Q0.9", "Q8.0"):
            score += 100.0

        # 3. Global and block popcounts: eliminate massive binomial subspaces
        elif q.id in ("Q0.4", "Q0.5", "Q0.8", "Q0.11", "Q0.12", "Q0.13", "Q0.14", "Q2.1", "Q2.2", "Q2.3", "Q2.4", "Q6.1"):
            score += 85.0

        # 4. Equivalence run questions (Field A): tie unit variables into chains
        elif q.block_id == "b3":
            score += 70.0

        # 5. Representative value probes: force values for all units in run simultaneously
        elif q.block_id == "b4":
            score += 80.0

        # 6. Spot checks & soft hypothesis tests (Field D / C):
        elif q.id in ("Q5.8", "Q5.9", "Q7.1", "Q7.2"):
            score += 65.0

        # 7. Field B unit values:
        elif q.block_id == "b6":
            score += 60.0

        # 8. Rule 5 parity and storage variable questions:
        elif q.block_id in ("b9", "b10", "b11"):
            score += 55.0

        else:
            score += 50.0

        # Bonus for number of facts established
        score += len(q.facts_established) * 5.0

        # Bonus for downstream questions enabled
        score += len(q.downstream_enabled) * 3.0

        return score

    @classmethod
    def get_question_by_id(
        cls,
        question_id: str,
        workflow: str = "unsecured_design_encoding",
        block5b_enabled: bool = False,
    ) -> Optional[QuestionDefinition]:
        for q in cls.build_question_bank(workflow=workflow, block5b_enabled=block5b_enabled):
            if q.id == question_id:
                return q
        return None

    @classmethod
    def get_next_question(
        cls,
        effective_answers: Optional[Dict[str, Any]] = None,
        workflow: str = "unsecured_design_encoding",
        p1_failed: bool = False,
        block5b_enabled: bool = False,
        answers: Optional[Dict[str, Any]] = None,
    ) -> Optional[QuestionDefinition]:
        if effective_answers is None and answers is not None:
            effective_answers = answers
        if effective_answers is None:
            effective_answers = {}

        eval_res = cls.evaluate_state(
            effective_answers,
            workflow=workflow,
            block5b_enabled=block5b_enabled,
        )
        outcome = eval_res.get("outcome", "")
        if outcome == "CONTRADICTION" or outcome.startswith("UNSUPPORTED_BRANCH") or outcome.startswith("INCOMPLETE") or outcome.startswith("COMPLETE") or eval_res.get("contradictions"):
            return None

        eligible = cls.get_eligible_questions(
            effective_answers,
            workflow=workflow,
            p1_failed=eval_res.get("p1_failed", p1_failed),
            block5b_enabled=block5b_enabled,
        )
        unanswered = [q for q in eligible if q.id not in effective_answers or effective_answers[q.id] is None]
        if not unanswered:
            return None

        scored: List[Tuple[float, QuestionDefinition]] = []
        for q in unanswered:
            s = cls.score_question_impact(q, eval_res, effective_answers)
            if s >= 0:
                scored.append((s, q))

        if not scored:
            return unanswered[0]

        # Stable sort: Python sort preserves original list order when scores tie
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[0][1]

    @classmethod
    def evaluate_state(
        cls,
        effective_answers: Optional[Dict[str, Any]] = None,
        workflow: str = "unsecured_design_encoding",
        block5b_enabled: bool = False,
        stored_c_es: Optional[str] = None,
        opening_factor_r_es: Optional[Union[str, int]] = None,
        blinding_int: Optional[Union[str, int]] = None,
        answers: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Executes deterministic constraint evaluation, provenance tracking,
        hypothesis testing, branch resolution, and candidate bitstream assembly.
        """
        if effective_answers is None and answers is not None:
            effective_answers = answers
        if effective_answers is None:
            effective_answers = {}
        if blinding_int is not None and opening_factor_r_es is None:
            opening_factor_r_es = blinding_int

        facts: Dict[str, Dict[str, Any]] = {}
        contradictions: List[str] = []
        soft_hypotheses: Dict[str, Dict[str, Any]] = {
            "P1": {"name": "Field D Run Constancy", "status": "PENDING", "description": "D is constant within runs of equal A values"},
            "P2": {"name": "Field D Run Length Equality", "status": "UNTESTED", "description": "D value matches the length of the A-run"},
            "P3": {"name": "Field B Permutation 1..13", "status": "PENDING", "description": "B represents a complete permutation of integers 1 through 13"},
            "P4": {"name": "Parity Consistency A & D", "status": "UNTESTED", "description": "The lowest bit of A correlates with the lowest bit of D"},
        }
        retracted_facts: List[str] = []
        unsupported_branch_reason: Optional[str] = None
        incomplete_reason: Optional[str] = None

        # Helper to set fact
        def set_fact(key: str, val: Any, status: FactStatus, source: str, deps: Optional[List[str]] = None):
            facts[key] = {
                "val": val,
                "status": status.value,
                "source": source,
                "deps": deps or [],
            }

        # ------------------------------------------------------------------
        # 1. Evaluate Block 0: Structure
        # ------------------------------------------------------------------
        total_bits = effective_answers.get("Q0.1")
        total_zeros = effective_answers.get("Q0.2")

        if total_bits is not None:
            if total_bits <= 0:
                contradictions.append(f"H0.1: Total bits ({total_bits}) must be a positive integer.")
            else:
                set_fact("total_bits", total_bits, FactStatus.OBSERVED, "Q0.1")

        if total_zeros is not None:
            if total_zeros < 0:
                contradictions.append(f"H0.2: Zero count ({total_zeros}) cannot be negative.")
            elif total_bits is not None and total_zeros > total_bits:
                contradictions.append(f"H1: Zero count ({total_zeros}) exceeds total bits ({total_bits}).")
            else:
                set_fact("total_zeros", total_zeros, FactStatus.OBSERVED, "Q0.2")
                if total_bits is not None:
                    total_ones = total_bits - total_zeros
                    set_fact("total_ones", total_ones, FactStatus.DERIVED, "H1 (total_bits - total_zeros)", ["Q0.1", "Q0.2"])

        # Determine parts_divided and parts_count
        parts_divided = None
        parts_count = None
        q0_3_val = effective_answers.get("Q0.3")
        if q0_3_val is not None:
            if isinstance(q0_3_val, int):
                if q0_3_val >= 2:
                    parts_divided = "yes"
                    parts_count = q0_3_val
                elif q0_3_val == 1:
                    parts_divided = "no"
                    parts_count = 1
                else:
                    contradictions.append(f"H0.3: Part count ({q0_3_val}) must be at least 1.")
            elif str(q0_3_val).lower() in ("yes", "y", "true"):
                parts_divided = "yes"
                parts_count = effective_answers.get("Q0.3_count")
                if parts_count is None and "Q0.4" in effective_answers:
                    parts_count = 2
            elif str(q0_3_val).lower() in ("no", "n", "false"):
                parts_divided = "no"
                parts_count = 1
            elif str(q0_3_val).lower() in ("unknown", "cannot determine"):
                parts_divided = "unknown"
                incomplete_reason = "Incomplete: Stream partition structure unknown: claimant indicated independence of stream parts is unknown."

        if effective_answers.get("Q0.3_count") is not None:
            cnt_val = effective_answers.get("Q0.3_count")
            if cnt_val < 2:
                contradictions.append(f"H0.3: Multiple independent parts count ({cnt_val}) must be >= 2.")
            else:
                parts_count = cnt_val
                if parts_divided is None:
                    parts_divided = "yes"

        if parts_divided == "yes":
            set_fact("parts_divided", "yes", FactStatus.OBSERVED, "Q0.3")
            if parts_count is not None:
                set_fact("parts_count", parts_count, FactStatus.OBSERVED, "Q0.3_count" if "Q0.3_count" in effective_answers else "Q0.3")
        elif parts_divided == "no":
            set_fact("parts_divided", "no", FactStatus.OBSERVED, "Q0.3")
            set_fact("parts_count", 1, FactStatus.DERIVED, "parts_divided=no", ["Q0.3"])
            parts_count = 1

        # Check Equal Lengths of Parts
        parts_equal_length = None
        q0_3_eq = effective_answers.get("Q0.3_equal")
        if q0_3_eq is not None:
            if str(q0_3_eq).lower() in ("yes", "y", "true"):
                parts_equal_length = "yes"
                set_fact("parts_equal_length", "yes", FactStatus.OBSERVED, "Q0.3_equal")
                if total_bits is not None and parts_count is not None and parts_count > 1:
                    if total_bits % parts_count != 0:
                        contradictions.append(f"H0.3: Total bit length ({total_bits}) cannot be divided into {parts_count} equal parts (indivisible).")
                    else:
                        derived_p_len = total_bits // parts_count
                        set_fact("part1_len", derived_p_len, FactStatus.DERIVED, "H0.3 (total_bits / parts_count)", ["total_bits", "parts_count"])
                        part1_len = derived_p_len
            elif str(q0_3_eq).lower() in ("no", "n", "false"):
                parts_equal_length = "no"
                set_fact("parts_equal_length", "no", FactStatus.OBSERVED, "Q0.3_equal")
        elif "Q0.4" in effective_answers and total_bits is not None and parts_count is not None:
            parts_equal_length = "no" if (effective_answers["Q0.4"] * parts_count != total_bits) else "yes"

        part1_len = effective_answers.get("Q0.4") if parts_divided != "no" else total_bits
        if parts_equal_length == "yes" and "part1_len" in facts:
            part1_len = facts["part1_len"]["val"]

        if part1_len is not None:
            set_fact("part1_len", part1_len, FactStatus.OBSERVED if parts_divided != "no" else FactStatus.DERIVED, "Q0.4" if parts_divided != "no" else "single_stream")
            if total_bits is not None:
                if part1_len > total_bits:
                    contradictions.append(f"H2: First segment length ({part1_len}) exceeds total bits ({total_bits}).")
                elif part1_len <= 0:
                    contradictions.append(f"H2: First segment length ({part1_len}) must be positive.")
                elif parts_count == 2:
                    part2_len = total_bits - part1_len
                    set_fact("part2_len", part2_len, FactStatus.DERIVED, "H2 (total_bits - part1_len)", ["Q0.1", "Q0.4"])

        part1_zeros = effective_answers.get("Q0.5") if parts_divided != "no" else total_zeros
        if part1_zeros is not None:
            set_fact("part1_zeros", part1_zeros, FactStatus.OBSERVED if parts_divided != "no" else FactStatus.DERIVED, "Q0.5" if parts_divided != "no" else "single_stream")
            if total_zeros is not None and part1_zeros > total_zeros:
                contradictions.append(f"H2: Segment 1 zeros ({part1_zeros}) exceed total zeros ({total_zeros}).")
            if part1_len is not None:
                if part1_zeros > part1_len:
                    contradictions.append(f"H1: Segment 1 zeros ({part1_zeros}) exceed segment 1 length ({part1_len}).")
                else:
                    part1_ones = part1_len - part1_zeros
                    set_fact("part1_ones", part1_ones, FactStatus.DERIVED, "H1 (part1_len - part1_zeros)", ["part1_len", "part1_zeros"])
                    if total_zeros is not None and part1_zeros <= total_zeros and parts_count == 2:
                        part2_zeros = total_zeros - part1_zeros
                        set_fact("part2_zeros", part2_zeros, FactStatus.DERIVED, "H2 (total_zeros - part1_zeros)", ["Q0.2", "part1_zeros"])
                    if "total_ones" in facts and parts_count == 2:
                        part2_ones = facts["total_ones"]["val"] - part1_ones
                        set_fact("part2_ones", part2_ones, FactStatus.DERIVED, "H2 (total_ones - part1_ones)", ["total_ones", "part1_ones"])

        # Units check
        has_units = None
        num_units = None
        q0_6_has = effective_answers.get("Q0.6_has_units")
        q0_6_val = effective_answers.get("Q0.6")
        if q0_6_has is not None:
            if str(q0_6_has).lower() in ("yes", "y", "true"):
                has_units = "yes"
                num_units = effective_answers.get("Q0.6")
            elif str(q0_6_has).lower() in ("no", "n", "false"):
                has_units = "no"
            elif str(q0_6_has).lower() in ("unknown", "cannot determine"):
                has_units = "unknown"
                incomplete_reason = "Incomplete: Unit structure presence unknown: claimant indicated unit division is unknown."
        elif q0_6_val is not None:
            if isinstance(q0_6_val, int):
                has_units = "yes"
                num_units = q0_6_val
            elif str(q0_6_val).lower() in ("yes", "y", "true"):
                has_units = "yes"
                num_units = 13
            elif str(q0_6_val).lower() in ("no", "n", "false"):
                has_units = "no"
            elif str(q0_6_val).lower() in ("unknown", "cannot determine"):
                has_units = "unknown"
                incomplete_reason = "Incomplete: Unit structure presence unknown: claimant indicated unit division is unknown."

        if has_units == "yes":
            set_fact("has_units", "yes", FactStatus.OBSERVED, "Q0.6_has_units")
        elif has_units == "no":
            set_fact("has_units", "no", FactStatus.OBSERVED, "Q0.6_has_units")

        unit_uniform = effective_answers.get("Q0.7")
        if unit_uniform is not None:
            if str(unit_uniform).lower() in ("no", "n", "false"):
                set_fact("units_uniform", "no", FactStatus.OBSERVED, "Q0.7")
                unsupported_branch_reason = "Unsupported Branch: Variable-width unit architecture (non-uniform unit length) is not supported by the 4-rule encoding schema."
            elif str(unit_uniform).lower() in ("yes", "y", "true"):
                set_fact("units_uniform", "yes", FactStatus.OBSERVED, "Q0.7")

        unit_len = effective_answers.get("Q0.8")

        if num_units is not None:
            set_fact("num_units", num_units, FactStatus.OBSERVED, "Q0.6")
            eff_seg_len = part1_len if part1_len is not None else total_bits
            if eff_seg_len is not None and (unit_uniform is None or str(unit_uniform).lower() in ("yes", "y", "true")):
                if eff_seg_len % num_units != 0:
                    contradictions.append(f"H3: Segment length ({eff_seg_len}) is not evenly divisible by unit count ({num_units}).")
                else:
                    calc_unit_len = eff_seg_len // num_units
                    set_fact("expected_unit_len", calc_unit_len, FactStatus.DERIVED, "H3 (segment_len / num_units)", ["part1_len", "Q0.6"])
                    if unit_len is not None and unit_len != calc_unit_len:
                        contradictions.append(f"H3: Answered unit length ({unit_len}) contradicts derived unit length ({calc_unit_len}).")

        if unit_len is not None:
            set_fact("unit_len", unit_len, FactStatus.OBSERVED, "Q0.8")

        # Fields check
        has_fields = None
        fields_per_unit = None
        q0_9_has = effective_answers.get("Q0.9_has_fields")
        q0_9_val = effective_answers.get("Q0.9")
        if q0_9_has is not None:
            if str(q0_9_has).lower() in ("yes", "y", "true"):
                has_fields = "yes"
                fields_per_unit = effective_answers.get("Q0.9")
            elif str(q0_9_has).lower() in ("no", "n", "false"):
                has_fields = "no"
            elif str(q0_9_has).lower() in ("unknown", "cannot determine"):
                has_fields = "unknown"
                incomplete_reason = "Incomplete: Field layout presence unknown: claimant indicated field division is unknown."
        elif q0_9_val is not None:
            if isinstance(q0_9_val, int):
                has_fields = "yes"
                fields_per_unit = q0_9_val
            elif str(q0_9_val).lower() in ("yes", "y", "true"):
                has_fields = "yes"
                fields_per_unit = 4
            elif str(q0_9_val).lower() in ("no", "n", "false"):
                has_fields = "no"
            elif str(q0_9_val).lower() in ("unknown", "cannot determine"):
                has_fields = "unknown"
                incomplete_reason = "Incomplete: Field layout presence unknown: claimant indicated field division is unknown."

        if has_fields == "yes":
            set_fact("has_fields", "yes", FactStatus.OBSERVED, "Q0.9_has_fields")
        elif has_fields == "no":
            set_fact("has_fields", "no", FactStatus.OBSERVED, "Q0.9_has_fields")

        if fields_per_unit is not None:
            set_fact("fields_per_unit", fields_per_unit, FactStatus.OBSERVED, "Q0.9")

        layout_uniform = effective_answers.get("Q0.10")
        if layout_uniform is not None:
            if str(layout_uniform).lower() in ("no", "n", "false"):
                set_fact("layout_uniform", "no", FactStatus.OBSERVED, "Q0.10")
                unsupported_branch_reason = "Unsupported Branch: Variable internal field layouts across units are not supported by the 4-rule encoding schema."
            elif str(layout_uniform).lower() in ("yes", "y", "true"):
                set_fact("layout_uniform", "yes", FactStatus.OBSERVED, "Q0.10")

        fields_equal_width = effective_answers.get("Q0.10b")
        f_a_len = effective_answers.get("Q0.11")
        f_b_len = effective_answers.get("Q0.12")
        f_c_len = effective_answers.get("Q0.13")
        f_d_len = effective_answers.get("Q0.14")

        if fields_equal_width is not None and str(fields_equal_width).lower() in ("yes", "y", "true"):
            set_fact("fields_equal_width", "yes", FactStatus.OBSERVED, "Q0.10b")
            eff_u_len = unit_len if unit_len is not None else facts.get("expected_unit_len", {}).get("val")
            if eff_u_len is not None and fields_per_unit is not None and fields_per_unit > 0:
                if eff_u_len % fields_per_unit != 0:
                    contradictions.append(f"H4: Unit length ({eff_u_len}) is not evenly divisible by equal field count ({fields_per_unit}).")
                else:
                    shared_f_len = eff_u_len // fields_per_unit
                    set_fact("f_a_len", shared_f_len, FactStatus.DERIVED, "unit_len / fields_per_unit")
                    set_fact("f_b_len", shared_f_len, FactStatus.DERIVED, "unit_len / fields_per_unit")
                    set_fact("f_c_len", shared_f_len, FactStatus.DERIVED, "unit_len / fields_per_unit")
                    set_fact("f_d_len", shared_f_len, FactStatus.DERIVED, "unit_len / fields_per_unit")
                    f_a_len = shared_f_len
                    f_b_len = shared_f_len
                    f_c_len = shared_f_len
                    f_d_len = shared_f_len
        elif fields_equal_width is not None and str(fields_equal_width).lower() in ("no", "n", "false"):
            set_fact("fields_equal_width", "no", FactStatus.OBSERVED, "Q0.10b")

        if f_a_len is not None and f_b_len is not None and f_c_len is not None:
            set_fact("f_a_len", f_a_len, FactStatus.OBSERVED, "Q0.11")
            set_fact("f_b_len", f_b_len, FactStatus.OBSERVED, "Q0.12")
            set_fact("f_c_len", f_c_len, FactStatus.OBSERVED, "Q0.13")
            eff_u_len = unit_len if unit_len is not None else facts.get("expected_unit_len", {}).get("val")
            if eff_u_len is not None:
                expected_d_len = eff_u_len - (f_a_len + f_b_len + f_c_len)
                set_fact("expected_d_len", expected_d_len, FactStatus.DERIVED, "H4 (unit_len - (A+B+C))", ["Q0.11", "Q0.12", "Q0.13"])
                if f_d_len is not None and f_d_len != expected_d_len:
                    contradictions.append(f"H0.11: Sum of field widths ({f_a_len + f_b_len + f_c_len + f_d_len}) does not equal unit length ({eff_u_len}) (Sum of field widths must match unit length; field D {f_d_len} != expected {expected_d_len}).")

        if f_d_len is not None:
            set_fact("f_d_len", f_d_len, FactStatus.OBSERVED, "Q0.14")

        # ------------------------------------------------------------------
        # 2. Evaluate Block 1: Ones per unit (Q1.1 - Q1.12)
        # ------------------------------------------------------------------
        unit_ones: Dict[int, int] = {}
        c_values: Dict[int, int] = {}
        for i in range(1, 13):
            q_key = f"Q1.{i}"
            if q_key in effective_answers:
                u_ones = effective_answers[q_key]
                unit_ones[i] = u_ones
                set_fact(f"unit_{i}_ones", u_ones, FactStatus.OBSERVED, q_key)

        # Derive Unit 13 ones if all 12 are observed and part1_ones is known
        part1_ones_val = facts.get("part1_ones", {}).get("val")
        if len(unit_ones) == 12 and part1_ones_val is not None:
            sum_12 = sum(unit_ones.values())
            if sum_12 > part1_ones_val:
                contradictions.append(f"H2: Sum of first 12 units' ones ({sum_12}) exceeds segment 1 ones ({part1_ones_val}).")
            else:
                u13_ones = part1_ones_val - sum_12
                unit_ones[13] = u13_ones
                set_fact("unit_13_ones", u13_ones, FactStatus.DERIVED, "H2 (part1_ones - sum(U1..U12))", ["part1_ones"] + [f"Q1.{i}" for i in range(1, 13)])

        # ------------------------------------------------------------------
        # 3. Evaluate Block 2: Field Totals (Q2.1 - Q2.4)
        # ------------------------------------------------------------------
        tot_a = effective_answers.get("Q2.1")
        tot_b = effective_answers.get("Q2.2")
        tot_c = effective_answers.get("Q2.3")
        is_even_ones = effective_answers.get("Q2.4")

        if tot_a is not None:
            set_fact("field_a_total_ones", tot_a, FactStatus.OBSERVED, "Q2.1")
        if tot_b is not None:
            set_fact("field_b_total_ones", tot_b, FactStatus.OBSERVED, "Q2.2")
        if tot_c is not None:
            set_fact("field_c_total_ones", tot_c, FactStatus.OBSERVED, "Q2.3")

        if is_even_ones is not None and "total_ones" in facts:
            actual_is_even = "yes" if (facts["total_ones"]["val"] % 2 == 0) else "no"
            if is_even_ones != actual_is_even:
                contradictions.append(f"Answered stream ones parity ('{is_even_ones}') contradicts derived total ones ({facts['total_ones']['val']}).")

        if tot_a is not None and tot_b is not None and tot_c is not None and part1_ones_val is not None:
            sum_abc = tot_a + tot_b + tot_c
            if sum_abc > part1_ones_val:
                contradictions.append(f"H4: Sum of fields A+B+C ones ({sum_abc}) exceeds segment 1 ones ({part1_ones_val}).")
            else:
                tot_d = part1_ones_val - sum_abc
                set_fact("field_d_total_ones", tot_d, FactStatus.DERIVED, "H4 (part1_ones - (A+B+C))", ["part1_ones", "Q2.1", "Q2.2", "Q2.3"])

        # ------------------------------------------------------------------
        # 4. Evaluate Block 3 & 4: Field A Equality Chain & Run Values
        # ------------------------------------------------------------------
        eq_answers: Dict[int, str] = {}
        for i in range(1, 13):
            q_key = f"Q3.{i}"
            if q_key in effective_answers:
                eq_answers[i] = effective_answers[q_key]

        # Partition into runs based on confirmed equality answers
        runs: List[List[int]] = []
        if len(eq_answers) == 12:
            current_run = [1]
            for i in range(1, 13):
                if eq_answers[i] == "yes":
                    current_run.append(i + 1)
                else:
                    runs.append(current_run)
                    current_run = [i + 1]
            runs.append(current_run)
            set_fact("a_runs", runs, FactStatus.DERIVED, "H6 (Transitive equality chain on A)", [f"Q3.{i}" for i in range(1, 13)])

        # Read A run representative values (Q4.1 - Q4.7)
        a_values: Dict[int, int] = {}
        rep_a_answers: Dict[int, int] = {}
        for r_idx in range(1, 8):
            q_key = f"Q4.{r_idx}"
            if q_key in effective_answers:
                rep_a_answers[r_idx] = effective_answers[q_key]

        if runs:
            # Assign answered representative values
            for r_idx, run_units in enumerate(runs, start=1):
                if r_idx in rep_a_answers:
                    rep_u = run_units[0]
                    a_values[rep_u] = rep_a_answers[r_idx]
                    set_fact(f"unit_{rep_u}_A", rep_a_answers[r_idx], FactStatus.OBSERVED, f"Q4.{r_idx}")

            weighted_a_popcount = None
            if len(rep_a_answers) == len(runs):
                # Propagate A to all units in runs
                weighted_a_popcount = 0
                for r_idx, run_units in enumerate(runs, start=1):
                    r_val = rep_a_answers[r_idx]
                    r_pop = get_popcount(r_val)
                    weighted_a_popcount += len(run_units) * r_pop
                    for u in run_units:
                        a_values[u] = r_val
                        status = FactStatus.OBSERVED if (u == run_units[0]) else FactStatus.DERIVED
                        set_fact(f"unit_{u}_A", r_val, status, f"Run {r_idx} equality propagation", [f"Q4.{r_idx}"] + [f"Q3.{i}" for i in range(1, 13)])

            # Validate weighted popcount against field A total ones
            tot_a_val = facts.get("field_a_total_ones", {}).get("val")
            if tot_a_val is not None and weighted_a_popcount is not None:
                if weighted_a_popcount != tot_a_val:
                    contradictions.append(f"H5: Weighted popcount of field A ({weighted_a_popcount}) does not equal field A total ones ({tot_a_val}).")

        # ------------------------------------------------------------------
        # 5. Evaluate Block 5: Field D Values & P1 Hypothesis
        # ------------------------------------------------------------------
        d_values: Dict[int, int] = {}
        rep_d_answers: Dict[int, int] = {}
        for r_idx in range(1, 8):
            q_key = f"Q5.{r_idx}"
            if q_key in effective_answers:
                rep_d_answers[r_idx] = effective_answers[q_key]

        spot_d4 = effective_answers.get("Q5.8")
        spot_d8 = effective_answers.get("Q5.9")

        # Check fallback answers if any
        fallback_d2 = effective_answers.get("Q5.10")
        fallback_d5 = effective_answers.get("Q5.11")
        fallback_d7 = effective_answers.get("Q5.12")
        fallback_d10 = effective_answers.get("Q5.13")

        p1_failed = False
        if runs and len(rep_d_answers) == len(runs):
            # Assign representative D values
            for r_idx, run_units in enumerate(runs, start=1):
                rep_u = run_units[0]
                d_values[rep_u] = rep_d_answers[r_idx]
                set_fact(f"unit_{rep_u}_D", rep_d_answers[r_idx], FactStatus.OBSERVED, f"Q5.{r_idx}")

            # Test P1 Hypothesis: Spot check validation
            # Run 2 includes units 3, 4, 5. Rep is 3. Spot check Q5.8 checks Unit 4.
            # Run 3 includes units 6, 7, 8. Rep is 6. Spot check Q5.9 checks Unit 8.
            rep_run2_d = rep_d_answers.get(2)
            rep_run3_d = rep_d_answers.get(3)

            if spot_d4 is not None and rep_run2_d is not None:
                if spot_d4 != rep_run2_d:
                    p1_failed = True
            if spot_d8 is not None and rep_run3_d is not None:
                if spot_d8 != rep_run3_d:
                    p1_failed = True

            # If spot checks haven't failed, record spot checks as OBSERVED and infer D for units 2, 5, 7, 10
            if not p1_failed:
                soft_hypotheses["P1"]["status"] = "ACTIVE"
                # Spot checks for Unit 4 and Unit 8 are directly OBSERVED
                if spot_d4 is not None:
                    d_values[4] = spot_d4
                    set_fact("unit_4_D", spot_d4, FactStatus.OBSERVED, "Q5.8")
                if spot_d8 is not None:
                    d_values[8] = spot_d8
                    set_fact("unit_8_D", spot_d8, FactStatus.OBSERVED, "Q5.9")

                # The four units inferred under P1 are units 2, 5, 7, and 10 (four 2-bit fields = 8 bits)
                inferred_units_map = {
                    2: (rep_d_answers.get(1), "Run 1 (Rep Unit 1)"),
                    5: (rep_d_answers.get(2), "Run 2 (Rep Unit 3)"),
                    7: (rep_d_answers.get(3), "Run 3 (Rep Unit 6)"),
                    10: (rep_d_answers.get(4), "Run 4 (Rep Unit 9)"),
                }
                for inf_u, (inf_val, inf_src) in inferred_units_map.items():
                    if inf_val is not None:
                        d_values[inf_u] = inf_val
                        set_fact(f"unit_{inf_u}_D", inf_val, FactStatus.INFERRED, f"P1 Hypothesis ({inf_src})", ["P1"])

                # Check popcount against D total
                tot_d_val = facts.get("field_d_total_ones", {}).get("val")
                if tot_d_val is not None:
                    d_pop_sum = sum(get_popcount(d_values[u]) for u in range(1, 14) if u in d_values)
                    if len(d_values) == 13 and d_pop_sum != tot_d_val:
                        p1_failed = True

            if p1_failed:
                soft_hypotheses["P1"]["status"] = "FAILED"
                # Retract inferred D facts and downstream C facts for non-representatives
                for u in [2, 5, 7, 10]:
                    if u in d_values:
                        del d_values[u]
                    facts[f"unit_{u}_D"] = {
                        "val": None,
                        "status": FactStatus.REJECTED.value,
                        "source": "P1 Retracted (Hypothesis Failed)",
                        "deps": [],
                    }
                    if f"unit_{u}_D" not in retracted_facts:
                        retracted_facts.append(f"unit_{u}_D")

                    if u in c_values:
                        del c_values[u]
                    facts[f"unit_{u}_C"] = {
                        "val": None,
                        "status": FactStatus.REJECTED.value,
                        "source": "P1 Retracted (Downstream C Invalidated)",
                        "deps": [],
                    }
                    if f"unit_{u}_C" not in retracted_facts:
                        retracted_facts.append(f"unit_{u}_C")

                # If fallbacks answered, populate with OBSERVED
                if fallback_d2 is not None:
                    d_values[2] = fallback_d2
                    set_fact("unit_2_D", fallback_d2, FactStatus.OBSERVED, "Q5.10 (Fallback)")
                if fallback_d5 is not None:
                    d_values[5] = fallback_d5
                    set_fact("unit_5_D", fallback_d5, FactStatus.OBSERVED, "Q5.11 (Fallback)")
                if fallback_d7 is not None:
                    d_values[7] = fallback_d7
                    set_fact("unit_7_D", fallback_d7, FactStatus.OBSERVED, "Q5.12 (Fallback)")
                if fallback_d10 is not None:
                    d_values[10] = fallback_d10
                    set_fact("unit_10_D", fallback_d10, FactStatus.OBSERVED, "Q5.13 (Fallback)")

                # If all fallbacks answered, re-verify total D popcount
                tot_d_val = facts.get("field_d_total_ones", {}).get("val")
                if tot_d_val is not None and len(d_values) == 13:
                    d_pop_sum = sum(get_popcount(d_values[u]) for u in range(1, 14))
                    if d_pop_sum != tot_d_val:
                        contradictions.append(f"H5: Sum of field D popcounts ({d_pop_sum}) contradicts field D total ones ({tot_d_val}).")
            else:
                # If spot checks confirmed and popcount verified, mark P1 as VALIDATED
                # Note: In accordance with provenance audit, facts remain INFERRED to keep hypothesis dependency explicit
                if spot_d4 is not None and spot_d8 is not None and len(d_values) == 13:
                    soft_hypotheses["P1"]["status"] = "VALIDATED"

        # ------------------------------------------------------------------
        # 6. Evaluate Block 6: Field B Values (Q6.1 - Q6.13)
        # ------------------------------------------------------------------
        b_sum_ans = effective_answers.get("Q6.1")
        if b_sum_ans is not None:
            set_fact("field_b_sum", b_sum_ans, FactStatus.OBSERVED, "Q6.1")

        b_values: Dict[int, int] = {}
        for i in range(1, 13):
            q_key = f"Q6.{i + 1}"
            if q_key in effective_answers:
                b_val = effective_answers[q_key]
                b_values[i] = b_val
                set_fact(f"unit_{i}_B", b_val, FactStatus.OBSERVED, q_key)

        # Derive B13 from sum
        if len(b_values) == 12 and b_sum_ans is not None:
            sum_12_b = sum(b_values.values())
            b13 = b_sum_ans - sum_12_b
            if b13 < 0 or b13 > 15:
                contradictions.append(f"H5: Derived field B13 ({b13}) is outside valid 4-bit range 0..15.")
            else:
                b_values[13] = b13
                set_fact("unit_13_B", b13, FactStatus.DERIVED, "H5 (B_sum - sum(B1..B12))", ["Q6.1"] + [f"Q6.{i + 1}" for i in range(1, 13)])

        # Check total popcount of B
        tot_b_val = facts.get("field_b_total_ones", {}).get("val")
        if tot_b_val is not None and len(b_values) == 13:
            b_pop_sum = sum(get_popcount(b_values[u]) for u in range(1, 14))
            if b_pop_sum != tot_b_val:
                contradictions.append(f"H5: Sum of field B popcounts ({b_pop_sum}) does not match field B total ones ({tot_b_val}).")

        # Check P3 soft hypothesis: Permutation of 1..13
        if len(b_values) == 13:
            b_set = set(b_values.values())
            is_p3 = (b_set == set(range(1, 14)) and sum(b_values.values()) == 91)
            soft_hypotheses["P3"]["status"] = "VALIDATED" if is_p3 else "FAILED"

        # ------------------------------------------------------------------
        # 7. Evaluate Block 7: Field C Derivations & Spot Checks (Q7.1, Q7.2)
        # ------------------------------------------------------------------
        c_values: Dict[int, int] = {}
        spot_c9 = effective_answers.get("Q7.1")
        spot_c10 = effective_answers.get("Q7.2")

        for u in range(1, 14):
            u_ones = unit_ones.get(u)
            a_v = a_values.get(u)
            b_v = b_values.get(u)
            d_v = d_values.get(u)

            if u_ones is not None and a_v is not None and b_v is not None and d_v is not None:
                # C_k = U_k - popcount(A) - popcount(B) - popcount(D)
                pop_a = get_popcount(a_v)
                pop_b = get_popcount(b_v)
                pop_d = get_popcount(d_v)
                c_calc = u_ones - pop_a - pop_b - pop_d

                d_status = facts.get(f"unit_{u}_D", {}).get("status")
                c_status = FactStatus.INFERRED if (d_status == FactStatus.INFERRED.value) else FactStatus.DERIVED

                if c_calc not in (0, 1):
                    if d_status == FactStatus.INFERRED.value:
                        # Soft hypothesis caused invalid C, retract hypothesis P1
                        soft_hypotheses["P1"]["status"] = "FAILED"
                        retracted_facts.append(f"unit_{u}_C")
                    else:
                        contradictions.append(f"H7: Derived 1-bit field C in unit {u} evaluates to {c_calc} (must be 0 or 1).")
                else:
                    c_values[u] = c_calc
                    set_fact(f"unit_{u}_C", c_calc, c_status, "H7 (Unit Additivity U - pop(A) - pop(B) - pop(D))", [f"unit_{u}_ones", f"unit_{u}_A", f"unit_{u}_B", f"unit_{u}_D"])

        # Spot checks for C9 and C10
        if spot_c9 is not None:
            set_fact("spot_check_C9", spot_c9, FactStatus.OBSERVED, "Q7.1")
            c9_calc = c_values.get(9)
            if c9_calc is not None and spot_c9 != c9_calc:
                contradictions.append(f"Spot check C9 ({spot_c9}) contradicts calculated C9 ({c9_calc}).")

        if spot_c10 is not None:
            set_fact("spot_check_C10", spot_c10, FactStatus.OBSERVED, "Q7.2")
            c10_calc = c_values.get(10)
            if c10_calc is not None and spot_c10 != c10_calc:
                contradictions.append(f"Spot check C10 ({spot_c10}) contradicts calculated C10 ({c10_calc}).")

        # Verify sum of C bits matches Q2.3 (7)
        tot_c_val = facts.get("field_c_total_ones", {}).get("val")
        if tot_c_val is not None and len(c_values) == 13:
            c_sum = sum(c_values.values())
            if c_sum != tot_c_val:
                contradictions.append(f"H4: Sum of field C bits ({c_sum}) does not equal field C total ones ({tot_c_val}).")

        # ------------------------------------------------------------------
        # 8. Assemble Candidate Units and Bitstream
        # ------------------------------------------------------------------
        unit_candidates: List[UnitCandidate] = []
        assembled_stream_chars: List[str] = []
        bit_provenance_list: List[BitProvenance] = []

        bit_cursor = 0
        all_bits_confirmed = True

        for idx, node_id in enumerate(CANONICAL_REFERENCE_NODES, start=1):
            a_v = a_values.get(idx)
            b_v = b_values.get(idx)
            c_v = c_values.get(idx)
            d_v = d_values.get(idx)
            u_ones = unit_ones.get(idx)

            a_str = format(a_v, "04b") if (a_v is not None and 0 <= a_v <= 15) else "????"
            b_str = format(b_v, "04b") if (b_v is not None and 0 <= b_v <= 15) else "????"
            c_str = str(c_v) if (c_v is not None and c_v in (0, 1)) else "?"
            d_str = format(d_v, "02b") if (d_v is not None and 0 <= d_v <= 3) else "??"
            u_str = f"{a_str}{b_str}{c_str}{d_str}"

            u_status = "CONFIRMED"
            if "?" in u_str:
                u_status = "UNKNOWN"
                all_bits_confirmed = False
            elif any(facts.get(f"unit_{idx}_{f}", {}).get("status") == FactStatus.INFERRED.value for f in ("A", "B", "C", "D")):
                u_status = "INFERRED"
                all_bits_confirmed = False

            meta = CANONICAL_REFERENCE_UNITS.get(idx)
            if meta:
                pos_val = idx
                cs_val = meta["cs"]
                cs_lbl = f"T{cs_val}"
                node_lbl = f"N{node_id}"
            else:
                pos_val = idx
                cs_val = 0
                cs_lbl = "UNMAPPED_CS"
                node_lbl = f"N{node_id}"

            unit_candidates.append(UnitCandidate(
                unit_index=idx,
                node_id=node_id,
                position=pos_val,
                cs_step=cs_val,
                cs_label=cs_lbl,
                node_label=node_lbl,
                a_val=a_v,
                b_val=b_v,
                c_val=c_v,
                d_val=d_v,
                a_bits=a_str,
                b_bits=b_str,
                c_bits=c_str,
                d_bits=d_str,
                assembled_bits=u_str,
                ones_count=u_ones,
                status=u_status,
            ))
            assembled_stream_chars.append(u_str)

            # Record bit-level provenance
            # Field A (4 bits)
            for bit_char in a_str:
                status = facts.get(f"unit_{idx}_A", {}).get("status", "UNKNOWN")
                src = facts.get(f"unit_{idx}_A", {}).get("source", "none")
                bit_provenance_list.append(BitProvenance(
                    bit_index=bit_cursor,
                    value=bit_char if bit_char != "?" else None,
                    status=status,
                    source_constraint=src,
                    source_facts=facts.get(f"unit_{idx}_A", {}).get("deps", []),
                ))
                bit_cursor += 1

            # Field B (4 bits)
            for bit_char in b_str:
                status = facts.get(f"unit_{idx}_B", {}).get("status", "UNKNOWN")
                src = facts.get(f"unit_{idx}_B", {}).get("source", "none")
                bit_provenance_list.append(BitProvenance(
                    bit_index=bit_cursor,
                    value=bit_char if bit_char != "?" else None,
                    status=status,
                    source_constraint=src,
                    source_facts=facts.get(f"unit_{idx}_B", {}).get("deps", []),
                ))
                bit_cursor += 1

            # Field C (1 bit)
            status = facts.get(f"unit_{idx}_C", {}).get("status", "UNKNOWN")
            src = facts.get(f"unit_{idx}_C", {}).get("source", "none")
            bit_provenance_list.append(BitProvenance(
                bit_index=bit_cursor,
                value=c_str if c_str != "?" else None,
                status=status,
                source_constraint=src,
                source_facts=facts.get(f"unit_{idx}_C", {}).get("deps", []),
            ))
            bit_cursor += 1

            # Field D (2 bits)
            for bit_char in d_str:
                status = facts.get(f"unit_{idx}_D", {}).get("status", "UNKNOWN")
                src = facts.get(f"unit_{idx}_D", {}).get("source", "none")
                bit_provenance_list.append(BitProvenance(
                    bit_index=bit_cursor,
                    value=bit_char if bit_char != "?" else None,
                    status=status,
                    source_constraint=src,
                    source_facts=facts.get(f"unit_{idx}_D", {}).get("deps", []),
                ))
                bit_cursor += 1

        reconstructed_str = "".join(assembled_stream_chars)

        # Statistics
        obs_count = sum(1 for bp in bit_provenance_list if bp.status == FactStatus.OBSERVED.value)
        der_count = sum(1 for bp in bit_provenance_list if bp.status == FactStatus.DERIVED.value)
        inf_count = sum(1 for bp in bit_provenance_list if bp.status == FactStatus.INFERRED.value)
        unk_count = sum(1 for bp in bit_provenance_list if bp.status not in (FactStatus.OBSERVED.value, FactStatus.DERIVED.value, FactStatus.INFERRED.value) or bp.value is None)

        bit_stats = {
            "total_bits": 143,
            "observed_bits": obs_count,
            "derived_bits": der_count,
            "inferred_bits": inf_count,
            "unknown_bits": unk_count,
        }

        # ------------------------------------------------------------------
        # 8b. Evaluate Secured Rule 5: Blocks 8 - 11 (if workflow is secured)
        # ------------------------------------------------------------------
        pair_candidates: List[PairCandidate] = []
        r5_reconstructed_str = ""
        all_r5_pairs_confirmed = False
        r5_total_ones = None
        r5_applicable: Optional[str] = None

        if workflow == "secured_design_encoding":
            q8_0 = effective_answers.get("Q8.0")
            if q8_0 is not None:
                if str(q8_0).lower() in ("yes", "y", "true"):
                    r5_applicable = "yes"
                    set_fact("r5_applicable", "yes", FactStatus.OBSERVED, "Q8.0")
                elif str(q8_0).lower() in ("no", "n", "false"):
                    r5_applicable = "no"
                    set_fact("r5_applicable", "no", FactStatus.OBSERVED, "Q8.0")
                elif str(q8_0).lower() in ("unknown", "cannot determine"):
                    r5_applicable = "unknown"
                    incomplete_reason = "Incomplete: Rule 5 structural applicability is unknown."
            elif any(k.startswith("Q8.") or k.startswith("Q9.") or k.startswith("Q10.") or k.startswith("Q11.") for k in effective_answers):
                # Backward compatibility with existing tests that answer Q8.1 directly without Q8.0
                r5_applicable = "yes"
                set_fact("r5_applicable", "yes", FactStatus.OBSERVED, "Q8.1")

        if workflow == "secured_design_encoding" and r5_applicable != "no" and not incomplete_reason:
            # Block 8: Rule 5 Structure & Partition
            r5_total_bits = effective_answers.get("Q8.1")
            r5_pairs_count = effective_answers.get("Q8.2")
            r5_pair_len = effective_answers.get("Q8.3")
            r5_reg_width = effective_answers.get("Q8.4")
            r5_var_width = effective_answers.get("Q8.5")
            r5_seq_order = effective_answers.get("Q8.6")
            r5_zeros = effective_answers.get("Q8.7")

            if r5_total_bits is not None:
                set_fact("r5_total_bits", r5_total_bits, FactStatus.OBSERVED, "Q8.1")
                if r5_total_bits != 108:
                    contradictions.append(f"H8.1: Declared Rule 5 length ({r5_total_bits}) contradicts required 108 bits.")

            if r5_pairs_count is not None:
                set_fact("r5_pairs_count", r5_pairs_count, FactStatus.OBSERVED, "Q8.2")
                if r5_pairs_count != 27:
                    contradictions.append(f"H8.2: Declared pair count ({r5_pairs_count}) contradicts expected 27 pairs.")

            if r5_pair_len is not None:
                set_fact("r5_pair_len", r5_pair_len, FactStatus.OBSERVED, "Q8.3")
                if r5_pair_len != 4:
                    contradictions.append(f"H8.3: Pair bit length ({r5_pair_len}) contradicts required 4 bits per pair.")

            if r5_pairs_count is not None and r5_pair_len is not None:
                calc_r5_len = r5_pairs_count * r5_pair_len
                set_fact("derived_r5_len", calc_r5_len, FactStatus.DERIVED, "H8 (pairs * pair_len)", ["Q8.2", "Q8.3"])
                if r5_total_bits is not None and r5_total_bits != calc_r5_len:
                    contradictions.append(f"H8: Total Rule 5 bits ({r5_total_bits}) contradicts pairs * pair_len ({calc_r5_len}).")

            if r5_reg_width is not None and r5_var_width is not None:
                calc_pair_w = r5_reg_width + r5_var_width
                if r5_pair_len is not None and r5_pair_len != calc_pair_w:
                    contradictions.append(f"H8.4: Register width ({r5_reg_width}) + Var width ({r5_var_width}) != pair width ({r5_pair_len}).")

            # Block 9: Parity Rules & Ones
            r5_odd_code = effective_answers.get("Q9.1")
            r5_even_code = effective_answers.get("Q9.2")
            r5_ones_ans = effective_answers.get("Q9.3")
            r5_layout_ans = effective_answers.get("Q9.4")

            if r5_odd_code is not None:
                set_fact("r5_odd_code", r5_odd_code, FactStatus.OBSERVED, "Q9.1")
                if str(r5_odd_code).strip() != "01":
                    contradictions.append(f"H9.1: Odd parity code must be '01', got '{r5_odd_code}'.")

            if r5_even_code is not None:
                set_fact("r5_even_code", r5_even_code, FactStatus.OBSERVED, "Q9.2")
                if str(r5_even_code).strip() != "00":
                    contradictions.append(f"H9.2: Even parity code must be '00', got '{r5_even_code}'.")

            if r5_zeros is not None:
                set_fact("r5_zeros", r5_zeros, FactStatus.OBSERVED, "Q8.7")
            if r5_ones_ans is not None:
                r5_total_ones = r5_ones_ans
                set_fact("r5_ones", r5_ones_ans, FactStatus.OBSERVED, "Q9.3")
                if r5_zeros is not None:
                    if r5_zeros + r5_ones_ans != 108:
                        contradictions.append(f"H9.3: Zeros ({r5_zeros}) + Ones ({r5_ones_ans}) != 108 Rule 5 bits.")

            # Block 10: Aggregate checks
            odd_vars = effective_answers.get("Q10.1")
            even_vars = effective_answers.get("Q10.2")
            odd_regs = effective_answers.get("Q10.3")
            even_regs = effective_answers.get("Q10.4")
            c1_ones = effective_answers.get("Q10.5")
            c2_ones = effective_answers.get("Q10.6")
            c3_ones = effective_answers.get("Q10.7")

            if odd_vars is not None and even_vars is not None:
                if odd_vars + even_vars != 27:
                    contradictions.append(f"H10.1: Odd vars ({odd_vars}) + Even vars ({even_vars}) != 27.")

            if odd_regs is not None and even_regs is not None:
                if odd_regs + even_regs != 27:
                    contradictions.append(f"H10.2: Odd regs ({odd_regs}) + Even regs ({even_regs}) != 27.")

            if c1_ones is not None and c2_ones is not None and c3_ones is not None:
                if c1_ones + c2_ones + c3_ones != 28:
                    contradictions.append(f"H10.5: Chunk ones sum ({c1_ones + c2_ones + c3_ones}) != total Rule 5 ones (28).")

            # Block 11: Register Parity Deductions & Relational Verification (27 Pairs)
            reg_parities: Dict[int, str] = {}
            reg_sources: Dict[int, str] = {}

            # Chunk 1: V1..V8
            if "Q11.1" in effective_answers:
                if effective_answers["Q11.1"] == "yes":
                    reg_parities[1] = "Odd"
                    reg_sources[1] = "Q11.1"
                else:
                    contradictions.append("H11.1: Variable V1 must have odd register parity (R1).")

            if "Q11.2" in effective_answers:
                if effective_answers["Q11.2"] == "no":
                    reg_parities[2] = "Even"
                    reg_sources[2] = "Q11.2"
                else:
                    contradictions.append("H11.2: Variable V2 must have even register parity (R2).")

            if "Q11.3" in effective_answers:
                if effective_answers["Q11.3"] == "yes":
                    reg_parities[3] = "Odd"
                    reg_sources[3] = "Q11.3"
                else:
                    contradictions.append("H11.3: Variable V3 must have odd register parity (R3).")

            if "Q11.4" in effective_answers:
                if effective_answers["Q11.4"] == "no":
                    reg_parities[4] = "Even"
                    reg_sources[4] = "Q11.4"
                else:
                    contradictions.append("H11.4: Variable V4 must have even register parity (R4).")

            if "Q11.5" in effective_answers:
                if effective_answers["Q11.5"] == "yes":
                    if 2 in reg_parities:
                        reg_parities[5] = reg_parities[2]
                        reg_sources[5] = "Q11.5 (Shares with V2)"
                else:
                    contradictions.append("H11.5: Variable V5 must share register parity with V2 (both R2, Even).")

            if "Q11.6" in effective_answers:
                if effective_answers["Q11.6"] == "yes":
                    if 3 in reg_parities:
                        reg_parities[6] = reg_parities[3]
                        reg_sources[6] = "Q11.6 (Shares with V3)"
                else:
                    contradictions.append("H11.6: Variable V6 must share register parity with V3 (both R3, Odd).")

            if "Q11.7" in effective_answers:
                if effective_answers["Q11.7"] == "yes":
                    reg_parities[7] = "Odd"
                    reg_sources[7] = "Q11.7"
                else:
                    contradictions.append("H11.7: Variable V7 must have odd register parity (R5).")

            if "Q11.8" in effective_answers:
                if effective_answers["Q11.8"] == "no":
                    reg_parities[8] = "Even"
                    reg_sources[8] = "Q11.8"
                else:
                    contradictions.append("H11.8: Variable V8 must have even register parity (R6).")

            # Derivation of V9 from Chunk 1 sum (Q10.5 = 10)
            if c1_ones is not None and all(k in reg_parities for k in range(1, 9)):
                sum_1_8 = sum((1 if reg_parities[k] == "Odd" else 0) + (1 if k % 2 != 0 else 0) for k in range(1, 9))
                rem_c1 = c1_ones - sum_1_8
                if rem_c1 - 1 == 1:
                    reg_parities[9] = "Odd"
                    reg_sources[9] = "DERIVED (Q10.5 Chunk 1 balance)"
                    set_fact("r5_v9_derived", "Odd", FactStatus.DERIVED, "H10.5", ["Q10.5"] + [f"Q11.{x}" for x in range(1, 9)])
                elif rem_c1 - 1 == 0:
                    reg_parities[9] = "Even"
                    reg_sources[9] = "DERIVED (Q10.5 Chunk 1 balance)"
                else:
                    contradictions.append(f"H10.5: Inconsistent Chunk 1 ones remainder ({rem_c1}) for pair V9.")

            # Chunk 2: V10..V18
            if "Q11.9" in effective_answers:
                if effective_answers["Q11.9"] == "no":
                    reg_parities[10] = "Even"
                    reg_sources[10] = "Q11.9"
                else:
                    contradictions.append("H11.9: Variable V10 must have even register parity (R8).")

            if "Q11.10" in effective_answers:
                if effective_answers["Q11.10"] == "yes":
                    if 4 in reg_parities:
                        reg_parities[11] = reg_parities[4]
                        reg_sources[11] = "Q11.10 (Shares with V4)"
                else:
                    contradictions.append("H11.10: Variable V11 must share register parity with V4 (both R4, Even).")

            if "Q11.11" in effective_answers:
                if effective_answers["Q11.11"] == "yes":
                    if 7 in reg_parities:
                        reg_parities[12] = reg_parities[7]
                        reg_sources[12] = "Q11.11 (Shares with V7)"
                else:
                    contradictions.append("H11.11: Variable V12 must share register parity with V7 (both R5, Odd).")

            if "Q11.12" in effective_answers:
                if effective_answers["Q11.12"] == "yes":
                    if 10 in reg_parities:
                        reg_parities[13] = reg_parities[10]
                        reg_sources[13] = "Q11.12 (Shares with V10)"
                else:
                    contradictions.append("H11.12: Variable V13 must share register parity with V10 (both R8, Even).")

            if "Q11.13" in effective_answers:
                if effective_answers["Q11.13"] == "yes":
                    reg_parities[14] = "Odd"
                    reg_sources[14] = "Q11.13"
                else:
                    contradictions.append("H11.13: Variable V14 must have odd register parity (R9).")

            if "Q11.14" in effective_answers:
                if effective_answers["Q11.14"] == "yes":
                    reg_parities[14] = "Odd"
                    reg_parities[15] = "Even"
                    reg_parities[16] = "Odd"
                    reg_parities[17] = "Even"
                    reg_sources[14] = "Q11.14 (Alternating V14..V17)"
                    reg_sources[15] = "Q11.14 (Alternating V14..V17)"
                    reg_sources[16] = "Q11.14 (Alternating V14..V17)"
                    reg_sources[17] = "Q11.14 (Alternating V14..V17)"
                else:
                    contradictions.append("H11.14: Variables V14 through V17 must alternate register parities (Odd, Even, Odd, Even).")

            if "Q11.15" in effective_answers:
                if effective_answers["Q11.15"] == "yes":
                    if 1 in reg_parities:
                        reg_parities[18] = reg_parities[1]
                        reg_sources[18] = "Q11.15 (Shares with V1)"
                else:
                    contradictions.append("H11.15: Variable V18 must share register parity with V1 (both R1, Odd).")

            # Chunk 3: V19..V26
            if "Q11.16" in effective_answers:
                if effective_answers["Q11.16"] == "yes":
                    if 14 in reg_parities:
                        reg_parities[19] = reg_parities[14]
                        reg_sources[19] = "Q11.16 (Shares with V14)"
                else:
                    contradictions.append("H11.16: Variable V19 must share register parity with V14 (both R9, Odd).")

            if "Q11.17" in effective_answers:
                if effective_answers["Q11.17"] == "yes":
                    if 9 in reg_parities:
                        reg_parities[20] = reg_parities[9]
                        reg_sources[20] = "Q11.17 (Shares with V9)"
                else:
                    contradictions.append("H11.17: Variable V20 must share register parity with V9 (both R7, Odd).")

            if "Q11.18" in effective_answers:
                if effective_answers["Q11.18"] == "yes":
                    reg_parities[21] = "Odd"
                    reg_sources[21] = "Q11.18"
                else:
                    contradictions.append("H11.18: Variable V21 must have odd register parity (R13).")

            if "Q11.19" in effective_answers:
                if effective_answers["Q11.19"] == "no":
                    reg_parities[22] = "Even"
                    reg_sources[22] = "Q11.19"
                else:
                    contradictions.append("H11.19: Variable V22 must have even register parity (R14).")

            if "Q11.20" in effective_answers:
                if effective_answers["Q11.20"] == "yes":
                    if 8 in reg_parities:
                        reg_parities[23] = reg_parities[8]
                        reg_sources[23] = "Q11.20 (Shares with V8)"
                else:
                    contradictions.append("H11.20: Variable V23 must share register parity with V8 (both R6, Even).")

            if "Q11.21" in effective_answers:
                if effective_answers["Q11.21"] == "yes":
                    if 21 in reg_parities:
                        reg_parities[24] = reg_parities[21]
                        reg_sources[24] = "Q11.21 (Shares with V21)"
                else:
                    contradictions.append("H11.21: Variable V24 must share register parity with V21 (both R13, Odd).")

            if "Q11.22" in effective_answers:
                if effective_answers["Q11.22"] == "yes":
                    if 16 in reg_parities:
                        reg_parities[25] = reg_parities[16]
                        reg_sources[25] = "Q11.22 (Shares with V16)"
                else:
                    contradictions.append("H11.22: Variable V25 must share register parity with V16 (both R11, Odd).")

            if "Q11.23" in effective_answers:
                if effective_answers["Q11.23"] == "yes":
                    if 17 in reg_parities:
                        reg_parities[26] = reg_parities[17]
                        reg_sources[26] = "Q11.23 (Shares with V17)"
                else:
                    contradictions.append("H11.23: Variable V26 must share register parity with V17 (both R12, Even).")

            # Derivation of V27 from Chunk 3 sum (Q10.7 = 9)
            if c3_ones is not None and all(k in reg_parities for k in range(19, 27)):
                sum_19_26 = sum((1 if reg_parities[k] == "Odd" else 0) + (1 if k % 2 != 0 else 0) for k in range(19, 27))
                rem_c3 = c3_ones - sum_19_26
                if rem_c3 - 1 == 0:
                    reg_parities[27] = "Even"
                    reg_sources[27] = "DERIVED (Q10.7 Chunk 3 balance)"
                    set_fact("r5_v27_derived", "Even", FactStatus.DERIVED, "H10.7", ["Q10.7"] + [f"Q11.{x}" for x in range(16, 24)])
                elif rem_c3 - 1 == 1:
                    reg_parities[27] = "Odd"
                    reg_sources[27] = "DERIVED (Q10.7 Chunk 3 balance)"
                else:
                    contradictions.append(f"H10.7: Inconsistent Chunk 3 ones remainder ({rem_c3}) for pair V27.")

            # Assemble Pair Candidates
            r5_pair_bits_list: List[str] = []
            observed_odd_regs = 0
            observed_even_regs = 0
            all_r5_pairs_confirmed = True

            for i in range(1, 28):
                v_name = f"V{i}"
                v_parity = "Odd" if (i % 2 != 0) else "Even"
                v_code = "01" if (i % 2 != 0) else "00"
                canon_r = CANONICAL_SECURED_RULE5_REGISTERS[v_name]
                canon_r_idx = int(canon_r.replace("R", ""))
                bit_p2 = (i - 1) * 4
                bit_glob = 143 + bit_p2
                bit_range_str = f"Bit {bit_glob}..{bit_glob + 3}"

                if i in reg_parities:
                    r_parity = reg_parities[i]
                    r_code = "01" if r_parity == "Odd" else "00"
                    pair_bits = f"{r_code}{v_code}"
                    p_fixed = True
                    p_status = "CONFIRMED"
                    src = reg_sources.get(i, "OBSERVED")
                    p_prov = FactStatus.DERIVED.value if "DERIVED" in src else FactStatus.OBSERVED.value
                    if r_parity == "Odd":
                        observed_odd_regs += 1
                    else:
                        observed_even_regs += 1
                    set_fact(f"r5_pair_{i}", pair_bits, FactStatus(p_prov), src)
                else:
                    r_parity = None
                    r_code = "??"
                    pair_bits = "????"
                    p_fixed = False
                    p_status = "UNRESOLVED"
                    p_prov = "UNKNOWN"
                    all_r5_pairs_confirmed = False

                pair_candidates.append(PairCandidate(
                    pair_index=i,
                    variable_name=v_name,
                    variable_index=i,
                    variable_parity=v_parity,
                    variable_parity_code=v_code,
                    register_name=None,
                    register_index=None,
                    register_parity=r_parity,
                    register_parity_code=r_code,
                    four_bit_code=pair_bits,
                    bit_offset_part2=bit_p2,
                    bit_offset_global=bit_glob,
                    bit_range=bit_range_str,
                    is_fixed=p_fixed,
                    status=p_status,
                    provenance=p_prov,
                ))
                r5_pair_bits_list.append(pair_bits)

            r5_reconstructed_str = "".join(r5_pair_bits_list)

            # Chunk checks
            if c1_ones is not None and all(pair_candidates[idx].is_fixed for idx in range(9)):
                chunk1_ones_calc = sum(pair_candidates[idx].four_bit_code.count("1") for idx in range(9))
                if chunk1_ones_calc != c1_ones:
                    contradictions.append(f"H10.5: Ones in first 9 pairs ({chunk1_ones_calc}) contradicts Q10.5 answer ({c1_ones}).")

            if c2_ones is not None and all(pair_candidates[idx].is_fixed for idx in range(9, 18)):
                chunk2_ones_calc = sum(pair_candidates[idx].four_bit_code.count("1") for idx in range(9, 18))
                if chunk2_ones_calc != c2_ones:
                    contradictions.append(f"H10.6: Ones in middle 9 pairs ({chunk2_ones_calc}) contradicts Q10.6 answer ({c2_ones}).")

            if c3_ones is not None and all(pair_candidates[idx].is_fixed for idx in range(18, 27)):
                chunk3_ones_calc = sum(pair_candidates[idx].four_bit_code.count("1") for idx in range(18, 27))
                if chunk3_ones_calc != c3_ones:
                    contradictions.append(f"H10.7: Ones in final 9 pairs ({chunk3_ones_calc}) contradicts Q10.7 answer ({c3_ones}).")

            if all_r5_pairs_confirmed and "?" not in r5_reconstructed_str:
                if odd_regs is not None and observed_odd_regs != odd_regs:
                    contradictions.append(f"H10.3: Observed odd registers ({observed_odd_regs}) contradicts Q10.3 ({odd_regs}).")
                if even_regs is not None and observed_even_regs != even_regs:
                    contradictions.append(f"H10.4: Observed even registers ({observed_even_regs}) contradicts Q10.4 ({even_regs}).")
                if r5_total_ones is not None:
                    tot_r5_ones_calc = r5_reconstructed_str.count("1")
                    if tot_r5_ones_calc != r5_total_ones:
                        contradictions.append(f"H9.3: Total Rule 5 ones ({tot_r5_ones_calc}) contradicts Q9.3 ({r5_total_ones}).")

        # ------------------------------------------------------------------
        # 9. Determine Progressive Reconstruction Stage
        # ------------------------------------------------------------------
        is_complete_143 = (
            len(reconstructed_str) == 143
            and "?" not in reconstructed_str
            and not contradictions
            and not p1_failed
        )
        is_complete_rule5 = bool(
            workflow == "secured_design_encoding"
            and all_r5_pairs_confirmed
            and "?" not in r5_reconstructed_str
            and len(r5_reconstructed_str) == 108
            and not contradictions
        )

        if unsupported_branch_reason:
            recon_stage = ReconstructionStage.STAGE_UNSUPPORTED
            recon_title = "Unsupported Structural Branch"
            recon_desc = unsupported_branch_reason
        elif incomplete_reason:
            recon_stage = ReconstructionStage.STAGE_INCOMPLETE
            recon_title = "Incomplete Structural Branch"
            recon_desc = incomplete_reason
        elif parts_divided == "no":
            recon_stage = ReconstructionStage.STAGE_MONOLITHIC
            recon_title = f"Monolithic Stream ({total_bits} bits)"
            recon_desc = "Encoding evaluated as a single complete stream without independent structural segments."
        elif total_bits is None:
            recon_stage = ReconstructionStage.STAGE_A
            recon_title = "Stage A: Awaiting Total Bitstream Length"
            recon_desc = "Total structural bit length is unknown. Final candidate grid is unallocated until Q0.1 is accepted."
        elif total_zeros is None:
            recon_stage = ReconstructionStage.STAGE_B
            recon_title = f"Stage B: Total Bitstream Length Established ({total_bits} bits)"
            recon_desc = f"Encoding allocated with exactly {total_bits} candidate positions. All positions are UNKNOWN."
        elif parts_count is None or part1_len is None:
            recon_stage = ReconstructionStage.STAGE_C
            recon_title = f"Stage C: Population Counts Established ({total_zeros} zeros, {facts.get('total_ones', {}).get('val', '?')} ones)"
            recon_desc = "Aggregate population is confirmed in the provisional pool. Canonical bit positions remain unfixed (RED)."
        elif num_units is None or unit_len is None:
            recon_stage = ReconstructionStage.STAGE_D
            recon_title = f"Stage D: Independent Segments Divided (Part 1: {part1_len}b)"
            recon_desc = "Stream divided into two structural segments. Reusable grid supports segment inspection."
        elif f_a_len is None or f_b_len is None or f_c_len is None or f_d_len is None:
            recon_stage = ReconstructionStage.STAGE_E
            recon_title = f"Stage E: Part 1 Subdivided into {num_units} Units ({unit_len}b each)"
            recon_desc = "Unit boundaries revealed in canonical schedule order. Internal field layout pending."
        elif not is_complete_143:
            recon_stage = ReconstructionStage.STAGE_F
            recon_title = f"Stage F: Per-Unit Field Layout Active (A:{f_a_len}b | B:{f_b_len}b | C:{f_c_len}b | D:{f_d_len}b)"
            recon_desc = "Per-Unit Field Assembly table active. Observed and derived fields progressively fix canonical cells (GREEN)."
        elif workflow == "secured_design_encoding":
            if r5_applicable == "no":
                recon_stage = ReconstructionStage.STAGE_F
                recon_title = "Stage S1 Complete (Rule 5 Not Applicable)"
                recon_desc = "143-bit Four-Rule design encoding complete. Rule 5 stage marked not applicable by claimant."
            elif not is_complete_rule5:
                recon_stage = ReconstructionStage.STAGE_G
                recon_title = "Stage S2: Rule 5 Interrogation In Progress"
                recon_desc = "143-bit Four-Rule encoding reconstructed. Interrogating 27 register/storage-variable allocation pairs."
            else:
                recon_stage = ReconstructionStage.STAGE_H
                recon_title = "Stage S3: Full 251-Bit Secured Design Encoding Assembled"
                recon_desc = "Both 143-bit Four-Rule and 108-bit Rule 5 streams successfully reconstructed and assembled."
        else:
            recon_stage = ReconstructionStage.STAGE_F
            recon_title = "Stage U1: Four-Rule Design Encoding Complete (143 bits)"
            recon_desc = "143-bit four-rule encoding reconstructed. Stage U2 (Unsecured Rule 5) is pending implementation."

        units_established = (has_units == "yes" and recon_stage in (ReconstructionStage.STAGE_E, ReconstructionStage.STAGE_F, ReconstructionStage.STAGE_G, ReconstructionStage.STAGE_H, ReconstructionStage.STAGE_I))
        fields_established = (has_fields == "yes" and recon_stage in (ReconstructionStage.STAGE_F, ReconstructionStage.STAGE_G, ReconstructionStage.STAGE_H, ReconstructionStage.STAGE_I))

        # ------------------------------------------------------------------
        # 10. Build Authoritative Reusable Cell Grids (Part 1, Part 2, Entire)
        # ------------------------------------------------------------------
        part1_cells: List[ReconstructionCell] = []
        part2_cells: List[ReconstructionCell] = []
        entire_cells: List[ReconstructionCell] = []

        eff_p1_len = part1_len if part1_len is not None else (total_bits if total_bits is not None else 143)
        eff_p2_len = (facts.get("part2_len", {}).get("val", 108)) if (parts_divided != "no" and r5_applicable != "no") else 0

        if recon_stage == ReconstructionStage.STAGE_A:
            part1_cells = []
            part2_cells = []
            entire_cells = []
        elif recon_stage == ReconstructionStage.STAGE_B:
            tot_b = total_bits or 251
            for b_i in range(tot_b):
                entire_cells.append(ReconstructionCell(
                    bit_index=b_i,
                    canonical_pos=b_i + 1,
                    segment="entire",
                    value=None,
                    display_char="?",
                    is_fixed=False,
                    fill=CellFill.NEUTRAL,
                    provenance="UNKNOWN",
                    source="Unallocated candidate position",
                ))
        elif recon_stage == ReconstructionStage.STAGE_C:
            tot_b = total_bits or 251
            for b_i in range(tot_b):
                entire_cells.append(ReconstructionCell(
                    bit_index=b_i,
                    canonical_pos=b_i + 1,
                    segment="entire",
                    value=None,
                    display_char="?",
                    is_fixed=False,
                    fill=CellFill.RED,
                    provenance="UNKNOWN",
                    source="Provisional pool; canonical position unfixed",
                ))
        else:
            # Build Part 1 cells (143 bits)
            for b_i in range(eff_p1_len):
                u_idx: Optional[int] = None
                u_off: Optional[int] = None
                n_id: Optional[int] = None
                n_lbl: Optional[str] = None
                cs_s: Optional[int] = None
                cs_lbl: Optional[str] = None
                f_name: Optional[str] = None
                f_off: Optional[int] = None
                c_val: Optional[str] = None
                c_disp: str = "?"
                c_fixed: bool = False
                c_fill: CellFill = CellFill.RED
                c_prov: str = "UNKNOWN"
                c_src: str = "Position unfixed in Part 1"

                if units_established:
                    u_idx = (b_i // 11) + 1
                    u_off = b_i % 11
                    if u_idx <= len(CANONICAL_REFERENCE_NODES):
                        n_id = CANONICAL_REFERENCE_NODES[u_idx - 1]
                        meta = CANONICAL_REFERENCE_UNITS.get(u_idx, {})
                        cs_s = meta.get("cs", 1)
                        n_lbl = f"N{n_id}"
                        cs_lbl = f"T{cs_s}"
                    else:
                        n_lbl = "UNMAPPED_NODE"
                        cs_lbl = "UNMAPPED_CS"

                if fields_established and u_idx is not None and u_off is not None:
                    if 0 <= u_off < 4:
                        f_name = "A"
                        f_off = u_off
                        c_prov = facts.get(f"unit_{u_idx}_A", {}).get("status", "UNKNOWN")
                        c_src = facts.get(f"unit_{u_idx}_A", {}).get("source", "none")
                        a_v = a_values.get(u_idx)
                        if a_v is not None and 0 <= a_v <= 15:
                            c_val = format(a_v, "04b")[f_off]
                    elif 4 <= u_off < 8:
                        f_name = "B"
                        f_off = u_off - 4
                        c_prov = facts.get(f"unit_{u_idx}_B", {}).get("status", "UNKNOWN")
                        c_src = facts.get(f"unit_{u_idx}_B", {}).get("source", "none")
                        b_v = b_values.get(u_idx)
                        if b_v is not None and 0 <= b_v <= 15:
                            c_val = format(b_v, "04b")[f_off]
                    elif u_off == 8:
                        f_name = "C"
                        f_off = 0
                        c_prov = facts.get(f"unit_{u_idx}_C", {}).get("status", "UNKNOWN")
                        c_src = facts.get(f"unit_{u_idx}_C", {}).get("source", "none")
                        c_v = c_values.get(u_idx)
                        if c_v is not None and c_v in (0, 1):
                            c_val = str(c_v)
                    elif 9 <= u_off < 11:
                        f_name = "D"
                        f_off = u_off - 9
                        c_prov = facts.get(f"unit_{u_idx}_D", {}).get("status", "UNKNOWN")
                        c_src = facts.get(f"unit_{u_idx}_D", {}).get("source", "none")
                        d_v = d_values.get(u_idx)
                        if d_v is not None and 0 <= d_v <= 3:
                            c_val = format(d_v, "02b")[f_off]

                    if c_val is not None and c_prov in (FactStatus.OBSERVED.value, FactStatus.DERIVED.value):
                        c_fixed = True
                        c_fill = CellFill.GREEN
                        c_disp = c_val
                    elif c_val is not None and c_prov == FactStatus.INFERRED.value:
                        c_fixed = False
                        c_fill = CellFill.INFERRED
                        c_disp = c_val
                    else:
                        c_fixed = False
                        c_fill = CellFill.RED
                        c_disp = "?"
                        c_val = None
                        if c_prov not in ("REJECTED", "UNKNOWN"):
                            c_prov = "UNKNOWN"

                part1_cells.append(ReconstructionCell(
                    bit_index=b_i,
                    canonical_pos=b_i + 1,
                    segment="part1",
                    unit_index=u_idx,
                    node_id=n_id,
                    node_label=n_lbl,
                    cs_step=cs_s,
                    cs_label=cs_lbl,
                    field_name=f_name,
                    field_bit_offset=f_off,
                    value=c_val,
                    display_char=c_disp,
                    is_fixed=c_fixed,
                    fill=c_fill,
                    provenance=c_prov,
                    source=c_src,
                ))

            # Build Part 2 cells (108 bits)
            if workflow == "secured_design_encoding" and pair_candidates:
                for p in pair_candidates:
                    p_i = p.pair_index
                    for off in range(4):
                        bit_in_r5 = (p_i - 1) * 4 + off
                        canon_p = eff_p1_len + bit_in_r5 + 1
                        if p.is_fixed and "?" not in p.four_bit_code:
                            cell_char = p.four_bit_code[off]
                            part2_cells.append(ReconstructionCell(
                                bit_index=bit_in_r5,
                                canonical_pos=canon_p,
                                segment="part2",
                                unit_index=p_i,
                                node_label=f"P{p_i}",
                                field_name="REG" if off < 2 else "VAR",
                                field_bit_offset=off if off < 2 else off - 2,
                                value=cell_char,
                                display_char=cell_char,
                                is_fixed=True,
                                fill=CellFill.GREEN,
                                provenance=p.provenance,
                                source=f"Pair {p_i} ({p.variable_name} -> {p.register_name or 'Parity'}) [{p.provenance}]",
                            ))
                        else:
                            part2_cells.append(ReconstructionCell(
                                bit_index=bit_in_r5,
                                canonical_pos=canon_p,
                                segment="part2",
                                unit_index=p_i,
                                node_label=f"P{p_i}",
                                field_name="REG" if off < 2 else "VAR",
                                field_bit_offset=off if off < 2 else off - 2,
                                value=None,
                                display_char="?",
                                is_fixed=False,
                                fill=CellFill.RED if recon_stage not in (ReconstructionStage.STAGE_A, ReconstructionStage.STAGE_B) else CellFill.NEUTRAL,
                                provenance="UNKNOWN",
                                source=f"Pair {p_i} ({p.variable_name}) unfixed",
                            ))
            else:
                for b_i in range(eff_p2_len):
                    part2_cells.append(ReconstructionCell(
                        bit_index=b_i,
                        canonical_pos=eff_p1_len + b_i + 1,
                        segment="part2",
                        value=None,
                        display_char="?",
                        is_fixed=False,
                        fill=CellFill.RED,
                        provenance="UNKNOWN",
                        source="Part 2 Rule 5 segment (unsecured interrogation pending implementation)",
                    ))

            entire_cells = list(part1_cells) + list(part2_cells)

        # Compute Provisional Pool
        fixed_p1_zeros = sum(1 for c in part1_cells if c.is_fixed and c.value == "0")
        fixed_p1_ones = sum(1 for c in part1_cells if c.is_fixed and c.value == "1")
        fixed_p2_zeros = sum(1 for c in part2_cells if c.is_fixed and c.value == "0")
        fixed_p2_ones = sum(1 for c in part2_cells if c.is_fixed and c.value == "1")

        tot_fixed_zeros = fixed_p1_zeros + fixed_p2_zeros
        tot_fixed_ones = fixed_p1_ones + fixed_p2_ones

        if workflow == "secured_design_encoding":
            if total_zeros is not None and total_bits is not None:
                tot_expected_zeros = total_zeros
                tot_expected_ones = total_bits - total_zeros
            elif part1_zeros is not None:
                p2_z = facts.get("part2_zeros", {}).get("val", 80)
                p2_o = facts.get("part2_ones", {}).get("val", 28)
                p1_o = facts.get("part1_ones", {}).get("val", 67)
                tot_expected_zeros = part1_zeros + p2_z
                tot_expected_ones = p1_o + p2_o
            else:
                tot_expected_zeros = 0
                tot_expected_ones = 0
        else:
            if part1_zeros is not None:
                tot_expected_zeros = part1_zeros
                tot_expected_ones = facts.get("part1_ones", {}).get("val", 67)
            elif total_zeros is not None:
                tot_expected_zeros = total_zeros
                tot_expected_ones = facts.get("total_ones", {}).get("val", 0)
            else:
                tot_expected_zeros = 0
                tot_expected_ones = 0

        unfixed_zeros = max(0, tot_expected_zeros - tot_fixed_zeros)
        unfixed_ones = max(0, tot_expected_ones - tot_fixed_ones)
        total_unfixed = unfixed_zeros + unfixed_ones

        # Distribute remaining unplaced zeros and ones directly into the unfixed cells (Requirement A)
        if recon_stage not in (ReconstructionStage.STAGE_A, ReconstructionStage.STAGE_B):
            if parts_divided == "no":
                tot_exp_z = total_zeros if total_zeros is not None else 0
                tot_exp_o = (total_bits - total_zeros) if (total_bits is not None and total_zeros is not None) else 0
                rem_z = max(0, tot_exp_z - fixed_p1_zeros)
                rem_o = max(0, tot_exp_o - fixed_p1_ones)
                for c in part1_cells:
                    if not c.is_fixed and c.fill != CellFill.INFERRED and c.provenance != "REJECTED":
                        if rem_z > 0:
                            c.display_char = "0"
                            c.value = "0"
                            c.fill = CellFill.RED
                            c.provenance = "POPULATION_UNPLACED"
                            c.source = "Monolithic stream aggregate population (0); canonical position unfixed"
                            rem_z -= 1
                        elif rem_o > 0:
                            c.display_char = "1"
                            c.value = "1"
                            c.fill = CellFill.RED
                            c.provenance = "POPULATION_UNPLACED"
                            c.source = "Monolithic stream aggregate population (1); canonical position unfixed"
                            rem_o -= 1
                        else:
                            c.display_char = "?"
                            c.value = None
                            c.fill = CellFill.NEUTRAL
                            c.provenance = "UNKNOWN"
                entire_cells = list(part1_cells)
            else:
                # 1. Distribute unplaced values for Part 1
                tot_p1_exp_z = part1_zeros if part1_zeros is not None else (76 if workflow == "secured_design_encoding" else (total_zeros or 0))
                tot_p1_exp_o = (eff_p1_len - tot_p1_exp_z) if (tot_p1_exp_z and eff_p1_len >= tot_p1_exp_z) else 0
                rem_p1_z = max(0, tot_p1_exp_z - fixed_p1_zeros)
                rem_p1_o = max(0, tot_p1_exp_o - fixed_p1_ones)
                for c in part1_cells:
                    if not c.is_fixed and c.fill != CellFill.INFERRED and c.provenance != "REJECTED":
                        if rem_p1_z > 0:
                            c.display_char = "0"
                            c.value = "0"
                            c.fill = CellFill.RED
                            c.provenance = "POPULATION_UNPLACED"
                            c.source = "Part 1 aggregate population (0); canonical position unfixed"
                            rem_p1_z -= 1
                        elif rem_p1_o > 0:
                            c.display_char = "1"
                            c.value = "1"
                            c.fill = CellFill.RED
                            c.provenance = "POPULATION_UNPLACED"
                            c.source = "Part 1 aggregate population (1); canonical position unfixed"
                            rem_p1_o -= 1
                        else:
                            c.display_char = "?"
                            c.value = None
                            c.fill = CellFill.NEUTRAL
                            c.provenance = "UNKNOWN"

                # 2. Distribute unplaced values for Part 2
                is_r5_active = (workflow == "secured_design_encoding" and r5_applicable != "no" and (facts.get("part2_zeros") is not None or recon_stage.value in ("STAGE_S2", "STAGE_S3", "STAGE_S4", "STAGE_COMPLETE")))
                if is_r5_active:
                    tot_p2_exp_z = 80
                    tot_p2_exp_o = 28
                    rem_p2_z = max(0, tot_p2_exp_z - fixed_p2_zeros)
                    rem_p2_o = max(0, tot_p2_exp_o - fixed_p2_ones)
                    for c in part2_cells:
                        if not c.is_fixed:
                            if rem_p2_z > 0:
                                c.display_char = "0"
                                c.value = "0"
                                c.fill = CellFill.RED
                                c.provenance = "POPULATION_UNPLACED"
                                c.source = "Rule 5 aggregate population (0); canonical position unfixed"
                                rem_p2_z -= 1
                            elif rem_p2_o > 0:
                                c.display_char = "1"
                                c.value = "1"
                                c.fill = CellFill.RED
                                c.provenance = "POPULATION_UNPLACED"
                                c.source = "Rule 5 aggregate population (1); canonical position unfixed"
                                rem_p2_o -= 1
                            else:
                                c.display_char = "?"
                                c.value = None
                                c.fill = CellFill.NEUTRAL
                                c.provenance = "UNKNOWN"
                else:
                    for c in part2_cells:
                        c.display_char = "?"
                        c.value = None
                        c.fill = CellFill.NEUTRAL
                        c.provenance = "UNKNOWN"

                # 3. For Entire view
                if recon_stage == ReconstructionStage.STAGE_C:
                    curr_tot_z = unfixed_zeros
                    curr_tot_o = unfixed_ones
                    for c in entire_cells:
                        if curr_tot_z > 0:
                            c.display_char = "0"
                            c.value = "0"
                            c.fill = CellFill.RED
                            c.provenance = "POPULATION_UNPLACED"
                            c.source = "Aggregate population confirmed (0); canonical position unfixed"
                            curr_tot_z -= 1
                        elif curr_tot_o > 0:
                            c.display_char = "1"
                            c.value = "1"
                            c.fill = CellFill.RED
                            c.provenance = "POPULATION_UNPLACED"
                            c.source = "Aggregate population confirmed (1); canonical position unfixed"
                            curr_tot_o -= 1
                        else:
                            c.display_char = "?"
                            c.value = None
                            c.fill = CellFill.NEUTRAL
                            c.provenance = "UNKNOWN"
                else:
                    entire_cells = list(part1_cells) + list(part2_cells)

        # Compute Candidate Space State
        if entire_cells and not part1_cells:
            scope_cells = entire_cells
        else:
            scope_cells = (part1_cells + part2_cells) if (workflow == "secured_design_encoding" and r5_applicable != "no") else part1_cells
        obs_count = sum(1 for c in scope_cells if c.is_fixed and c.provenance == "OBSERVED")
        der_count = sum(1 for c in scope_cells if c.is_fixed and c.provenance == "DERIVED")
        inf_count = sum(1 for c in scope_cells if c.is_fixed and c.provenance == "INFERRED")
        scope_total = len(scope_cells) if scope_cells else (total_bits or 0)
        scope_unfixed = sum(1 for c in scope_cells if not c.is_fixed)

        candidate_space = ConstraintModel.compute_candidate_space(
            total_bits=scope_total,
            total_ones=tot_expected_ones if (tot_expected_ones or tot_expected_zeros) else None,
            total_zeros=tot_expected_zeros if (tot_expected_ones or tot_expected_zeros) else None,
            fixed_ones=tot_fixed_ones,
            fixed_zeros=tot_fixed_zeros,
            total_unfixed=scope_unfixed,
            contradictions=contradictions,
            observed_count=obs_count,
            derived_count=der_count,
            inferred_count=inf_count,
        )

        reconstruction_state = {
            "stage": recon_stage.value,
            "stage_title": recon_title,
            "stage_description": recon_desc,
            "total_length": total_bits,
            "total_zeros": total_zeros,
            "total_ones": facts.get("total_ones", {}).get("val"),
            "parts_count": parts_count,
            "candidate_space": candidate_space.model_dump(),
            "branch_info": {
                "parts_divided": parts_divided,
                "parts_count": parts_count,
                "parts_equal": parts_equal_length,
                "has_units": has_units,
                "num_units": num_units,
                "equal_units": unit_uniform,
                "has_fields": has_fields,
                "fields_per_unit": fields_per_unit,
                "layout_uniform": layout_uniform,
                "fields_equal_width": fields_equal_width,
                "r5_applicable": r5_applicable,
                "unsupported_branch_reason": unsupported_branch_reason,
                "incomplete_reason": incomplete_reason,
            },
            "segments": {
                "part1": {
                    "name": "Complete Stream" if parts_divided == "no" else "Part 1",
                    "length": part1_len,
                    "zeros": part1_zeros,
                    "ones": facts.get("part1_ones", {}).get("val") or (facts.get("total_ones", {}).get("val") if parts_divided == "no" else None),
                    "is_established": (part1_len is not None),
                },
                "part2": {
                    "name": "Part 2",
                    "length": (facts.get("r5_total_bits", {}).get("val") or facts.get("part2_len", {}).get("val")) if (parts_divided != "no" and r5_applicable != "no") else 0,
                    "zeros": (facts.get("r5_zeros", {}).get("val") or facts.get("part2_zeros", {}).get("val")) if (parts_divided != "no" and r5_applicable != "no") else 0,
                    "ones": (facts.get("r5_ones", {}).get("val") or facts.get("part2_ones", {}).get("val")) if (parts_divided != "no" and r5_applicable != "no") else 0,
                    "is_established": bool(("r5_total_bits" in facts or "part2_len" in facts) and parts_divided != "no" and r5_applicable != "no"),
                },
            },
            "units_established": units_established,
            "unit_count": num_units,
            "unit_length": unit_len,
            "fields_established": fields_established,
            "field_widths": {
                "A": f_a_len,
                "B": f_b_len,
                "C": f_c_len,
                "D": f_d_len,
            } if fields_established else None,
            "provisional_pool": {
                "total_unfixed": total_unfixed,
                "unfixed_zeros": unfixed_zeros,
                "unfixed_ones": unfixed_ones,
                "fixed_zeros": tot_fixed_zeros,
                "fixed_ones": tot_fixed_ones,
            },
            "active_segment": "entire" if parts_divided == "no" else "part1",
            "part1_cells": [c.model_dump() for c in part1_cells],
            "part2_cells": [c.model_dump() for c in part2_cells],
            "entire_cells": [c.model_dump() for c in entire_cells],
        }

        # ------------------------------------------------------------------
        # 11. Session Outcome Determination & Commitment Verification
        # ------------------------------------------------------------------
        comm_status = "PENDING"
        comm_detail = "Stage S4 commitment verification pending."
        assembled_251 = ""

        if contradictions:
            outcome = "CONTRADICTION"
        elif unsupported_branch_reason:
            outcome = "UNSUPPORTED_BRANCH"
        elif incomplete_reason:
            outcome = f"INCOMPLETE: {incomplete_reason}"
        elif parts_divided == "no":
            outcome = "IN PROGRESS (Monolithic Single-Stream Branch)"
        elif workflow == "secured_design_encoding":
            if r5_applicable == "no":
                if is_complete_143:
                    outcome = "COMPLETE (Four-Rule Only; Rule 5 Not Applicable)"
                else:
                    outcome = "IN PROGRESS (Four-Rule Only; Rule 5 Not Applicable)"
            elif not is_complete_143:
                outcome = "IN PROGRESS (Stage S1: 143-Bit Four-Rule)"
            elif not is_complete_rule5:
                outcome = "IN PROGRESS (Stage S2: 108-Bit Rule 5)"
            else:
                assembled_251 = f"{reconstructed_str}{r5_reconstructed_str}"
                # Stage S4 commitment check
                if stored_c_es:
                    pe = PedersenEngine()
                    try:
                        blinding_int = int(opening_factor_r_es, 16) if isinstance(opening_factor_r_es, str) else int(opening_factor_r_es) if opening_factor_r_es is not None else None
                        if blinding_int is not None:
                            ver_res = pe.verify(assembled_251, stored_c_es, blinding_int)
                            if ver_res == CommitmentVerificationStatus.VALID:
                                comm_status = "VERIFIED"
                                comm_detail = "Secured 251-bit design encoding commitment C_ES verified against recorded canonical hash (MATCH)."
                                recon_stage = ReconstructionStage.STAGE_I
                                recon_title = "Stage S4: Secured Design-Encoding Commitment Verified"
                                recon_desc = "Cryptographic Pedersen commitment C_ES matches reconstructed 251-bit candidate bitstream."
                                reconstruction_state["stage"] = recon_stage.value
                                reconstruction_state["stage_title"] = recon_title
                                reconstruction_state["stage_description"] = recon_desc
                                outcome = "COMPLETE"
                            else:
                                comm_status = "COMMITMENT_MISMATCH"
                                comm_detail = "Recalculated commitment for assembled 251-bit candidate does not match stored commitment C_ES (MISMATCH)."
                                recon_stage = ReconstructionStage.STAGE_I
                                recon_title = "Stage S4: Commitment Mismatch"
                                recon_desc = "Cryptographic check failed: candidate 251-bit bitstream does not open commitment C_ES."
                                reconstruction_state["stage"] = recon_stage.value
                                reconstruction_state["stage_title"] = recon_title
                                reconstruction_state["stage_description"] = recon_desc
                                outcome = "COMMITMENT_MISMATCH"
                        else:
                            outcome = "INCOMPLETE: 251-bit candidate assembled; opening factor pending"
                    except Exception as e:
                        comm_status = "COMMITMENT_MISMATCH"
                        comm_detail = f"Commitment verification failed with error: {e}"
                        outcome = "COMMITMENT_MISMATCH"
                else:
                    outcome = "INCOMPLETE: 251-bit candidate assembled; commitment check pending"
        else:
            if is_complete_143:
                outcome = "INCOMPLETE: 143-bit stage complete; Rule 5 interrogation pending"
            else:
                outcome = "IN PROGRESS"

        recalced_ces = None
        if stored_c_es and opening_factor_r_es is not None and assembled_251:
            try:
                pe = PedersenEngine()
                bl_int = int(opening_factor_r_es, 16) if isinstance(opening_factor_r_es, str) else int(opening_factor_r_es)
                recalc_comm, _ = pe.commit(assembled_251, blinding_factor=bl_int)
                recalced_ces = recalc_comm.commitment_hex
            except Exception:
                pass

        stages = {
            "S1_143_RECONSTRUCTION": {
                "status": "COMPLETE" if is_complete_143 else ("CONTRADICTION" if contradictions else "IN_PROGRESS"),
                "bit_count": 143,
            },
            "S2_RULE5_INTERROGATION": {
                "status": "COMPLETE" if is_complete_rule5 else ("CONTRADICTION" if contradictions and not is_complete_143 else ("IN_PROGRESS" if is_complete_143 else "PENDING")),
                "bit_count": 108,
            },
            "S3_251_ASSEMBLY": {
                "status": "COMPLETE" if (is_complete_143 and is_complete_rule5) else "PENDING",
                "bit_count": 251,
            },
            "S4_COMMITMENT_VERIFICATION": {
                "status": comm_status,
                "target_commitment": stored_c_es,
            },
        } if workflow == "secured_design_encoding" else {
            "U1_143_RECONSTRUCTION": {
                "status": "COMPLETE" if is_complete_143 else ("CONTRADICTION" if contradictions else "IN_PROGRESS"),
                "bit_count": 143,
            },
            "U2_UNSECURED_RULE5_PENDING": {
                "status": "PENDING",
                "detail": "Unsecured Rule 5 interrogation deliberately partial/pending.",
            },
        }

        if workflow == "secured_design_encoding" and r5_applicable == "no":
            stages["S2_RULE5_INTERROGATION"] = {
                "status": "NOT_APPLICABLE",
                "detail": "Rule 5 structure marked not applicable by claimant.",
            }
            stages["S3_251_ASSEMBLY"] = {
                "status": "NOT_APPLICABLE",
                "detail": "251-bit assembly not applicable for single 143-bit candidate.",
            }
            stages["S4_COMMITMENT_VERIFICATION"] = {
                "status": "NOT_APPLICABLE",
                "detail": "Commitment verification for 251-bit secured stream not applicable.",
            }

        return {
            "outcome": outcome,
            "contradictions": contradictions,
            "facts": facts,
            "retracted_facts": retracted_facts,
            "soft_hypotheses": soft_hypotheses,
            "p1_failed": p1_failed,
            "unit_candidates": [u.model_dump() for u in unit_candidates],
            "pair_candidates": [p.model_dump() for p in pair_candidates] if workflow == "secured_design_encoding" else [],
            "reconstructed_bitstream": assembled_251 if (workflow == "secured_design_encoding" and assembled_251 and "?" not in assembled_251) else reconstructed_str,
            "reconstructed_part1_143": reconstructed_str,
            "reconstructed_part2_108": r5_reconstructed_str if workflow == "secured_design_encoding" else "",
            "rule5_reconstructed_bitstream": r5_reconstructed_str if workflow == "secured_design_encoding" else "",
            "assembled_251_bitstream": assembled_251 if workflow == "secured_design_encoding" else "",
            "bit_provenance": [bp.model_dump() for bp in bit_provenance_list],
            "bit_statistics": bit_stats,
            "is_complete_143": is_complete_143,
            "is_complete_rule5": is_complete_rule5,
            "is_complete_251": bool(assembled_251 and "?" not in assembled_251 and len(assembled_251) == 251),
            "commitment_verification": {
                "status": comm_status,
                "detail": comm_detail,
                "target_commitment": stored_c_es,
                "recalculated_commitment": recalced_ces,
            } if workflow == "secured_design_encoding" else None,
            "stages": stages,
            "reconstruction_state": reconstruction_state,
            "candidate_space": candidate_space.model_dump(),
            "branch_info": reconstruction_state["branch_info"],
            "unsupported_branch_reason": unsupported_branch_reason,
            "incomplete_reason": incomplete_reason,
        }

