"""
Deterministic Structural Design Encoder (V1 Prototype).

Encodes a scheduled Data-Flow Graph (DFG) according to the four rules
specified in 'design encoded data.docx':

Rule 1:
    Control step parity and node-count parity in that control step:
    Even = "00", Odd = "01".
    Format: [CS Parity (2 bits)] [Node Count Parity (2 bits)] -> 4 bits total.

Rule 2:
    Encode each design node using ceil(log2(n)) bits, where n is the total
    number of nodes in the design.

Rule 3:
    Encode operation type:
    multiplier = '1'
    adder = '0'

Rule 4:
    Encode total number of nodes in that control step in binary.
    In the golden specification: 1 node -> "01", 2 nodes -> "10", 3 nodes -> "11".

Final Watermark per node = Rule 1 + Rule 2 + Rule 3 + Rule 4.

Invariant:
    - This is NOT the transaction watermark (W_256).
    - It does NOT include register allocation or CIG constraints.
    - Scope selection does NOT redefine n or node_width.
    - Supports Level 1 (exact) and Level 2 (component/rule-level) comparisons.
    - Level 3 is intentionally not implemented.
"""

from typing import Dict, List, Tuple, Optional, Any, Set
import math
import hashlib
import re

from .dfg import DFG, DFGNode
from .scheduler import ScheduledDFG


class NodeEncodingRecord:
    """
    Structured encoding record for a single design node within a control step.
    Preserves all 4 individual rule components.
    """

    def __init__(
        self,
        step_index: int,
        step_name: str,
        step_number: int,
        node_id: int,
        op_type: str,
        rule1: str,
        rule2: str,
        rule3: str,
        rule4: str,
    ):
        self.step_index = step_index
        self.step_name = step_name
        self.step_number = step_number
        self.node_id = node_id
        self.op_type = op_type
        self.rule1 = rule1
        self.rule2 = rule2
        self.rule3 = rule3
        self.rule4 = rule4
        self.bitstream = f"{rule1}{rule2}{rule3}{rule4}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_index": self.step_index,
            "step_name": self.step_name,
            "step_number": self.step_number,
            "node_id": self.node_id,
            "op_type": self.op_type,
            "rule1": self.rule1,
            "rule2": self.rule2,
            "rule3": self.rule3,
            "rule4": self.rule4,
            "bitstream": self.bitstream,
            "formatted": f"{self.rule1} | {self.rule2} | {self.rule3} | {self.rule4}",
        }


class StepEncodingGroup:
    """
    Group of encoded node records belonging to a single control step.
    """

    def __init__(
        self,
        step_index: int,
        step_name: str,
        step_number: int,
        node_count: int,
        cs_parity_code: str,
        count_parity_code: str,
        rule1: str,
        rule4: str,
        nodes: List[NodeEncodingRecord],
    ):
        self.step_index = step_index
        self.step_name = step_name
        self.step_number = step_number
        self.node_count = node_count
        self.cs_parity_code = cs_parity_code
        self.count_parity_code = count_parity_code
        self.rule1 = rule1
        self.rule4 = rule4
        self.nodes = list(nodes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_index": self.step_index,
            "step_name": self.step_name,
            "step_number": self.step_number,
            "node_count": self.node_count,
            "cs_parity_code": self.cs_parity_code,
            "count_parity_code": self.count_parity_code,
            "rule1": self.rule1,
            "rule4": self.rule4,
            "nodes": [n.to_dict() for n in self.nodes],
        }


class StructuralEncodingResult:
    """
    Complete structural encoding evidence container for a hardware design.
    """

    def __init__(
        self,
        design_name: str,
        total_design_nodes: int,
        node_width: int,
        total_steps: int,
        selected_scope: List[int],
        rule4_width: int,
        records: List[NodeEncodingRecord],
        step_groups: List[StepEncodingGroup],
        encoding_version: str = "structural-v1",
        commitment_hex: Optional[str] = None,
        blinding_factor_hex: Optional[str] = None,
    ):
        self.design_name = design_name
        self.encoding_version = encoding_version
        self.total_design_nodes = total_design_nodes
        self.node_width = node_width
        self.total_steps = total_steps
        self.selected_scope = sorted(list(selected_scope))
        self.rule4_width = rule4_width
        self.records = records
        self.step_groups = step_groups
        self.canonical_bitstream = "".join(r.bitstream for r in records)
        self.canonical_sha256 = hashlib.sha256(self.canonical_bitstream.encode("utf-8")).hexdigest()
        self.commitment_hex = commitment_hex
        self.blinding_factor_hex = blinding_factor_hex

    def to_dict(self) -> Dict[str, Any]:
        return {
            "design_name": self.design_name,
            "encoding_version": self.encoding_version,
            "total_design_nodes": self.total_design_nodes,
            "node_width": self.node_width,
            "total_steps": self.total_steps,
            "selected_scope": self.selected_scope,
            "scope_steps_count": len(self.selected_scope),
            "rule4_width": self.rule4_width,
            "total_encoded_nodes": len(self.records),
            "total_bit_length": len(self.canonical_bitstream),
            "canonical_bitstream": self.canonical_bitstream,
            "canonical_sha256": self.canonical_sha256,
            "commitment_hex": self.commitment_hex,
            "blinding_factor_hex": self.blinding_factor_hex,
            "step_groups": [g.to_dict() for g in self.step_groups],
            "records": [r.to_dict() for r in self.records],
        }


class DesignStructuralEncoder:
    """
    Deterministic structural encoder and Level 1 / Level 2 comparative verifier.
    """

    ENCODING_VERSION = "structural-v1"
    PARITY_EVEN = "00"
    PARITY_ODD = "01"

    @classmethod
    def encode_rule1(cls, step_number: int, node_count: int) -> Tuple[str, str, str]:
        """
        Rule 1: Control step parity (Odd="01", Even="00") and node count parity (Odd="01", Even="00").
        Step numbering is 1-based (T1, T2...).
        Returns (cs_parity_code, count_parity_code, rule1_combined_4bits).
        """
        cs_code = cls.PARITY_ODD if (step_number % 2 != 0) else cls.PARITY_EVEN
        cnt_code = cls.PARITY_ODD if (node_count % 2 != 0) else cls.PARITY_EVEN
        return cs_code, cnt_code, f"{cs_code}{cnt_code}"

    @classmethod
    def encode_rule2(
        cls,
        node_id: int,
        node_width: int,
        use_document_table_quirks: bool = False,
    ) -> str:
        """
        Rule 2: Each design node encoded in ceil(log2(n)) bits.
        If use_document_table_quirks is True, maps node 7 to '1011' and node 11 to '0111'
        to reproduce the literal printed Word document table page 3.
        Otherwise standard binary format: e.g. 7 -> '0111', 11 -> '1011'.
        """
        if use_document_table_quirks:
            if node_id == 7 and node_width == 4:
                return "1011"
            if node_id == 11 and node_width == 4:
                return "0111"
        return format(node_id, f"0{node_width}b")

    @classmethod
    def encode_rule3(cls, op_type: str, allow_sub_as_adder: bool = False) -> str:
        """
        Rule 3: Multiplier = '1', Adder = '0'.
        If allow_sub_as_adder is True, treats 'sub' as '0' (as in the document's IIR Butterworth table).
        Otherwise, unsupported operations raise ValueError.
        """
        op = str(op_type).strip().lower()
        if op in ("mul", "multiplier", "mult", "*", "1"):
            return "1"
        if op in ("add", "adder", "+", "0"):
            return "0"
        if allow_sub_as_adder and op in ("sub", "subtractor", "-"):
            return "0"
        raise ValueError(
            f"Unsupported operation type '{op_type}'. "
            f"Rule 3 explicitly defines only multiplier='1' and adder='0'."
        )

    @classmethod
    def encode_rule4(cls, node_count: int, rule4_width: int = 2) -> str:
        """
        Rule 4: Total number of nodes scheduled in the current control step in binary.
        Formatted with rule4_width bits (default 2 bits: 1 -> '01', 2 -> '10', 3 -> '11').
        """
        return format(node_count, f"0{rule4_width}b")

    @classmethod
    def encode_scheduled_dfg(
        cls,
        scheduled_dfg: ScheduledDFG,
        scope_control_steps: Optional[List[int]] = None,
        rule4_width: Optional[int] = None,
        use_document_table_quirks: bool = False,
        allow_sub_as_adder: bool = False,
    ) -> StructuralEncodingResult:
        """
        Encodes a scheduled DFG adhering to the 4 documented rules.
        scope_control_steps: List of 1-based control step numbers to include (e.g. [1, 2, 3...]).
                             If None, includes all scheduled control steps.
        """
        dfg = scheduled_dfg.dfg
        total_nodes = len(dfg.nodes)
        if total_nodes == 0:
            raise ValueError("Cannot structurally encode an empty design with 0 nodes.")

        # Rule 2 width is based on total design nodes n
        node_width = max(1, math.ceil(math.log2(total_nodes)))

        # Determine scheduled steps
        total_steps = scheduled_dfg.total_steps
        all_step_numbers = list(range(1, total_steps + 1))

        if scope_control_steps is None:
            selected_scope = list(all_step_numbers)
        else:
            selected_scope = sorted(list(set(scope_control_steps)))
            for s_num in selected_scope:
                if s_num < 1 or s_num > total_steps:
                    raise ValueError(
                        f"Invalid control step {s_num} in encoding scope. "
                        f"Design has steps 1 to {total_steps}."
                    )

        # Determine Rule 4 width:
        # In the golden example, max count is 3 and formatted with 2 bits.
        # If any step has count > 3, scale rule4_width accordingly.
        max_nodes_in_any_step = max(
            (len(scheduled_dfg.step_nodes.get(s, [])) for s in range(total_steps)),
            default=1,
        )
        if rule4_width is None:
            calc_w = max(2, math.ceil(math.log2(max_nodes_in_any_step + 1))) if max_nodes_in_any_step > 0 else 2
            eff_rule4_width = max(2, calc_w)
        else:
            eff_rule4_width = max(2, rule4_width)

        records: List[NodeEncodingRecord] = []
        step_groups: List[StepEncodingGroup] = []

        for step_idx in range(total_steps):
            step_num = step_idx + 1
            if step_num not in selected_scope:
                continue

            node_ids = scheduled_dfg.step_nodes.get(step_idx, [])
            node_count = len(node_ids)
            step_name = f"T{step_num}"

            cs_code, cnt_code, rule1 = cls.encode_rule1(step_num, node_count)
            rule4 = cls.encode_rule4(node_count, eff_rule4_width)

            step_records: List[NodeEncodingRecord] = []
            for nid in node_ids:
                node = dfg._node_map.get(nid)
                if node is None:
                    raise ValueError(f"Node ID {nid} not found in DFG node map.")

                rule2 = cls.encode_rule2(nid, node_width, use_document_table_quirks)
                rule3 = cls.encode_rule3(node.op_type, allow_sub_as_adder)

                rec = NodeEncodingRecord(
                    step_index=step_idx,
                    step_name=step_name,
                    step_number=step_num,
                    node_id=nid,
                    op_type=node.op_type,
                    rule1=rule1,
                    rule2=rule2,
                    rule3=rule3,
                    rule4=rule4,
                )
                step_records.append(rec)
                records.append(rec)

            group = StepEncodingGroup(
                step_index=step_idx,
                step_name=step_name,
                step_number=step_num,
                node_count=node_count,
                cs_parity_code=cs_code,
                count_parity_code=cnt_code,
                rule1=rule1,
                rule4=rule4,
                nodes=step_records,
            )
            step_groups.append(group)

        return StructuralEncodingResult(
            design_name=dfg.name,
            total_design_nodes=total_nodes,
            node_width=node_width,
            total_steps=total_steps,
            selected_scope=selected_scope,
            rule4_width=eff_rule4_width,
            records=records,
            step_groups=step_groups,
            encoding_version=cls.ENCODING_VERSION,
        )

    @classmethod
    def encode_golden_butterworth(
        cls,
        use_document_table_quirks: bool = False,
        scope_control_steps: Optional[List[int]] = None,
    ) -> StructuralEncodingResult:
        """
        Creates and encodes the documented 13-node, 7-control-step IIR Butterworth filter benchmark.
        Schedule:
            T1: node 1 (mul), node 2 (mul)
            T2: node 8 (add), node 3 (mul), node 4 (mul)
            T3: node 9 (add), node 5 (mul), node 6 (mul)
            T4: node 10 (add), node 7 (mul)
            T5: node 11 (add)
            T6: node 12 (add)
            T7: node 13 (add)
        """
        nodes = [
            DFGNode(1, "mul", ["in1", "c1"], "t1"),
            DFGNode(2, "mul", ["in2", "c2"], "t2"),
            DFGNode(3, "mul", ["in3", "c3"], "t3"),
            DFGNode(4, "mul", ["in4", "c4"], "t4"),
            DFGNode(5, "mul", ["in5", "c5"], "t5"),
            DFGNode(6, "mul", ["in6", "c6"], "t6"),
            DFGNode(7, "mul", ["in7", "c7"], "t7"),
            DFGNode(8, "add", ["t1", "t2"], "t8"),
            DFGNode(9, "add", ["t8", "t3"], "t9"),
            DFGNode(10, "add", ["t9", "t4"], "t10"),
            DFGNode(11, "add", ["t10", "t5"], "t11"),
            DFGNode(12, "add", ["t11", "t6"], "t12"),
            DFGNode(13, "add", ["t12", "t7"], "out_bw"),
        ]
        dfg = DFG(
            name="iir_butterworth_filter",
            inputs=[f"in{i}" for i in range(1, 8)] + [f"c{i}" for i in range(1, 8)],
            outputs=["out_bw"],
            nodes=nodes,
        )
        # Explicit schedule mapping matching page-3 table:
        # T1 (step 0): [1, 2]
        # T2 (step 1): [8, 3, 4]
        # T3 (step 2): [9, 5, 6]
        # T4 (step 3): [10, 7]
        # T5 (step 4): [11]
        # T6 (step 5): [12]
        # T7 (step 6): [13]
        node_step = {
            1: 0, 2: 0,
            8: 1, 3: 1, 4: 1,
            9: 2, 5: 2, 6: 2,
            10: 3, 7: 3,
            11: 4,
            12: 5,
            13: 6,
        }
        sched_dfg = ScheduledDFG(
            dfg=dfg,
            node_step=node_step,
            total_steps=7,
            resource_config={"mul": 2, "add": 1},
        )
        # Ensure step_nodes preserves the document's exact node ordering in each step:
        sched_dfg.step_nodes = {
            0: [1, 2],
            1: [8, 3, 4],
            2: [9, 5, 6],
            3: [10, 7],
            4: [11],
            5: [12],
            6: [13],
        }
        return cls.encode_scheduled_dfg(
            sched_dfg,
            scope_control_steps=scope_control_steps,
            rule4_width=2,
            use_document_table_quirks=use_document_table_quirks,
            allow_sub_as_adder=True,
        )

    @classmethod
    def parse_scheduled_nodes_from_verilog(cls, verilog_code: str) -> Optional[Dict[str, Any]]:
        """
        Recovers scheduled control steps and node operation assignments directly
        from standard synthesizable Verilog modules generated by this framework.
        Supports:
        - FSM state headers: STATE_STEP_<n>, STATE_<n>, STEP_<n>
        - Scheduled node comments: // node <n>, /* node <n> */, // node_<n>
        - Dataflow assignments in control steps
        Returns a dict with 'node_step', 'step_nodes', 'node_ops', 'total_steps', and 'diagnostics', or None.
        """
        parsed, _ = cls.parse_scheduled_nodes_with_diagnostics(verilog_code)
        return parsed

    @classmethod
    def parse_scheduled_nodes_with_diagnostics(
        cls, verilog_code: str
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        """
        Parses scheduled control steps and operations with explicit failure diagnostics.
        """
        step_nodes: Dict[int, List[int]] = {}
        node_step: Dict[int, int] = {}
        node_ops: Dict[int, str] = {}
        current_step: Optional[int] = None

        lines = verilog_code.splitlines()
        has_states = False

        for line in lines:
            line_str = line.strip()
            # Match state header: STATE_STEP_0:, STATE_0:, STEP_0:, etc.
            m_state = re.match(r"(?:STATE_STEP_|STATE_|STEP_)(\d+)\s*:", line_str, re.IGNORECASE)
            if m_state:
                current_step = int(m_state.group(1))
                if current_step not in step_nodes:
                    step_nodes[current_step] = []
                has_states = True
                continue

            if current_step is not None:
                if line_str.startswith("STATE_DONE") or line_str.startswith("default:"):
                    current_step = None
                    continue

                # Match node comment: e.g. R1 <= R0 + R2; // node 5 (v8) or /* node 5 */
                m_node = re.search(r"(?://|/\*)\s*(?:node[_\s]+|\(node\s+)(\d+)", line_str, re.IGNORECASE)
                if m_node and "<=" in line_str:
                    nid = int(m_node.group(1))
                    if nid not in step_nodes[current_step]:
                        step_nodes[current_step].append(nid)
                    node_step[nid] = current_step

                    # Identify operation type
                    lhs_rhs = line_str.split("//")[0].split("/*")[0]
                    if "+" in lhs_rhs:
                        node_ops[nid] = "add"
                    elif "*" in lhs_rhs:
                        node_ops[nid] = "mul"
                    elif "-" in lhs_rhs:
                        node_ops[nid] = "sub"
                    elif "^" in lhs_rhs:
                        node_ops[nid] = "xor"
                    else:
                        node_ops[nid] = "add"

        diagnostics = {
            "has_states": has_states,
            "detected_steps": len(step_nodes),
            "recovered_nodes": len(node_step),
            "missing_node_annotations": (has_states and not node_step),
            "supported_subset": (
                "Synthesizable Verilog subset featuring FSM state headers (STATE_STEP_<n>) "
                "and scheduled operation node annotations (// node <n>)"
            ),
        }

        if not has_states or not node_step:
            diagnostics["error"] = "Missing FSM state labels" if not has_states else "Missing scheduled node annotations"
            return None, diagnostics

        total_steps = max(step_nodes.keys()) + 1 if step_nodes else 0
        result = {
            "total_steps": total_steps,
            "step_nodes": step_nodes,
            "node_step": node_step,
            "node_ops": node_ops,
            "diagnostics": diagnostics,
        }
        return result, diagnostics

    # ==========================================================================
    # Verification: Level 1 (Exact) and Level 2 (Component-Level)
    # ==========================================================================

    @classmethod
    def compare_level1(
        cls,
        reference: StructuralEncodingResult,
        suspicious: StructuralEncodingResult,
    ) -> Dict[str, Any]:
        """
        Level 1 Comparison: Evaluates exact equality of the canonical structural encoding.
        Does NOT produce an ownership or infringement score.
        """
        ref_bits = reference.canonical_bitstream
        sus_bits = suspicious.canonical_bitstream
        ref_len = len(ref_bits)
        sus_len = len(sus_bits)

        is_exact_match = (ref_bits == sus_bits)
        min_len = min(ref_len, sus_len)
        max_len = max(ref_len, sus_len)

        matching_bits = sum(1 for i in range(min_len) if ref_bits[i] == sus_bits[i])
        differing_bits = (min_len - matching_bits) + (max_len - min_len)
        match_rate = (matching_bits / max_len) if max_len > 0 else 1.0

        scope_mismatch = (reference.selected_scope != suspicious.selected_scope)
        node_count_mismatch = (reference.total_design_nodes != suspicious.total_design_nodes)
        version_mismatch = (reference.encoding_version != suspicious.encoding_version)

        status = "MATCH" if is_exact_match else "MISMATCH"

        return {
            "level": 1,
            "comparison_type": "EXACT_CANONICAL_ENCODING",
            "status": status,
            "is_exact_match": is_exact_match,
            "reference_bit_length": ref_len,
            "suspicious_bit_length": sus_len,
            "matching_bits": matching_bits,
            "differing_bits": differing_bits,
            "match_rate": round(match_rate, 6),
            "match_percentage_str": f"{match_rate * 100:.2f}%",
            "scope_mismatch": scope_mismatch,
            "node_count_mismatch": node_count_mismatch,
            "version_mismatch": version_mismatch,
            "reference_sha256": reference.canonical_sha256,
            "suspicious_sha256": suspicious.canonical_sha256,
            "disclaimer": (
                "Level 1 structural evidence only. Factual mathematical comparison; "
                "does NOT claim legal ownership determination or infringement adjudication."
            ),
        }

    @classmethod
    def compare_level2(
        cls,
        reference: StructuralEncodingResult,
        suspicious: StructuralEncodingResult,
    ) -> Dict[str, Any]:
        """
        Level 2 Comparison: Rule- and component-level inspection.
        Analyzes individual components (Rule 1, Rule 2, Rule 3, Rule 4) grouped
        by control step and node.
        """
        ref_groups = {g.step_number: g for g in reference.step_groups}
        sus_groups = {g.step_number: g for g in suspicious.step_groups}

        all_steps = sorted(list(set(ref_groups.keys()).union(set(sus_groups.keys()))))

        total_rules_evaluated = 0
        matching_rules_count = 0
        differing_rules_count = 0

        step_comparisons: List[Dict[str, Any]] = []
        differences_only: List[Dict[str, Any]] = []

        for s_num in all_steps:
            r_grp = ref_groups.get(s_num)
            s_grp = sus_groups.get(s_num)

            step_name = f"T{s_num}"
            step_has_diff = False
            node_comparisons: List[Dict[str, Any]] = []

            if r_grp is None or s_grp is None:
                step_has_diff = True
                step_comparisons.append({
                    "step_number": s_num,
                    "step_name": step_name,
                    "status": "STEP_MISSING",
                    "reference_node_count": r_grp.node_count if r_grp else 0,
                    "suspicious_node_count": s_grp.node_count if s_grp else 0,
                    "nodes": [],
                    "difference_summary": f"Step {step_name} present in {'reference' if r_grp else 'suspicious'} only.",
                })
                differences_only.append({
                    "step_number": s_num,
                    "step_name": step_name,
                    "type": "STEP_PRESENCE_MISMATCH",
                    "details": f"Step {step_name} present in {'reference' if r_grp else 'suspicious'} only.",
                })
                continue

            # Compare nodes within this step
            r_nodes = {r.node_id: r for r in r_grp.nodes}
            s_nodes = {s.node_id: s for s in s_grp.nodes}
            all_nids = sorted(list(set(r_nodes.keys()).union(set(s_nodes.keys()))))

            for nid in all_nids:
                r_rec = r_nodes.get(nid)
                s_rec = s_nodes.get(nid)

                if r_rec is None or s_rec is None:
                    step_has_diff = True
                    differing_rules_count += 4
                    total_rules_evaluated += 4
                    node_diff_desc = f"Node {nid} present in {'reference' if r_rec else 'suspicious'} only"
                    node_comp = {
                        "node_id": nid,
                        "status": "NODE_MISSING",
                        "op_type": r_rec.op_type if r_rec else (s_rec.op_type if s_rec else "unknown"),
                        "rule1": {"match": False, "ref": r_rec.rule1 if r_rec else "N/A", "sus": s_rec.rule1 if s_rec else "N/A"},
                        "rule2": {"match": False, "ref": r_rec.rule2 if r_rec else "N/A", "sus": s_rec.rule2 if s_rec else "N/A"},
                        "rule3": {"match": False, "ref": r_rec.rule3 if r_rec else "N/A", "sus": s_rec.rule3 if s_rec else "N/A"},
                        "rule4": {"match": False, "ref": r_rec.rule4 if r_rec else "N/A", "sus": s_rec.rule4 if s_rec else "N/A"},
                        "differences": [node_diff_desc],
                    }
                    node_comparisons.append(node_comp)
                    differences_only.append({
                        "step_number": s_num,
                        "step_name": step_name,
                        "node_id": nid,
                        "type": "NODE_PRESENCE_MISMATCH",
                        "details": node_diff_desc,
                    })
                    continue

                r1_match = (r_rec.rule1 == s_rec.rule1)
                r2_match = (r_rec.rule2 == s_rec.rule2)
                r3_match = (r_rec.rule3 == s_rec.rule3)
                r4_match = (r_rec.rule4 == s_rec.rule4)

                rule_matches = [r1_match, r2_match, r3_match, r4_match]
                matching_rules_count += sum(1 for m in rule_matches if m)
                differing_rules_count += sum(1 for m in rule_matches if not m)
                total_rules_evaluated += 4

                node_diffs = []
                if not r1_match:
                    node_diffs.append(f"Rule 1 differs (CS/Count parity): Ref '{r_rec.rule1}' vs Sus '{s_rec.rule1}'")
                if not r2_match:
                    node_diffs.append(f"Rule 2 differs (Node ID encoding): Ref '{r_rec.rule2}' vs Sus '{s_rec.rule2}'")
                if not r3_match:
                    node_diffs.append(f"Rule 3 differs (Op Type): Ref '{r_rec.rule3}' ({r_rec.op_type}) vs Sus '{s_rec.rule3}' ({s_rec.op_type})")
                if not r4_match:
                    node_diffs.append(f"Rule 4 differs (Step Node Count): Ref '{r_rec.rule4}' vs Sus '{s_rec.rule4}'")

                is_node_match = (len(node_diffs) == 0)
                if not is_node_match:
                    step_has_diff = True

                node_comp = {
                    "node_id": nid,
                    "status": "MATCH" if is_node_match else "DIFFER",
                    "op_type": r_rec.op_type,
                    "rule1": {"match": r1_match, "ref": r_rec.rule1, "sus": s_rec.rule1},
                    "rule2": {"match": r2_match, "ref": r_rec.rule2, "sus": s_rec.rule2},
                    "rule3": {"match": r3_match, "ref": r_rec.rule3, "sus": s_rec.rule3},
                    "rule4": {"match": r4_match, "ref": r_rec.rule4, "sus": s_rec.rule4},
                    "differences": node_diffs,
                }
                node_comparisons.append(node_comp)

                if not is_node_match:
                    differences_only.append({
                        "step_number": s_num,
                        "step_name": step_name,
                        "node_id": nid,
                        "type": "RULE_MISMATCH",
                        "differences": node_diffs,
                    })

            step_comparisons.append({
                "step_number": s_num,
                "step_name": step_name,
                "status": "DIFFER" if step_has_diff else "MATCH",
                "reference_node_count": r_grp.node_count,
                "suspicious_node_count": s_grp.node_count,
                "nodes": node_comparisons,
                "matching_node_count": sum(1 for n in node_comparisons if n["status"] == "MATCH"),
                "total_step_nodes": len(node_comparisons),
            })

        agreement_ratio = (
            (matching_rules_count / total_rules_evaluated) if total_rules_evaluated > 0 else 1.0
        )

        return {
            "level": 2,
            "comparison_type": "RULE_COMPONENT_LEVEL",
            "summary": {
                "reference_nodes": reference.total_design_nodes,
                "suspicious_nodes": suspicious.total_design_nodes,
                "reference_steps": reference.total_steps,
                "suspicious_steps": suspicious.total_steps,
                "reference_bits": len(reference.canonical_bitstream),
                "suspicious_bits": len(suspicious.canonical_bitstream),
                "total_components_evaluated": total_rules_evaluated,
                "matching_components": matching_rules_count,
                "differing_components": differing_rules_count,
                "agreement_ratio": round(agreement_ratio, 6),
                "agreement_percentage_str": f"{agreement_ratio * 100:.2f}%",
                "differing_steps_count": sum(1 for s in step_comparisons if s["status"] != "MATCH"),
                "total_steps_compared": len(step_comparisons),
            },
            "step_comparisons": step_comparisons,
            "differences_only": differences_only,
            "differences_count": len(differences_only),
            "level3_extension": {
                "status": "NOT_IMPLEMENTED",
                "reason": (
                    "Level 3 structural/node-correspondence similarity requires a formal "
                    "node alignment model for graph isomorphism, node insertions/deletions, "
                    "and schedule reordering. Intentionally deferred as future research extension."
                ),
            },
        }
