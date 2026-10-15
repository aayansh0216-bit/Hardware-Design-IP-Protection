"""
Data Flow Graph (DFG) Representation and Standard Hardware Benchmarks.

Provides standard hardware benchmark DFGs from the IP protection literature:
- 4-point Discrete Cosine Transform (DCT)
- Auto-Regressive Filter (ARF)
- Finite Impulse Response (FIR) Filter
- MESA Benchmark
- 3x3 Convolutional Hardware Accelerator Kernel (Conv3x3)
"""

from typing import Dict, List, Any, Optional, Set
import copy


def get_variable_index(var_name: str) -> int:
    """
    Extracts deterministic integer index of a storage variable.
    e.g., 'v0' -> 0, 'v1' -> 1, 'v10' -> 10, 'm1' -> 1, 'x0' -> 0.
    """
    digits = "".join(ch for ch in var_name if ch.isdigit())
    if digits:
        return int(digits)
    return sum(ord(c) for c in var_name)


class DFGNode:
    """
    Represents an operation or storage generation node in the DFG.
    """

    def __init__(
        self,
        node_id: int,
        op_type: str,
        inputs: List[str],
        output: str,
        delay: int = 1,
    ):
        self.node_id = node_id
        self.op_type = op_type.lower()
        self.inputs = list(inputs)
        self.output = output
        self.delay = delay  # in control steps / cycles

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.node_id,
            "op": self.op_type,
            "inputs": self.inputs,
            "output": self.output,
            "delay": self.delay,
        }


class DFG:
    """
    Data Flow Graph containing operation nodes, variables, and dependencies.
    """

    def __init__(
        self,
        name: str,
        inputs: List[str],
        outputs: List[str],
        nodes: List[DFGNode],
    ):
        self.name = name
        self.inputs = list(inputs)
        self.outputs = list(outputs)
        self.nodes = list(nodes)
        self._node_map: Dict[int, DFGNode] = {n.node_id: n for n in nodes}

    @property
    def storage_variables(self) -> List[str]:
        """
        Returns all storage variables allocated to registers, sorted naturally by variable index.
        For 4point_dct, storage variables are strictly v0..v10 (coefficients c0..c3 are multipliers).
        """
        vars_set = set()
        for node in self.nodes:
            vars_set.add(node.output)
            for inp in node.inputs:
                if self.name == "4point_dct" and inp.startswith("c") and len(inp) <= 2:
                    continue
                vars_set.add(inp)
        return sorted(list(vars_set), key=lambda v: (get_variable_index(v), v))

    @property
    def all_variables(self) -> List[str]:
        """
        Returns all unique storage variables in the DFG.
        """
        return self.storage_variables

    def get_predecessors(self, node_id: int) -> List[int]:
        """
        Returns IDs of nodes that produce inputs for node_id.
        """
        target = self._node_map[node_id]
        preds = []
        for n in self.nodes:
            if n.node_id != node_id and n.output in target.inputs:
                preds.append(n.node_id)
        return preds

    def get_successors(self, node_id: int) -> List[int]:
        """
        Returns IDs of nodes that consume the output of node_id.
        """
        target = self._node_map[node_id]
        succs = []
        for n in self.nodes:
            if n.node_id != node_id and target.output in n.inputs:
                succs.append(n.node_id)
        return succs

    def to_dict(self) -> Dict[str, Any]:
        deps = []
        for n in self.nodes:
            for inp in n.inputs:
                deps.append({"from_var": inp, "to_var": n.output})
        return {
            "name": self.name,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "operations": [n.to_dict() for n in self.nodes],
            "data_dependencies": deps,
        }


# ==============================================================================
# Standard Benchmark Factories
# ==============================================================================

def create_dct4() -> DFG:
    """
    4-point DCT benchmark from literature slides:
    Inputs: v0, v1, v2, v3
    Multipliers:
      op 1: v4 = v0 * c0
      op 2: v5 = v1 * c1
      op 3: v6 = v2 * c2
      op 4: v7 = v3 * c3
    Adders:
      op 5: v8 = v4 + v5
      op 6: v9 = v8 + v6
      op 7: v10 = v9 + v7
    Outputs: v10
    """
    nodes = [
        DFGNode(1, "mul", ["v0", "c0"], "v4"),
        DFGNode(2, "mul", ["v1", "c1"], "v5"),
        DFGNode(3, "mul", ["v2", "c2"], "v6"),
        DFGNode(4, "mul", ["v3", "c3"], "v7"),
        DFGNode(5, "add", ["v4", "v5"], "v8"),
        DFGNode(6, "add", ["v8", "v6"], "v9"),
        DFGNode(7, "add", ["v9", "v7"], "v10"),
    ]
    return DFG(
        name="4point_dct",
        inputs=["v0", "v1", "v2", "v3", "c0", "c1", "c2", "c3"],
        outputs=["v10"],
        nodes=nodes,
    )


def create_fir() -> DFG:
    """
    16-tap / 23-node FIR Filter benchmark.
    """
    inputs = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
    nodes = [
        # Multiplications
        DFGNode(1, "mul", ["x0", "h0"], "m1"),
        DFGNode(2, "mul", ["x1", "h1"], "m2"),
        DFGNode(3, "mul", ["x2", "h2"], "m3"),
        DFGNode(4, "mul", ["x3", "h3"], "m4"),
        DFGNode(5, "mul", ["x4", "h4"], "m5"),
        DFGNode(6, "mul", ["x5", "h5"], "m6"),
        DFGNode(7, "mul", ["x6", "h6"], "m7"),
        DFGNode(8, "mul", ["x7", "h7"], "m8"),
        # Adders Tree
        DFGNode(9, "add", ["m1", "m2"], "a1"),
        DFGNode(10, "add", ["m3", "m4"], "a2"),
        DFGNode(11, "add", ["m5", "m6"], "a3"),
        DFGNode(12, "add", ["m7", "m8"], "a4"),
        DFGNode(13, "add", ["a1", "a2"], "a5"),
        DFGNode(14, "add", ["a3", "a4"], "a6"),
        DFGNode(15, "add", ["a5", "a6"], "y_out"),
    ]
    return DFG(
        name="fir_filter",
        inputs=inputs + ["h0", "h1", "h2", "h3", "h4", "h5", "h6", "h7"],
        outputs=["y_out"],
        nodes=nodes,
    )


def create_arf() -> DFG:
    """
    Auto-Regressive Filter (ARF) benchmark (28 operations).
    """
    nodes = []
    # Layer 1 Multipliers
    for i in range(1, 9):
        nodes.append(DFGNode(i, "mul", [f"v_in_{i}", f"k_{i}"], f"m_{i}"))
    # Adders layers
    for i in range(1, 5):
        nodes.append(DFGNode(8 + i, "add", [f"m_{2*i-1}", f"m_{2*i}"], f"a_{i}"))
    for i in range(1, 3):
        nodes.append(DFGNode(12 + i, "add", [f"a_{2*i-1}", f"a_{2*i}"], f"b_{i}"))
    nodes.append(DFGNode(15, "add", ["b_1", "b_2"], "c_1"))
    # Additional feedback / AR nodes
    nodes.append(DFGNode(16, "mul", ["c_1", "fb_k1"], "fb_m1"))
    nodes.append(DFGNode(17, "add", ["fb_m1", "v_in_1"], "arf_out"))
    return DFG(
        name="arf_filter",
        inputs=[f"v_in_{i}" for i in range(1, 9)] + [f"k_{i}" for i in range(1, 9)] + ["fb_k1"],
        outputs=["arf_out"],
        nodes=nodes,
    )


def create_mesa() -> DFG:
    """
    MESA Benchmark from Roy & Sengupta (FGCS 2017):
    Storage variables v0 to v17, scheduled across control steps 0 to 6.
    """
    nodes = [
        DFGNode(1, "mul", ["v0", "c1"], "v4"),
        DFGNode(2, "mul", ["v1", "c2"], "v5"),
        DFGNode(3, "mul", ["v2", "c3"], "v6"),
        DFGNode(4, "mul", ["v3", "c4"], "v7"),
        DFGNode(5, "add", ["v4", "v5"], "v8"),
        DFGNode(6, "mul", ["v6", "c5"], "v9"),
        DFGNode(7, "add", ["v7", "v8"], "v10"),
        DFGNode(8, "add", ["v9", "v10"], "v11"),
        DFGNode(9, "mul", ["v11", "c6"], "v12"),
        DFGNode(10, "add", ["v10", "v12"], "v13"),
        DFGNode(11, "add", ["v12", "v13"], "v14"),
        DFGNode(12, "mul", ["v14", "c7"], "v15"),
        DFGNode(13, "add", ["v13", "v15"], "v16"),
        DFGNode(14, "add", ["v16", "v15"], "v17"),
    ]
    return DFG(
        name="mesa_benchmark",
        inputs=["v0", "v1", "v2", "v3", "c1", "c2", "c3", "c4", "c5", "c6", "c7"],
        outputs=["v17"],
        nodes=nodes,
    )


def create_conv3x3() -> DFG:
    """
    3x3 Convolutional Hardware Accelerator Kernel (from Retinal Biometric paper).
    9 Multiplications (inputs x00..x22 by kernels c00..c22) and 8 Additions tree.
    """
    inputs = [f"x{r}{c}" for r in range(3) for c in range(3)]
    kernels = [f"c{r}{c}" for r in range(3) for c in range(3)]
    nodes = []
    # 9 Multiplications
    for i in range(9):
        r, c = i // 3, i % 3
        nodes.append(DFGNode(i + 1, "mul", [f"x{r}{c}", f"c{r}{c}"], f"p_{i}"))
    # Adders tree: 8 additions
    nodes.append(DFGNode(10, "add", ["p_0", "p_1"], "s_0"))
    nodes.append(DFGNode(11, "add", ["p_2", "p_3"], "s_1"))
    nodes.append(DFGNode(12, "add", ["p_4", "p_5"], "s_2"))
    nodes.append(DFGNode(13, "add", ["p_6", "p_7"], "s_3"))
    nodes.append(DFGNode(14, "add", ["s_0", "s_1"], "t_0"))
    nodes.append(DFGNode(15, "add", ["s_2", "s_3"], "t_1"))
    nodes.append(DFGNode(16, "add", ["t_0", "t_1"], "u_0"))
    nodes.append(DFGNode(17, "add", ["u_0", "p_8"], "conv_out"))

    return DFG(
        name="conv3x3_kernel",
        inputs=inputs + kernels,
        outputs=["conv_out"],
        nodes=nodes,
    )


def create_iir_butterworth() -> DFG:
    """
    13-node, 7-control-step IIR Butterworth filter benchmark from 'design encoded data.docx'.
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
    return DFG(
        name="iir_butterworth_filter",
        inputs=[f"in{i}" for i in range(1, 8)] + [f"c{i}" for i in range(1, 8)],
        outputs=["out_bw"],
        nodes=nodes,
    )

