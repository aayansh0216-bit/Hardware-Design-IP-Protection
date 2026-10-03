"""
Register Allocation via CIG Graph Coloring.

Enforces:
    1. No two storage variables connected by a CIG edge (genuine or watermark constraint)
       may share a physical hardware register.
    2. Physical register parity is NEVER checked or constrained.
    3. Post-allocation validation verifies every watermark constraint is strictly respected.
"""

from typing import Dict, List, Tuple, Set, Optional, Any
from .cig import CIG, ConstrainedCIG
from .dfg import get_variable_index


class RegisterAllocationResult:
    """
    Structured outcome of register allocation on a CIG.
    """

    def __init__(
        self,
        variable_to_register: Dict[str, str],
        register_count: int,
        timing_table: Dict[int, Dict[str, Optional[str]]],
        cig: CIG,
        embedding_verified: bool = False,
    ):
        self.variable_to_register = variable_to_register
        self.register_count = register_count
        self.timing_table = timing_table
        self.cig = cig
        self.embedding_verified = embedding_verified
        self.registers = [f"R{i}" for i in range(register_count)]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "register_count": self.register_count,
            "registers": self.registers,
            "variable_to_register": self.variable_to_register,
            "timing_table": self.timing_table,
            "is_constrained": isinstance(self.cig, ConstrainedCIG),
            "embedding_verified": self.embedding_verified,
        }


class RegisterAllocator:
    """
    Determines minimum register binding satisfying CIG conflict constraints.
    """

    @classmethod
    def allocate(cls, cig: CIG) -> RegisterAllocationResult:
        """
        Performs deterministic graph coloring register allocation.
        """
        nodes = sorted(cig.nodes, key=lambda v: (get_variable_index(v), v))

        # Adjacency list
        adj: Dict[str, Set[str]] = {n: set() for n in nodes}
        for u, v in cig.edges:
            adj[u].add(v)
            adj[v].add(u)

        # Left-Edge interval graph coloring ordered by variable birth time and index
        nodes_sorted = sorted(
            nodes,
            key=lambda n: (cig.scheduled_dfg.variable_lifetimes.get(n, (0, 0))[0], get_variable_index(n), n),
        )

        coloring: Dict[str, int] = {}
        for node in nodes_sorted:
            # Find colors used by neighbors
            neighbor_colors = {coloring[nbr] for nbr in adj[node] if nbr in coloring}
            # Assign lowest available color
            c = 0
            while c in neighbor_colors:
                c += 1
            coloring[node] = c

        num_regs = max(coloring.values()) + 1 if coloring else 1
        var_to_reg: Dict[str, str] = {var: f"R{coloring[var]}" for var in nodes}

        # Verify invariant: No two connected nodes share a register
        for u, v in cig.edges:
            if var_to_reg[u] == var_to_reg[v]:
                raise RuntimeError(f"Register allocation invariant violated: {u} and {v} share {var_to_reg[u]}")

        # Construct timing table across control steps
        total_steps = cig.scheduled_dfg.total_steps
        lifetimes = cig.scheduled_dfg.variable_lifetimes
        timing_table: Dict[int, Dict[str, Optional[str]]] = {}

        for step in range(total_steps):
            timing_table[step] = {}
            for r_idx in range(num_regs):
                r_name = f"R{r_idx}"
                resident = None
                for var, reg in var_to_reg.items():
                    if reg == r_name:
                        birth, death = lifetimes.get(var, (0, 0))
                        if birth <= step <= death:
                            resident = var
                            break
                timing_table[step][r_name] = resident

        embedding_verified = False
        if isinstance(cig, ConstrainedCIG):
            cls.validate_embedding(var_to_reg, cig)
            embedding_verified = True

        return RegisterAllocationResult(
            variable_to_register=var_to_reg,
            register_count=num_regs,
            timing_table=timing_table,
            cig=cig,
            embedding_verified=embedding_verified,
        )

    @classmethod
    def validate_embedding(cls, var_to_reg: Dict[str, str], constrained_cig: ConstrainedCIG) -> None:
        """
        Validates Section 11 of the specification:
        For every watermark position:
            1. Selected pair exists as an edge in the constrained CIG.
            2. Resulting register allocation satisfies: register(Vi) != register(Vj).
        """
        for item in constrained_cig.embedding_log:
            u, v = item["pair"]
            if not constrained_cig.has_edge(u, v):
                raise RuntimeError(
                    f"Watermark embedding validation FAILED: CIG edge missing for pair ({u}, {v}) at position {item['position']}"
                )
            reg_u = var_to_reg.get(u)
            reg_v = var_to_reg.get(v)
            if reg_u == reg_v:
                raise RuntimeError(
                    f"Watermark embedding validation FAILED: variables {u} and {v} share register {reg_u} at position {item['position']}"
                )
        return True
