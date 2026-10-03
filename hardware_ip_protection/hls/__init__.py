"""
High-Level Synthesis (HLS) and CIG Watermarking Module for Hardware IP Protection V1.
"""
from .dfg import DFG, DFGNode, create_dct4, create_fir, create_arf, create_mesa, create_conv3x3
from .scheduler import ListScheduler, ScheduledDFG
from .cig import CIG, ConstrainedCIG, WatermarkCIGMapper
from .register_allocator import RegisterAllocator, RegisterAllocationResult
from .rtl_generator import RTLGenerator

__all__ = [
    "DFG",
    "DFGNode",
    "create_dct4",
    "create_fir",
    "create_arf",
    "create_mesa",
    "create_conv3x3",
    "ListScheduler",
    "ScheduledDFG",
    "CIG",
    "ConstrainedCIG",
    "WatermarkCIGMapper",
    "RegisterAllocator",
    "RegisterAllocationResult",
    "RTLGenerator",
]
