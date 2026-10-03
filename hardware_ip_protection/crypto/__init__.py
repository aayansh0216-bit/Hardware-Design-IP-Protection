"""
Cryptographic primitives for Hardware IP Protection V1.
Includes Pedersen commitment over NIST P-256, design hashing, and modular transaction watermark generation.
"""
from .pedersen import PedersenEngine, PedersenCommitment, CommitmentVerificationStatus
from .design_hasher import DesignHasher
from .watermark_generator import (
    TransactionWatermarkGenerator,
    SymmetricHKDFWatermarkGenerator,
    TransactionWatermark,
)

__all__ = [
    "PedersenEngine",
    "PedersenCommitment",
    "CommitmentVerificationStatus",
    "DesignHasher",
    "TransactionWatermarkGenerator",
    "SymmetricHKDFWatermarkGenerator",
    "TransactionWatermark",
]
