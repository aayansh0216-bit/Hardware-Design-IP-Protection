"""
Pedersen Commitment Scheme over NIST P-256 (secp256r1).

Provides information-theoretically hiding and computationally binding
commitments to values (e.g., test vectors, transaction watermarks).

Formula:
    C = s * G + r * H
where:
    G is the standard NIST P-256 generator point.
    H is a Nothing-Up-My-Sleeve (NUMS) generator point with unknown discrete log w.r.t. G.
    s is the message scalar (reduced modulo the curve order n).
    r is a cryptographically secure random blinding factor in [1, n - 1].
"""

import hashlib
import secrets
from enum import Enum
from typing import Optional, Tuple, Dict, Any
import ecdsa
from ecdsa.ellipticcurve import PointJacobi


class CommitmentVerificationStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    NOT_VERIFIABLE = "NOT_VERIFIABLE"


class PedersenCommitment:
    """
    Immutable representation of a Pedersen commitment value C and optional opening information.
    """

    def __init__(
        self,
        commitment_hex: str,
        curve_name: str = "NIST256p",
        blinding_factor_hex: Optional[str] = None,
        message_hash: Optional[str] = None,
    ):
        self.commitment_hex = commitment_hex
        self.curve_name = curve_name
        self.blinding_factor_hex = blinding_factor_hex
        self.message_hash = message_hash

    def to_dict(self, include_opening: bool = False) -> Dict[str, Any]:
        data = {
            "commitment_hex": self.commitment_hex,
            "curve_name": self.curve_name,
            "scheme": "pedersen",
        }
        if self.message_hash:
            data["message_hash"] = self.message_hash
        if include_opening and self.blinding_factor_hex:
            data["blinding_factor_hex"] = self.blinding_factor_hex
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PedersenCommitment":
        return cls(
            commitment_hex=data["commitment_hex"],
            curve_name=data.get("curve_name", "NIST256p"),
            blinding_factor_hex=data.get("blinding_factor_hex"),
            message_hash=data.get("message_hash"),
        )


class PedersenEngine:
    """
    Cryptographic engine for computing and verifying Pedersen commitments.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PedersenEngine, cls).__new__(cls)
            cls._instance._init_curve()
        return cls._instance

    def _init_curve(self):
        self.curve = ecdsa.NIST256p
        self.order = self.curve.order
        self.G = self.curve.generator
        self.H = self._derive_nums_generator()

    def _derive_nums_generator(self) -> PointJacobi:
        """
        Derives an independent Nothing-Up-My-Sleeve (NUMS) point H on NIST P-256
        via deterministic try-and-increment hash-to-curve.
        """
        seed = b"Pedersen_P256_NUMS_H_Generator_v1"
        p = self.curve.curve.p()
        a = self.curve.curve.a()
        b = self.curve.curve.b()

        for counter in range(1000):
            cand = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
            x = int.from_bytes(cand, "big") % p
            rhs = (pow(x, 3, p) + a * x + b) % p
            # For NIST P-256, p = 3 mod 4, so candidate square root is rhs^((p+1)//4) mod p
            y = pow(rhs, (p + 1) // 4, p)
            if pow(y, 2, p) == rhs:
                return PointJacobi(self.curve.curve, x, y, 1, self.order)
        raise RuntimeError("Failed to derive NUMS generator point H")

    def hash_to_scalar(self, data: bytes | str) -> int:
        """
        Converts arbitrary data to a non-zero scalar in [1, order - 1] via SHA-256.
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        h = hashlib.sha256(data).digest()
        scalar = int.from_bytes(h, "big") % self.order
        return scalar if scalar != 0 else 1

    def generate_blinding_factor(self) -> int:
        """
        Generates a fresh cryptographically secure random blinding factor r in [1, order - 1].
        """
        return secrets.randbelow(self.order - 1) + 1

    def point_to_hex(self, point: PointJacobi) -> str:
        """
        Encodes an elliptic curve point as a standard 33-byte compressed hex string.
        """
        affine = point.to_affine()
        x_bytes = affine.x().to_bytes(32, "big")
        prefix = b"\x02" if affine.y() % 2 == 0 else b"\x03"
        return (prefix + x_bytes).hex()

    def hex_to_point(self, hex_str: str) -> PointJacobi:
        """
        Decodes a compressed 33-byte hex string back to a Curve Point.
        """
        data = bytes.fromhex(hex_str)
        if len(data) != 33 or data[0] not in (2, 3):
            raise ValueError("Invalid compressed point format")
        prefix = data[0]
        x = int.from_bytes(data[1:], "big")
        p = self.curve.curve.p()
        a = self.curve.curve.a()
        b = self.curve.curve.b()
        rhs = (pow(x, 3, p) + a * x + b) % p
        y = pow(rhs, (p + 1) // 4, p)
        if pow(y, 2, p) != rhs:
            raise ValueError("Point not on curve")
        if (prefix == 2 and y % 2 != 0) or (prefix == 3 and y % 2 == 0):
            y = p - y
        return PointJacobi(self.curve.curve, x, y, 1, self.order)

    def commit(
        self, data: bytes | str, blinding_factor: Optional[int] = None
    ) -> Tuple[PedersenCommitment, int]:
        """
        Computes commitment C = s * G + r * H.
        Returns (PedersenCommitment, blinding_factor).
        """
        if blinding_factor is None:
            blinding_factor = self.generate_blinding_factor()

        s = self.hash_to_scalar(data)
        r = blinding_factor % self.order

        point_C = (s * self.G) + (r * self.H)
        c_hex = self.point_to_hex(point_C)

        if isinstance(data, str):
            msg_bytes = data.encode("utf-8")
        else:
            msg_bytes = data
        m_hash = hashlib.sha256(msg_bytes).hexdigest()

        commitment = PedersenCommitment(
            commitment_hex=c_hex,
            curve_name="NIST256p",
            blinding_factor_hex=hex(blinding_factor)[2:].zfill(64),
            message_hash=m_hash,
        )
        return commitment, blinding_factor

    def verify(
        self,
        data: Optional[bytes | str],
        commitment_hex: str,
        blinding_factor: Optional[int | str],
    ) -> CommitmentVerificationStatus:
        """
        Verifies exact equality C' == C given data, blinding factor, and stored commitment.
        If data or blinding factor is missing, returns NOT_VERIFIABLE.
        """
        if data is None or blinding_factor is None or not commitment_hex:
            return CommitmentVerificationStatus.NOT_VERIFIABLE

        try:
            if isinstance(blinding_factor, str):
                r = int(blinding_factor, 16)
            else:
                r = int(blinding_factor)

            s = self.hash_to_scalar(data)
            r = r % self.order

            recomputed_point = (s * self.G) + (r * self.H)
            recomputed_hex = self.point_to_hex(recomputed_point)

            if recomputed_hex.lower() == commitment_hex.lower():
                return CommitmentVerificationStatus.VALID
            else:
                return CommitmentVerificationStatus.INVALID
        except Exception:
            return CommitmentVerificationStatus.INVALID
