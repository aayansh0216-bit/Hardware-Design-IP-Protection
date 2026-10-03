"""
Modular Transaction Watermark Generation.

Generates a transaction watermark bitstream of design-dependent length N from
a canonical transaction record and cryptographic credentials.

Invariants:
    1. Exactly ONE transaction watermark per transaction.
    2. Binds: seller_id, buyer_id, design_hash, transaction_id, license_type, protocol_version.
    3. Output is an N-bit bitstream where N is the selected design-dependent watermark length.
    4. Generator is modular and replaceable by asymmetric ECDH without affecting
       CIG, register allocation, or RTL embedding.
"""

from abc import ABC, abstractmethod
import hashlib
import json
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


CANONICAL_WATERMARK_LENGTH = 256


class TransactionWatermark:
    """
    Container for the canonical 256-bit transaction watermark,
    partitioned into the physically embedded portion (N bits)
    and remaining portion (256 - N bits) retained as reconstruction metadata.
    """

    def __init__(
        self,
        bitstream: str,
        canonical_bitstream: Optional[str] = None,
        embedded_length: Optional[int] = None,
    ):
        if not bitstream or not set(bitstream).issubset({"0", "1"}):
            raise ValueError(f"Transaction watermark must be a non-empty binary string of 0s and 1s, got '{bitstream}'")

        if canonical_bitstream:
            if not set(canonical_bitstream).issubset({"0", "1"}):
                raise ValueError("Canonical watermark must be a binary string of 0s and 1s")
            self.canonical_bitstream: str = canonical_bitstream
        else:
            self.canonical_bitstream: str = bitstream

        self.canonical_length: int = len(self.canonical_bitstream)

        if embedded_length is not None:
            self.embedded_length: int = min(embedded_length, self.canonical_length)
        else:
            self.embedded_length: int = len(bitstream)

        self.embedded_bitstream: str = self.canonical_bitstream[: self.embedded_length]
        # Backwards compatibility: self.bitstream is the embedded bitstream of length N
        self.bitstream: str = self.embedded_bitstream
        self.bit_length: int = len(self.bitstream)

        self.remaining_bitstream: str = self.canonical_bitstream[self.embedded_length :]
        self.remaining_length: int = len(self.remaining_bitstream)

        self.hex: str = hex(int(self.bitstream, 2))[2:].zfill((self.bit_length + 3) // 4)
        self.canonical_hex: str = hex(int(self.canonical_bitstream, 2))[2:].zfill((self.canonical_length + 3) // 4)

        # Canonical 256-bit watermark hash used for Pedersen commitment
        self.watermark_hash: str = hashlib.sha256(self.canonical_bitstream.encode("utf-8")).hexdigest()
        self.embedded_hash: str = hashlib.sha256(self.embedded_bitstream.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bitstream": self.bitstream,
            "bit_length": self.bit_length,
            "hex": self.hex,
            "canonical_bitstream": self.canonical_bitstream,
            "canonical_length": self.canonical_length,
            "canonical_hex": self.canonical_hex,
            "embedded_bitstream": self.embedded_bitstream,
            "embedded_length": self.embedded_length,
            "remaining_bitstream": self.remaining_bitstream,
            "remaining_length": self.remaining_length,
            "watermark_hash": self.watermark_hash,
            "embedded_hash": self.embedded_hash,
        }

    def __repr__(self) -> str:
        return (
            f"<TransactionWatermark canonical_len={self.canonical_length} "
            f"embedded_len={self.embedded_length} remaining_len={self.remaining_length} "
            f"hash={self.watermark_hash[:16]}...>"
        )


class TransactionWatermarkGenerator(ABC):
    """
    Abstract interface for generating an N-bit transaction watermark.
    """

    @abstractmethod
    def generate(
        self,
        transaction_record: Dict[str, Any],
        transaction_credentials: Dict[str, Any],
        watermark_length: Optional[int] = 16,
    ) -> TransactionWatermark:
        """
        Derives an N-bit transaction watermark.
        """
        pass


class SymmetricHKDFWatermarkGenerator(TransactionWatermarkGenerator):
    """
    Authoritative V1 Symmetric Watermark Generator.
    Uses HKDF with HMAC-SHA256 over canonical transaction metadata and K_tx.
    Always generates the canonical 256-bit transaction watermark W_256,
    and partitions it into W_embedded (length N) and W_remaining (length 256 - N).
    """

    HKDF_INFO = b"HardwareIP_Transaction_Watermark_v1"
    HKDF_SALT = b"Hardware_IP_Protection_Salt_2026"

    @staticmethod
    def canonicalize_transaction_record(record: Dict[str, Any]) -> str:
        """
        Validates and canonicalizes the transaction record schema:
            transaction_id, seller_id, buyer_id, design_hash, license_type
        """
        required_fields = ["transaction_id", "seller_id", "buyer_id", "design_hash", "license_type"]
        for field in required_fields:
            if field not in record or not record[field]:
                raise ValueError(f"Missing required field '{field}' in transaction record")

        license_type = str(record["license_type"]).lower()
        if license_type not in ("exclusive", "non_exclusive"):
            raise ValueError(f"Invalid license_type '{license_type}'. Must be 'exclusive' or 'non_exclusive'")

        canonical_data = {
            "protocol_version": "1.0",
            "transaction_id": str(record["transaction_id"]).strip(),
            "seller_id": str(record["seller_id"]).strip(),
            "buyer_id": str(record["buyer_id"]).strip(),
            "design_hash": str(record["design_hash"]).strip().lower(),
            "license_type": license_type,
        }
        return json.dumps(canonical_data, sort_keys=True, separators=(",", ":"))

    def generate(
        self,
        transaction_record: Dict[str, Any],
        transaction_credentials: Dict[str, Any],
        watermark_length: Optional[int] = 16,
    ) -> TransactionWatermark:
        if watermark_length is not None and watermark_length < 1:
            raise ValueError(f"Watermark length must be >= 1, got {watermark_length}")

        canonical_tx_str = self.canonicalize_transaction_record(transaction_record)

        k_tx = transaction_credentials.get("k_tx")
        if not k_tx:
            raise ValueError("Missing 'k_tx' (symmetric transaction key) in transaction credentials")

        if isinstance(k_tx, str):
            k_tx_bytes = k_tx.encode("utf-8")
        else:
            k_tx_bytes = bytes(k_tx)

        # HKDF-SHA256 always derives exactly 32 bytes (256 bits) for the canonical transaction watermark
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.HKDF_SALT,
            info=self.HKDF_INFO + b":" + canonical_tx_str.encode("utf-8"),
        )
        derived_bytes = hkdf.derive(k_tx_bytes)

        # Convert to 256-bit binary string ('0' and '1')
        canonical_bitstream = "".join(f"{byte:08b}" for byte in derived_bytes)
        assert len(canonical_bitstream) == CANONICAL_WATERMARK_LENGTH

        # Partition into embedded (N) and remaining (256 - N)
        target_embedded_length = watermark_length if watermark_length is not None else CANONICAL_WATERMARK_LENGTH
        target_embedded_length = min(target_embedded_length, CANONICAL_WATERMARK_LENGTH)
        embedded_bitstream = canonical_bitstream[:target_embedded_length]

        return TransactionWatermark(
            bitstream=embedded_bitstream,
            canonical_bitstream=canonical_bitstream,
            embedded_length=target_embedded_length,
        )
