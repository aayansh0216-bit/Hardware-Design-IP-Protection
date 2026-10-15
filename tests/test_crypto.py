"""
Unit tests for Cryptographic primitives: Pedersen commitments, Design hashing, and Watermark generation.
"""

import pytest
from hardware_ip_protection.crypto.pedersen import (
    PedersenEngine,
    PedersenCommitment,
    CommitmentVerificationStatus,
)
from hardware_ip_protection.crypto.design_hasher import DesignHasher
from hardware_ip_protection.crypto.watermark_generator import (
    SymmetricHKDFWatermarkGenerator,
    TransactionWatermark,
)
from hardware_ip_protection.hls.dfg import create_dct4


def test_pedersen_completeness():
    pe = PedersenEngine()
    data = "test_transaction_bitstream_101010"
    comm, r = pe.commit(data)

    status = pe.verify(data, comm.commitment_hex, r)
    assert status == CommitmentVerificationStatus.VALID


def test_pedersen_soundness():
    pe = PedersenEngine()
    data = "valid_message"
    tampered = "tampered_message"
    comm, r = pe.commit(data)

    # Verifying with modified data must fail
    status = pe.verify(tampered, comm.commitment_hex, r)
    assert status == CommitmentVerificationStatus.INVALID

    # Verifying with wrong blinding factor must fail
    status_wrong_r = pe.verify(data, comm.commitment_hex, (r + 1) % pe.order)
    assert status_wrong_r == CommitmentVerificationStatus.INVALID


def test_pedersen_missing_opening():
    pe = PedersenEngine()
    data = "message"
    comm, r = pe.commit(data)

    assert pe.verify(None, comm.commitment_hex, r) == CommitmentVerificationStatus.NOT_VERIFIABLE
    assert pe.verify(data, comm.commitment_hex, None) == CommitmentVerificationStatus.NOT_VERIFIABLE


def test_design_hasher_reproducibility():
    dfg1 = create_dct4()
    dfg2 = create_dct4()

    h1 = DesignHasher.hash_design(dfg1.to_dict())
    h2 = DesignHasher.hash_design(dfg2.to_dict())
    assert h1 == h2
    assert len(h1) == 64


def test_watermark_generator_sensitivity():
    gen = SymmetricHKDFWatermarkGenerator()
    base_rec = {
        "transaction_id": "TX-1",
        "seller_id": "SELLER-1",
        "buyer_id": "BUYER-1",
        "design_hash": "a" * 64,
        "license_type": "exclusive",
    }
    creds = {"k_tx": "secret_key"}

    wm_base = gen.generate(base_rec, creds, watermark_length=16)
    assert len(wm_base.bitstream) == 16
    assert wm_base.bit_length == 16

    wm_32 = gen.generate(base_rec, creds, watermark_length=32)
    assert len(wm_32.bitstream) == 32
    assert wm_32.bit_length == 32

    # Changing buyer_id alters watermark
    rec_buyer = dict(base_rec, buyer_id="BUYER-2")
    wm_buyer = gen.generate(rec_buyer, creds)
    assert wm_base.bitstream != wm_buyer.bitstream

    # Changing license_type alters watermark
    rec_license = dict(base_rec, license_type="non_exclusive")
    wm_license = gen.generate(rec_license, creds)
    assert wm_base.bitstream != wm_license.bitstream

    # Changing key alters watermark
    wm_key = gen.generate(base_rec, {"k_tx": "different_secret"})
    assert wm_base.bitstream != wm_key.bitstream


def test_pedersen_malformed_and_edge_cases():
    pe = PedersenEngine()
    data = "test_data"
    comm, r = pe.commit(data)

    # 1. Invalid compressed prefix
    invalid_prefix_hex = "04" + comm.commitment_hex[2:]
    with pytest.raises(ValueError):
        pe.hex_to_point(invalid_prefix_hex)
    assert pe.verify(data, invalid_prefix_hex, r) == CommitmentVerificationStatus.INVALID

    # 2. Malformed non-hex string
    assert pe.verify(data, "not_a_valid_hex_point", r) == CommitmentVerificationStatus.INVALID

    # 3. Truncated point
    assert pe.verify(data, comm.commitment_hex[:30], r) == CommitmentVerificationStatus.INVALID

    # 4. Point not on curve (tampered coordinate)
    tampered_x_hex = comm.commitment_hex[:2] + "ff" * 32
    assert pe.verify(data, tampered_x_hex, r) == CommitmentVerificationStatus.INVALID

    # 5. Invalid blinding factor format
    assert pe.verify(data, comm.commitment_hex, "invalid_blinding_hex") == CommitmentVerificationStatus.INVALID

    # 6. Negative blinding factor rejected safely
    assert pe.verify(data, comm.commitment_hex, -5) == CommitmentVerificationStatus.INVALID


def test_watermark_generator_d_and_b_binding():
    gen = SymmetricHKDFWatermarkGenerator()
    base_rec = {
        "transaction_id": "TX-1",
        "seller_id": "SELLER-1",
        "buyer_id": "BUYER-1",
        "design_hash": "a" * 64,
        "license_type": "exclusive",
    }
    creds = {"k_tx": "secret_key"}

    d1 = "10101010" * 10
    d2 = "10101011" * 10
    b1 = "01010101" * 20
    b2 = "01010100" * 20

    # 1. Providing D and B binds them into the watermark
    wm_db1 = gen.generate(base_rec, creds, D=d1, B=b1)
    wm_db1_repeat = gen.generate(base_rec, creds, D=d1, B=b1)
    assert wm_db1.canonical_bitstream == wm_db1_repeat.canonical_bitstream

    # 2. Altering D while keeping B and context fixed changes W
    wm_db2 = gen.generate(base_rec, creds, D=d2, B=b1)
    assert wm_db1.canonical_bitstream != wm_db2.canonical_bitstream

    # 3. Altering B while keeping D and context fixed changes W
    wm_db3 = gen.generate(base_rec, creds, D=d1, B=b2)
    assert wm_db1.canonical_bitstream != wm_db3.canonical_bitstream

    # 4. Base record without D and B differs from record with D and B bound
    wm_base = gen.generate(base_rec, creds)
    assert wm_base.canonical_bitstream != wm_db1.canonical_bitstream

    # 5. D and B passed in record dictionary have identical effect to parameter passing
    rec_with_db = dict(base_rec, design_encoding_D=d1, buyer_contribution_B=b1)
    wm_from_rec = gen.generate(rec_with_db, creds)
    assert wm_from_rec.canonical_bitstream == wm_db1.canonical_bitstream
