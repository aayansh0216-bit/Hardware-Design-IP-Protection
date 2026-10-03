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
