# Hardware IP Protection V1 - System Architecture & Verification Guide

## 1. System Overview

> **Core System Definition:**  
> A hardware design is protected by embedding a transaction-specific cryptographic watermark into register allocation, while Pedersen commitments provide prior binding of the watermark and test vectors, and behavioral/structural similarity provide separate evidence during disputes.

This prototype provides end-to-end IP protection at the Verilog/RTL level, implementing:
1. **Structural Transaction Watermarking:** Embedded exclusively during register allocation via artificial Compatibility/Conflict Interaction Graph (CIG) constraints.
2. **Pedersen Commitments over NIST P-256:** Independent information-theoretically hiding commitments for the transaction watermark and stratified test vectors.
3. **Behavioral Simulation & Verification:** Cycle-accurate simulation comparing outputs under committed test vectors.
4. **Forensic Extraction & Structural Similarity Analysis:** Recovers surviving constraints and quantifies similarity without conflating it with cryptographic proof.
5. **Two-Workflow Web Application:** Tab 1 ("Protect Design") and Tab 2 ("Verify Dispute") with rich interactive visualizations and JSON evidence export.

---

## 2. Master Specification Invariants (1-14)

| Invariant | Specification Requirement | Verification Status |
|---|---|:---:|
| **Invariant 1** | Exactly ONE V1 transaction watermark per transaction. | Verified |
| **Invariant 2** | Watermark binds: `seller_id + buyer_id + design_hash + transaction_id + license_type`. | Verified |
| **Invariant 3** | Watermark is embedded ONLY at register allocation (scheduling is untouched). | Verified |
| **Invariant 4** | Test vectors are generated from the original unwatermarked design. | Verified |
| **Invariant 5** | Test vectors are committed (`C_V`) before committed verification. | Verified |
| **Invariant 6** | Transaction watermark is committed (`C_W`) before embedding. | Verified |
| **Invariant 7** | Pedersen commitment verification is exact (`VALID` / `INVALID` / `NOT_VERIFIABLE`). | Verified |
| **Invariant 8** | Watermark similarity is structural/forensic, separate from cryptographic verification. | Verified |
| **Invariant 9** | Extraction failure does NOT automatically report 0% similarity (reported as `NOT_AVAILABLE`). | Verified |
| **Invariant 10** | No bare or ambiguous `fingerprint` identifiers in codebase or schemas. | Verified |
| **Invariant 11** | Modular `TransactionWatermarkGenerator` interface allows seamless future ECDH upgrade. | Verified |
| **Invariant 12** | No single combined ownership score is presented as cryptographic proof. | Verified |
| **Invariant 13** | System reports digital evidence; does not claim legal contract adjudication. | Verified |
| **Invariant 14** | Test vectors are never regenerated merely to make failed verification pass. | Verified |

---

## 3. Mandatory Section 44 Test Cases

All 8 mandatory test cases from Section 44 of the Authoritative Specification are implemented in `tests/test_master_specification_cases.py`:

- **Case 1 (Untouched Protected Design):** Behavior matches, extraction succeeds (256/256 bits), similarity = 100.00% (`EXACT`), watermark commitment = `VALID`.
- **Case 2 (Partial Watermark Modification):** Behavior matches, similarity < 100.00% (e.g. 97.66%), watermark commitment = `INVALID`.
- **Case 3 (Complete Watermark Removal):** Extraction fails (`FAILED`), similarity = `NOT_AVAILABLE`, commitment = `NOT_VERIFIABLE`.
- **Case 4 (Corrupted Watermark):** Extraction partial or failed, similarity != `EXACT`, commitment = `INVALID`.
- **Case 5 (Different Transaction Watermark):** Watermark extracted from design of another buyer/key, similarity mismatch, commitment = `INVALID`.
- **Case 6 (Same Behavioral Function, Independent Design):** Behavioral check matches (`MATCH`), watermark commitment = `NOT_VERIFIABLE`/`INVALID`. Demonstrates that behavioral equivalence does NOT prove IP ownership.
- **Case 7 (Modified Test Vectors Post-Commitment):** Test vector commitment verification fails (`INVALID`).
- **Case 8 (Unchanged Test Vectors):** Test vector commitment verification succeeds (`VALID`).

---

## 4. Pipeline Stages

### Protection Pipeline (15 Stages)
1. `DesignInputStage`: Ingests DFG and resource constraints.
2. `DesignCanonicalizationStage`: Canonicalizes DFG representation into deterministic JSON.
3. `DesignHashStage`: Computes SHA-256 `design_hash`.
4. `SchedulingStage`: Executes deterministic list scheduling under resource constraints.
5. `CIGConstructionStage`: Builds genuine conflict edges from variable lifetime overlaps; allocates baseline registers.
6. `TestVectorGenerationStage`: Generates stratified deterministic test vectors from original design.
7. `TestVectorCommitmentStage`: Computes Pedersen commitment $C_V = h_V \cdot G + r_V \cdot H$.
8. `TransactionWatermarkGenerationStage`: Derives 256-bit watermark via HKDF-HMAC-SHA256 from transaction record and $K_{\text{tx}}$.
9. `WatermarkCommitmentStage`: Computes Pedersen commitment $C_W = h_W \cdot G + r_W \cdot H$ before embedding.
10. `WatermarkConstraintStage`: Injects artificial CIG constraints mapping '0' to even-even pairs and '1' to odd-odd pairs.
11. `RegisterAllocationStage`: Resolves constrained CIG via graph coloring, ensuring no conflicting variables share registers.
12. `RTLGenerationStage`: Synthesizes synthesizable Verilog modules for original and protected designs.
13. `BehavioralVerificationStage`: Simulates original vs protected RTL to verify identical input-output behavior.
14. `ReferenceWatermarkExtractionStage`: Recovers reference watermark from protected RTL and verifies against $C_W$.
15. `ProtectionRecordStage`: Packages formal Pydantic `ProtectionRecordSchema` and provenance metadata.

### Dispute Pipeline (11 Stages)
1. `ReferenceDesignLoadStage`: Loads protected reference design.
2. `SuspiciousDesignLoadStage`: Ingests suspicious design under audit.
3. `TestVectorLoadVerificationStage`: Loads and validates test vector set.
4. `DisputeBehavioralVerificationStage`: Simulates reference vs suspicious RTL under committed test vectors.
5. `ReferenceWatermarkExtractionDisputeStage`: Extracts reference watermark bitstream from reference RTL.
6. `SuspiciousWatermarkExtractionStage`: Extracts suspicious watermark bitstream from suspicious RTL.
7. `WatermarkSimilarityStage`: Computes structural forensic similarity (matching, mismatching, recovered, ratio).
8. `WatermarkCommitmentVerificationStage`: Computes $C'_W = \text{Commit}(W_{\text{sus}}, r_W)$ and checks $C'_W == C_W$.
9. `TestVectorCommitmentVerificationStage`: Computes $C'_V = \text{Commit}(V, r_V)$ and checks $C'_V == C_V$.
10. `DisputeVerificationResultStage`: Synthesizes factual findings report without subjective percentages.
11. `EvidencePackagingStage`: Compiles cryptographically signed forensic audit bundle with Verilog SHA-256 digests.

---

## 5. How to Run

### Run Full Test Suite
```bash
pytest -v
```

### Launch Interactive Web Application
```bash
python -m uvicorn hardware_ip_protection.web.app:app --host 127.0.0.1 --port 8000
```
Open your browser at `http://127.0.0.1:8000`:
- **Tab 1 ("Protect Design"):** Configure hardware benchmark (4-point DCT, FIR, ARF, MESA, Conv3x3), specify transaction metadata and key, and generate protected RTL with interactive CIG and register timing visualizers.
- **Tab 2 ("Verify Dispute"):** Select attack presets (Untouched, Partial Tampering, Complete Removal, Corrupted, Different Transaction, Independent Design) and verify factual forensic evidence.