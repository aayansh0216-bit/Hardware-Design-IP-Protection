# Hardware IP Protection V1 - System Architecture & Verification Guide

> **Core System Definition:**  
> A hardware IP protection and dispute-verification system at the Verilog/RTL level that embeds a transaction-specific cryptographic watermark into register allocation via Compatibility Interaction Graph (CIG) conflict constraints, uses information-theoretically hiding Pedersen commitments over NIST P-256 to bind watermarks and test vectors prior to embedding, and provides factual, multi-perspective digital evidence during IP ownership disputes.

---

## 1. Project Overview & Scope

This project implements an end-to-end framework for protecting hardware Intellectual Property (IP) at the High-Level Synthesis (HLS) and Register-Transfer Level (RTL). It bridges cryptographic commitments, behavioral simulation, graph-theoretic constraint embedding, and judge-led interrogation.

### Core Capabilities
1. **Structural Transaction Watermarking:** Derived using RFC 5869 HKDF-HMAC-SHA256 from the canonical transaction metadata, buyer biometric feature bitstream $B$, design structural encoding $D$, and transaction context $T$. Embedded exclusively during register allocation via artificial CIG constraints (mapping '0' to even–even variable pairs and '1' to odd–odd variable pairs) without altering the scheduling stage.
2. **Pedersen Commitments over NIST P-256:** Independent information-theoretically hiding and computationally binding commitments for the transaction watermark ($C_W$), test vectors ($C_V$), original design encoding ($C_D$), and secured design encoding ($C_{ES}$).
3. **Multi-Length Watermark Embedding (32, 64, 128, 256 bits):** Allows selecting 32, 64, 128, or 256 bits from the canonical 256-bit HKDF watermark to embed into CIG conflict constraints, dynamically updating CIG topology, graph-coloring register allocation, synthesized Verilog RTL, and secured structural encoding.
4. **Behavioral Simulation Verification:** Cycle-accurate simulation comparing original and watermarked RTL against committed stratified pseudorandom test vectors to verify functional equivalence (100% output match).
5. **Four Integrated User Profiles:**
   - **Seller Profile:** IP Author and Licensor 4-stage sequential pipeline + Commitments and Private Evidence.
   - **Buyer Profile:** Licensee contribution, biometric feature vector $B$, transaction review, approval, and cryptographic provenance.
   - **Verifier Profile:** Independent third-party dispute verification authority testing suspicious designs against 6 standard attack presets.
   - **Judge Profile:** Progressive and instant interrogation-based adjudication, 251-bit secured encoding reconstruction, CIG constraint stripping, and multi-length Results & Analysis dashboard.

### Explicitly Out of Scope
The system explicitly excludes:
- Full zero-knowledge proof systems (zk-SNARKs / zk-STARKs)
- General-purpose Verilog AST compilers/parsers
- Physical gate-level netlist or GDSII layout fingerprinting
- Subjective probabilistic legal ownership adjudication

---

## 2. Authoritative Terminology & Conceptual Boundaries

To prevent ambiguity, standard definitions are enforced across the entire codebase:

### Design Terms
- `original_design`: The unwatermarked hardware specification (DFG and synthesized base RTL).
- `protected_design`: The hardware design following watermark embedding and register allocation.
- `design_hash`: SHA-256 digest of the canonicalized DFG JSON representation.
- `design_encoding_D`: Canonical structural bitstream (143 bits under 4-rule mode; 251 bits under 5-rule mode).

### Cryptographic & Commitment Terms
- `PedersenCommitment`: A commitment $C = v \cdot G + r \cdot H$ computed over NIST P-256 with curve generator $G$ and verifiable random point $H$.
- `blinding_factor` ($r$): 256-bit scalar keeping the committed value perfectly hidden.
- `C_W`: Commitment to the transaction watermark bitstream.
- `C_V`: Commitment to the stratified test vector set.
- `C_D`: Commitment to the original design structural encoding $D$.
- `C_ES`: Commitment to the secured post-embedding design structural encoding $E_S$.

### Watermark & Forensic Terms
- `transaction_watermark`: Canonical 256-bit bitstream $W = \text{HKDF-SHA256}(D \,\|\, B \,\|\, T, K_{tx})$.
- `embedded_watermark`: The $N$-bit prefix ($N \in \{32, 64, 128, 256\}$) actively embedded into the CIG constraints.
- `surviving_watermark`: The watermark bits recovered from a suspicious design via forensic extraction.
- `watermark_similarity`: Factual comparison reporting matching bits, mismatching bits, and unrecovered bits.

---

## 3. Master Specification Invariants (1–14)

| Invariant | Specification Requirement | Verification Status | Implementation Enforcement |
|---|---|:---:|---|
| **Invariant 1** | Exactly ONE V1 transaction watermark per transaction. | Verified | `TransactionWatermarkGenerator` creates exactly one canonical 256-bit watermark bound to $T$. |
| **Invariant 2** | Watermark binds: `seller_id + buyer_id + design_hash + transaction_id + license_type`. | Verified | Enforced via canonical JSON hashing in `compute_transaction_factor()`. |
| **Invariant 3** | Watermark is embedded ONLY at register allocation (scheduling is untouched). | Verified | `SchedulingStage` runs independently before `WatermarkConstraintStage`. |
| **Invariant 4** | Test vectors are generated from the original unwatermarked design. | Verified | Generated directly from the baseline DFG before CIG constraint injection. |
| **Invariant 5** | Test vectors are committed ($C_V$) before verification. | Verified | `TestVectorCommitmentStage` commits vectors using Pedersen engine prior to simulation. |
| **Invariant 6** | Transaction watermark is committed ($C_W$) before embedding. | Verified | `WatermarkCommitmentStage` executes prior to `WatermarkConstraintStage`. |
| **Invariant 7** | Pedersen commitment verification is exact (`VALID` / `INVALID` / `NOT_VERIFIABLE`). | Verified | Strict elliptic-curve point equality check without threshold approximations. |
| **Invariant 8** | Watermark similarity is structural/forensic, separate from cryptographic verification. | Verified | Similarity reports bit ratios; commitment checks report point equality. |
| **Invariant 9** | Extraction failure does NOT automatically report 0% similarity. | Verified | Handled via explicit `NOT_AVAILABLE` status when constraints cannot be recovered. |
| **Invariant 10** | No bare or ambiguous `fingerprint` identifiers in codebase or schemas. | Verified | Codebase strictly uses explicit names: `transaction_watermark`, `biometric_B`, etc. |
| **Invariant 11** | Modular `TransactionWatermarkGenerator` interface allows future cryptographic upgrades. | Verified | Abstract base class with pluggable `SymmetricHKDFWatermarkGenerator`. |
| **Invariant 12** | No single combined ownership score is presented as cryptographic proof. | Verified | Findings report independent statuses for behavioral, extraction, and commitments. |
| **Invariant 13** | System reports digital evidence; does not claim legal contract adjudication. | Verified | Formal evidence bundles contain verifiable cryptographic digests and transcripts. |
| **Invariant 14** | Test vectors are never regenerated merely to make failed verification pass. | Verified | The verifier loads committed test vectors from the immutable session record. |

---

## 4. Mandatory Specification Test Cases (Cases 1–8)

Implemented in `tests/test_master_specification_cases.py` and regression suites:

- **Case 1 (Untouched Protected Design):** Behavioral match ($32/32$), full watermark recovery, similarity = $100.00\%$ (`EXACT`), commitment = `VALID`.
- **Case 2 (Partial Watermark Modification):** Behavior matches, surviving similarity $< 100.00\%$, watermark commitment check fails (`INVALID`).
- **Case 3 (Complete Watermark Removal):** Extraction fails (`FAILED`), similarity = `NOT_AVAILABLE`, commitment = `NOT_VERIFIABLE`.
- **Case 4 (Corrupted Watermark):** Extracted bitstream contains flipped bits, similarity $\neq$ `EXACT`, commitment = `INVALID`.
- **Case 5 (Different Transaction Watermark):** Watermark extracted from a different licensee's design, similarity mismatch against reference, commitment = `INVALID`.
- **Case 6 (Same Behavioral Function, Independent Design):** Behavioral check matches (`MATCH`), but watermark extraction/commitment fails (`NOT_VERIFIABLE`/`INVALID`), demonstrating that behavioral equivalence alone does not prove IP theft.
- **Case 7 (Modified Test Vectors Post-Commitment):** Tampered test vectors fail commitment verification (`INVALID`).
- **Case 8 (Unchanged Test Vectors):** Original committed test vectors pass opening verification (`VALID`).

---

## 5. System Architecture & Pipeline Stages

### Protection Pipeline (15 Stages)
1. `DesignInputStage`: Ingests benchmark DFG and functional unit resource limits.
2. `DesignCanonicalizationStage`: Normalizes node indices and operation tags into deterministic JSON.
3. `DesignHashStage`: Computes the SHA-256 `design_hash`.
4. `SchedulingStage`: Executes resource-constrained deterministic list scheduling.
5. `CIGConstructionStage`: Derives variable lifetimes and builds genuine conflict edges.
6. `TestVectorGenerationStage`: Generates stratified deterministic stimulus vectors from original DFG.
7. `TestVectorCommitmentStage`: Computes Pedersen commitment $C_V = h_V \cdot G + r_V \cdot H$.
8. `TransactionWatermarkGenerationStage`: Derives canonical 256-bit watermark from $D, B, T$ and $K_{tx}$ via HKDF-SHA256.
9. `WatermarkCommitmentStage`: Computes Pedersen commitment $C_W = h_W \cdot G + r_W \cdot H$.
10. `WatermarkConstraintStage`: Injects artificial CIG conflict edges according to the selected bit-length (32, 64, 128, or 256 bits).
11. `RegisterAllocationStage`: Resolves the augmented CIG via vertex coloring to assign hardware registers.
12. `RTLGenerationStage`: Synthesizes synthesizable Verilog modules with register multiplexing and control logic.
13. `BehavioralVerificationStage`: Runs cycle-accurate simulation verifying original vs protected output equivalence.
14. `ReferenceWatermarkExtractionStage`: Recovers embedded constraints from RTL and validates against $C_W$.
15. `ProtectionRecordStage`: Packages the formal immutable `ProtectionRecordSchema`.

### Dispute Pipeline (11 Stages)
1. `ReferenceDesignLoadStage`: Loads protected reference design and commitments.
2. `SuspiciousDesignLoadStage`: Ingests suspicious RTL under audit.
3. `TestVectorLoadVerificationStage`: Validates test vectors against stored commitment $C_V$.
4. `DisputeBehavioralVerificationStage`: Simulates suspicious RTL under committed vectors.
5. `ReferenceWatermarkExtractionDisputeStage`: Extracts reference watermark bitstream from reference RTL.
6. `SuspiciousWatermarkExtractionStage`: Extracts surviving constraints from suspicious RTL.
7. `WatermarkSimilarityStage`: Computes factual forensic bit match ratios.
8. `WatermarkCommitmentVerificationStage`: Validates recovered watermark against $C_W$.
9. `TestVectorCommitmentVerificationStage`: Re-verifies test vector opening.
10. `DisputeVerificationResultStage`: Synthesizes factual findings report.
11. `EvidencePackagingStage`: Compiles cryptographically signed audit evidence bundle.

---

## 6. Multi-Length Watermark Embedding (32, 64, 128, 256 bits)

During Stage 3 (Watermark Embedding), the user can select how many bits of the canonical 256-bit watermark to embed:

| Watermark Length | Pre-Existing Genuine Edges | Newly Added Artificial Edges | Distinct Artificial Edges | CIG Overhead ($E_{art} / 211$) | Register Overhead ($\Delta R$) | Functional Equivalence (32 Vectors) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **32 bits** | 18 | 14 | **14** | **6.64%** | +0 (16 regs) | 32 / 32 Match (100%) |
| **64 bits** | 40 | 24 | **24** | **11.37%** | +0 (16 regs) | 32 / 32 Match (100%) |
| **128 bits** | 78 | 50 (10 duplicates) | **40** | **18.96%** | +0 (16 regs) | 32 / 32 Match (100%) |
| **256 bits** | 151 | 105 (48 duplicates) | **57** | **27.01%** | +0 (16 regs) | 32 / 32 Match (100%) |

### Structural Invariants Across All Lengths
- **Baseline Genuine Conflict Edges:** Exactly 211 edges over 27 variables on IIR Butterworth.
- **Register Allocation:** Preserves minimum register count of 16 ($\Delta R = 0$).
- **Encoding Invariance:** Under 5-rule mode, the secured structural encoding $D_s$ differs from $D_u$ by exactly 6 bits (2.39% difference) at positions `[160, 184, 192, 232, 244, 248]` across all lengths.

---

## 7. Mathematical Foundations & Three-Problem Verification Analysis

The system evaluates three distinct verification problems with strictly separate search spaces ($S_K$), exact guessing probabilities ($P_K = 1/S_K$), and Shannon entropies ($H = \log_2 S_K$):

### Problem 1: Secured Design Verification
- **Target:** 251-bit secured design encoding $D_s$ ($143$b Rules 1–4 $E_4$, $108$b Rule 5).
- **Unrestricted Search Space:** $S_{K,\text{secured}} = 2^{251} \approx 3.6185 \times 10^{75}$
- **Shannon Entropy:** $H_{\text{secured}} = 251.00\text{ bits}$
- **Exact Guessing Probability:** $P_{K,\text{secured}} = 2^{-251} \approx 2.7636 \times 10^{-76}$
- **Fixed-Popcount Theoretical Sub-Model:** Disclosing the 95 set bits reduces the space to $\binom{251}{95} \approx 1.0514 \times 10^{71}$ ($H = 235.93\text{ bits}$, $P \approx 9.5110 \times 10^{-72}$).

### Problem 2: Unsecured Design Verification via CIG Constraint Stripping
- **Target:** Identifying which constraints to remove from the 256 disclosed constraints to recover the original 211-edge CIG without baseline knowledge.
- **Eligible Parity Pairs:** 169 pairs ($78$ Even–Even, $91$ Odd–Odd).
- **Distinct Artificial Edges to Strip:** 57 edges ($33$ Even–Even, $24$ Odd–Odd).
- **Combinatorial Search Space:**
  $$S_{K,\text{unsecured}} = \binom{78}{33} \times \binom{91}{24} \approx 6.5138 \times 10^{43}$$
- **Constraint Selection Entropy:** $H_{\text{unsecured}} = 145.55\text{ bits}$
- **Random Guessing Probability:** $P_{K,\text{unsecured}} \approx 1.5352 \times 10^{-44}$

### Problem 3: Watermark Cryptographic Guessing
- **Target:** Brute-force guessing of the HKDF-SHA256 derived watermark prefix of length $n$.
- **Formula:** $S_{K,\text{watermark}} = 2^n, \quad P = 2^{-n}, \quad H = n\text{ bits}$.
- **Values:**
  - 32b: $S_K = 4.2950 \times 10^9, \quad H = 32.0\text{ bits}, \quad P = 2.3283 \times 10^{-10}$
  - 64b: $S_K = 1.8447 \times 10^{19}, \quad H = 64.0\text{ bits}, \quad P = 5.4210 \times 10^{-20}$
  - 128b: $S_K = 3.4028 \times 10^{38}, \quad H = 128.0\text{ bits}, \quad P = 2.9387 \times 10^{-39}$
  - 256b: $S_K = 1.1579 \times 10^{77}, \quad H = 256.0\text{ bits}, \quad P = 8.6362 \times 10^{-78}$

---

## 8. Built-in Benchmarks

| Benchmark ID | Benchmark Name | Operations / Description | Target Variables |
|---|---|---|:---:|
| `iir_butterworth` | IIR Butterworth Filter | 8-order filter (add: 2, mul: 2, sub: 2) | 27 variables |
| `4point_dct` | 4-Point Discrete Cosine Transform | Matrix multiplication (4 mul, 3 add) | 12 variables |
| `fir_filter` | Finite Impulse Response Filter | 16-tap digital filter (23 operations) | 16 variables |
| `arf_filter` | Auto-Regressive Filter | Lattice/ladder architecture (28 operations) | 28 variables |
| `mesa_benchmark` | MESA Benchmark | Graphics pipeline transformation kernel | 18 variables |
| `conv3x3_kernel` | Conv 3×3 Accelerator | 2D image convolution accelerator | 35 variables |

---

## 9. Repository Structure

```
design ip/
├── hardware_ip_protection/          # Core Python package
│   ├── crypto/                      # Cryptographic layer
│   │   ├── pedersen.py              # NIST P-256 Pedersen commitment engine
│   │   ├── watermark_generator.py   # RFC 5869 HKDF-SHA256 watermark generator
│   │   └── design_hasher.py         # SHA-256 canonical design hasher
│   │
│   ├── hls/                         # High-Level Synthesis & graph transformations
│   │   ├── dfg.py                   # Data-Flow Graph definitions & built-in benchmarks
│   │   ├── scheduler.py             # Resource-constrained list scheduler
│   │   ├── cig.py                   # Compatibility Interference Graph & constraint mapper
│   │   ├── register_allocator.py    # Graph-coloring register allocation
│   │   ├── rtl_generator.py         # Synthesizable Verilog RTL generator
│   │   └── structural_encoder.py    # Structural design encoding (Rules 1-5, 143b & 251b)
│   │
│   ├── verification/                # Simulation and judge verification
│   │   ├── test_vector_generator.py # Stratified pseudorandom test vector generator
│   │   ├── simulator.py             # Cycle-accurate Verilog behavioral simulator
│   │   ├── behavioral_verifier.py   # Output equivalence comparator
│   │   ├── interrogation_engine.py  # Judge question bank (124 questions) & solver
│   │   └── interrogation_analysis.py # Simulation harness for interrogation analysis
│   │
│   ├── forensics/                   # Watermark extraction and forensic analysis
│   │   ├── watermark_extractor.py   # Netlist & timing constraint extractor
│   │   └── watermark_similarity.py  # Factual bit similarity metrics
│   │
│   ├── pipeline/                    # Workflow orchestration & services
│   │   ├── engine.py                # ProtectionPipeline and DisputePipeline runners
│   │   ├── stages.py                # 15 Protection stages + 11 Dispute stages
│   │   ├── transaction_manager.py   # Session state manager for Seller/Buyer/Judge
│   │   ├── interrogation_manager.py # Multi-stage judge interrogation workflow manager
│   │   ├── watermark_strength_analyzer.py # Multi-length CIG experiment runner
│   │   ├── results_analysis_service.py    # Authoritative Sections A-D results generator
│   │   ├── schemas.py               # Formal Pydantic schemas
│   │   └── repository.py            # SQLite persistence layer
│   │
│   └── web/                         # Web presentation layer
│       ├── app.py                   # FastAPI application & REST API endpoints
│       └── static/                  # Responsive web frontend
│           ├── index.html           # 4-profile UI (Seller, Buyer, Verifier, Judge)
│           ├── styles.css           # Modern dark-mode styling
│           └── app.js               # Frontend application logic & visualizers
│
├── tests/                           # Complete test suite (280+ tests)
│   ├── test_crypto.py               # Cryptographic primitives & commitments
│   ├── test_hls.py                  # DFG, scheduler, and CIG tests
│   ├── test_structural_encoding.py  # 4-rule and 5-rule structural encodings
│   ├── test_master_specification_cases.py # 8 mandatory specification test cases
│   ├── test_dispute_scenarios.py    # 6 dispute verification attack presets
│   ├── test_judge_interrogation.py  # Judge question evaluation & reconstruction
│   ├── test_judge_instant_verification.py # Automated instant verification mode
│   ├── test_interrogation_report.py # Judge analysis report & subtab integrity
│   ├── test_final_results_analysis.py     # Authoritative Sections A-D verification
│   ├── test_watermark_strength_and_constraint_analysis.py # Multi-length experiments
│   └── test_buyer_profile_and_embedding_options.py # Buyer profile & length options
│
├── requirements.txt                 # Pinned runtime and development dependencies
└── README.md                        # Master documentation and verification guide
```

---

## 10. Installation & Setup

### Prerequisites
- Python 3.10+ (tested on Python 3.11, 3.12, 3.13)
- pip and virtualenv

### 1. Clone & Setup Environment
```bash
# Clone repository
cd "c:/Users/HP-VICTUS/Documents/design ip"

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Launch the Web Application
```bash
python -m uvicorn hardware_ip_protection.web.app:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser at `http://127.0.0.1:8000`:
- **Seller Profile:** Select benchmark (IIR Butterworth), calculate design encoding, request buyer contribution, generate transaction watermark, choose embedding length (32, 64, 128, or 256 bits), synthesize protected RTL, and inspect CIG topology.
- **Buyer Profile:** View incoming contribution request, inspect biometric feature vector $B$, approve request, and view cryptographic commitments.
- **Verifier Profile:** Test protected designs against 6 dispute attack presets (Untouched, Tampered, Removed, Corrupted, Different TX, Independent Design).
- **Judge Profile:** Reconstruct 251-bit secured encoding via manual question-answering or Instant Verification, strip artificial constraints to recover the original 211-edge CIG, verify watermark derivation, and view the authoritative 4-section Results & Analysis dashboard with SVG charts.

### 3. Run Test Suite
```bash
# Run all tests
pytest -v

# Run Judge & Results Analysis test suites
pytest tests/test_final_results_analysis.py tests/test_watermark_strength_and_constraint_analysis.py tests/test_interrogation_report.py tests/test_judge_instant_verification.py tests/test_buyer_profile_and_embedding_options.py -v
```
