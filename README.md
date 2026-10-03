# Hardware IP Protection V1

A research prototype for hardware IP protection at the Verilog/RTL level.

The system embeds a transaction-specific cryptographic watermark into register
allocation, uses Pedersen commitments to bind the watermark and test vectors
before embedding, and provides a dispute-verification workflow for forensic
analysis of suspicious designs.

> **Status:** Research prototype. Not intended for production use, legal
> adjudication, or production authentication infrastructure.

---

## What It Does

Given a hardware benchmark (expressed as a Data-Flow Graph), the system:

1. **Generates test vectors** from the original unwatermarked design and
   commits them via Pedersen commitment (`C_V`) over NIST P-256.
2. **Derives a transaction watermark** (256-bit, via HKDF-HMAC-SHA256) from
   the transaction record (`seller_id`, `buyer_id`, `design_hash`,
   `transaction_id`, `license_type`) and a symmetric transaction key `K_tx`,
   and commits it (`C_W`) before embedding.
3. **Embeds the watermark structurally** by injecting artificial
   Compatibility/Conflict Interaction Graph (CIG) constraints that force
   specific register-allocation decisions, without changing the schedule.
4. **Generates synthesizable Verilog** for both the original and protected
   designs and verifies behavioral equivalence under the committed test vectors.
5. **Provides dispute verification** — given a suspicious design and the
   original protection record, it extracts surviving watermark constraints,
   computes structural similarity, and verifies Pedersen commitments.

The system explicitly does **not** implement zk-SNARKs, gate-level netlist
fingerprinting, production authentication, or legal ownership adjudication.

---

## Repository Structure

```
hardware_ip_protection/      # Main Python package
│
├── crypto/                  # Cryptographic primitives
│   ├── pedersen.py          # Pedersen commitment engine (NIST P-256)
│   ├── watermark_generator.py  # HKDF-based transaction watermark derivation
│   └── design_hasher.py     # SHA-256 design hashing
│
├── hls/                     # High-Level Synthesis layer
│   ├── dfg.py               # Data-Flow Graph representation + built-in benchmarks
│   ├── scheduler.py         # Deterministic list scheduler
│   ├── cig.py               # CIG construction, watermark constraint injection
│   ├── register_allocator.py # Graph-coloring register allocator
│   └── rtl_generator.py     # Synthesizable Verilog generator
│
├── verification/            # Behavioral verification
│   ├── test_vector_generator.py  # Stratified deterministic test vector generation
│   ├── simulator.py         # Cycle-accurate RTL simulator
│   └── behavioral_verifier.py   # Reference vs suspicious RTL comparison
│
├── forensics/               # Forensic watermark analysis
│   ├── watermark_extractor.py   # Constraint extraction from protected RTL
│   └── watermark_similarity.py  # Structural similarity calculator
│
├── pipeline/                # End-to-end orchestration
│   ├── stages.py            # All 15 protection + 11 dispute pipeline stages
│   ├── engine.py            # ProtectionPipeline and DisputePipeline runners
│   ├── schemas.py           # Pydantic schemas (records, evidence bundles)
│   └── repository.py        # SQLite persistence layer (protection records)
│
└── web/                     # Interactive web application
    ├── app.py               # FastAPI server (REST API + static file serving)
    └── static/              # Frontend (HTML, CSS, JavaScript)
        ├── index.html
        ├── styles.css
        └── app.js

tests/                       # Test suite
├── test_crypto.py
├── test_hls.py
├── test_v1_canonical_pipeline.py
├── test_master_specification_cases.py
├── test_dispute_scenarios.py
├── test_corrective_v1_requirements.py
├── test_v1_refinement_pass.py
├── test_scenarios_live.py
└── test_live_web_verification.py

markdown.md                  # Authoritative V1 specification and terminology
newM.md                      # System architecture and verification guide
```

---

## Built-in Benchmarks

The following DFG benchmarks are included and ready to protect:

| ID | Name | Notes |
|----|------|-------|
| `4point_dct` | 4-Point DCT | |
| `fir_filter` | FIR Filter | |
| `arf_filter` | ARF Filter | |
| `mesa_benchmark` | MESA Benchmark | |
| `conv3x3_kernel` | Conv 3×3 Kernel | |

---

## Dependencies

There is currently no `requirements.txt` or `pyproject.toml` in the repository.
The project uses at minimum:

- `fastapi`
- `uvicorn`
- `pydantic` (v2)
- Python standard library: `sqlite3`, `hashlib`, `hmac`, `secrets`, `json`

Install dependencies manually or generate a requirements file from your
virtual environment:

```bash
pip install fastapi uvicorn pydantic
```

> **Note:** Dependency pinning has not been done. The project owner should
> run `pip freeze > requirements.txt` after verifying a working environment.

---

## Setup

```bash
# Clone the repository
git clone <repository-url>
cd "design ip"

# Create and activate a virtual environment (recommended)
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install fastapi uvicorn pydantic
```

---

## Running the Web Application

```bash
python -m uvicorn hardware_ip_protection.web.app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in your browser.

- **Tab 1 — Protect Design:** Select a benchmark, enter transaction metadata
  and a transaction key (`K_tx`), then run the protection pipeline to generate
  watermarked RTL with interactive CIG and register timing visualizations.
- **Tab 2 — Verify Dispute:** Load the protection result from Tab 1, select an
  attack preset (Untouched, Partial Tampering, Complete Removal, Corrupted,
  Different Transaction, or Independent Design), and run forensic dispute
  verification.

---

## Running the Tests

```bash
pytest -v
```

Key test files:

| File | Coverage |
|------|----------|
| `test_v1_canonical_pipeline.py` | Full 15-stage protection pipeline |
| `test_master_specification_cases.py` | 8 mandatory specification invariant cases |
| `test_dispute_scenarios.py` | Dispute verification under all attack scenarios |
| `test_corrective_v1_requirements.py` | Detailed V1 requirement correctness |
| `test_v1_refinement_pass.py` | Refinement and edge-case coverage |
| `test_crypto.py` | Pedersen commitment and watermark generation |
| `test_hls.py` | DFG, scheduler, CIG, and register allocator |
| `test_live_web_verification.py` | Web API endpoint integration (requires running server) |
| `test_scenarios_live.py` | Live end-to-end pipeline scenarios |

---

## Database

The application persists protection records to a local SQLite database:

```
hardware_ip_protection/protection_records.db
```

**This file is generated automatically at runtime.** On a fresh clone, the
database does not exist; when the application or pipeline is first run,
`ProtectionRepository` creates the file and all required tables automatically
(`CREATE TABLE IF NOT EXISTS`). No manual setup or seed data is required.

The database file is listed in `.gitignore` and is not committed to the
repository. It accumulates records as you run the protection pipeline.

The dispute pipeline reads protection data from the in-memory session (not
from the database), so the dispute workflow functions correctly even on a
fresh install with no prior database records.

---

## Documentation

- [`markdown.md`](markdown.md) — Authoritative V1 specification, terminology,
  protocol invariants (Invariants 1–14), and implementation rules.
- [`newM.md`](newM.md) — System architecture overview, pipeline stage
  descriptions, specification test cases (Cases 1–8), and run instructions.

---

## Specification Invariants

The implementation enforces 14 formally specified invariants. See
[`newM.md`](newM.md) for the complete invariant table and verification status.

Key invariants:

- Exactly **one** watermark per transaction.
- Watermark binds: `seller_id + buyer_id + design_hash + transaction_id + license_type`.
- Watermark is embedded **only** at register allocation (scheduling is untouched).
- Test vectors are generated from the **original unwatermarked** design.
- Watermark similarity is **structural/forensic**, separate from cryptographic verification.
- System reports **digital evidence** only; does not claim legal adjudication.

---

## Known Limitations / Scope

- **Research prototype only.** Not for production or legal use.
- RTL is synthesized from a limited set of built-in DFG benchmarks.
- No general-purpose Verilog parser; protection is applied at the HLS stage.
- No gate-level, netlist-level, or GDSII/physical-layout protection.
- No zero-knowledge proof system (zk-SNARK/zk-STARK).
- No dependency pinning (`requirements.txt` not yet present).
- No license file currently present; see project owner to determine licensing.
