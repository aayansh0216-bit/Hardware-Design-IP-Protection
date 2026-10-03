# Hardware IP Protection V1
## Authoritative Agent Specification

> **Status:** Authoritative V1 architecture
>
> This document supersedes older project notes, diagrams, and prototype flows wherever they conflict with this specification.
>
> The attached research papers are references for individual mechanisms. They are not independent implementation instructions.

---

# 1. Project Purpose

This project is a prototype for **hardware IP protection at the Verilog/RTL level**.

The system combines:

1. Functional/behavioral verification using test vectors.
2. Structural transaction watermarking embedded through CIG constraints during register allocation.
3. Pedersen commitments for precommitting:
   - test-vector sets
   - transaction watermark values
4. Watermark similarity analysis for detecting partial watermark survival/removal.
5. A dispute-verification workflow comparing a legitimate protected design with a suspicious design.

The project is inspired by:

- the Pedersen commitment/test-case protection mechanism in **zk-DeepIP**
- CIG-based structural watermarking from the supplied hardware watermarking papers
- biometric-derived secret generation as a possible future input mechanism

This is **not a full zero-knowledge proof system**.

### Explicitly out of scope

Do not implement:

- zk-SNARK
- zk-STARK
- full zero-knowledge inference
- general-purpose Verilog compiler/parser
- real retinal biometric processing
- gate-level/netlist fingerprinting
- GDSII/physical-layout protection
- LLM-based decision making
- model training
- model fine-tuning
- production legal ownership adjudication
- production authentication/identity infrastructure

---

# 2. AUTHORITATIVE TERMINOLOGY

Several older project versions used the word "fingerprint" for unrelated concepts. This caused confusion.

## Never use a bare `fingerprint`

Use explicit names.

### Design

`original_design`

Design before transaction watermark embedding.

`protected_design`

Design after transaction watermark embedding.

`suspicious_design`

Design being investigated during a dispute.

Do **not** call the protected design a "signed design".

---

## Behavioral terms

`behavioral_verification`

Functional comparison of designs under the same test vectors.

`behavioral_result`

Structured result of behavioral verification.

If a statistical behavioral signature is actually needed internally, use the explicit name:

`behavioral_fingerprint`

Never use just `fingerprint`.

---

## Watermark terms

There is exactly **one V1 watermark concept**:

`transaction_watermark`

This is the cryptographic bitstream generated for one transaction.

`reference_extracted_watermark`

Watermark extracted from the legitimate protected design.

`suspicious_extracted_watermark`

Watermark extracted from the suspicious design.

Do NOT use the old V1 concepts:

- `seller_watermark`
- `buyer_fingerprint`
- `buyer_signature`
- separate seller/buyer watermark bitstreams

---

## Commitment terms

`watermark_commitment`

Pedersen commitment to the transaction watermark.

`watermark_blinding_factor`

Random opening/blinding value for the watermark commitment.

`test_vector_commitment`

Pedersen commitment to the test-vector set.

`test_vector_blinding_factor`

Random opening/blinding value for the test-vector commitment.

---

## Transaction terms

`transaction_record`

Structured metadata identifying the transaction.

It contains:

- `transaction_id`
- `seller_id`
- `buyer_id`
- `design_hash`
- `license_type`

V1 license types:

- `exclusive`
- `non_exclusive`

---

# 3. CORE ARCHITECTURE

There is **ONE transaction watermark**.

It binds:

- seller
- buyer
- design
- transaction
- license type

Conceptually:

```text
transaction_record
        +
transaction credentials/key
        |
        v
transaction_watermark
        |
        +----------------------+
        |                      |
        v                      v
watermark commitment       CIG embedding
                                |
                                v
                         register allocation
                                |
                                v
                         protected_design
```

Do not implement a separate pairing-verification mechanism.

The transaction watermark itself is the transaction binding mechanism.

---

# 4. DESIGN HASH

The design is hashed to create a stable cryptographic identifier for the particular design/version involved in the transaction.

Conceptually:

```text
canonical_design
       |
       v
SHA-256
       |
       v
design_hash
```

The design hash is **not** the watermark.

Do not do:

```text
design -> SHA256 -> watermark
```

Instead:

```text
design
  |
  v
design_hash
  |
  +--------------------------+
  |                          |
  v                          v
transaction_record       provenance
```

The transaction metadata participates in transaction-watermark generation.

The canonical design representation must be deterministic and explicitly defined.

Do not silently hash arbitrary filesystem contents.

---

# 5. TRANSACTION RECORD

Use a structure equivalent to:

```json
{
  "transaction_id": "TX-2026-0041",
  "seller_id": "SELLER-001",
  "buyer_id": "BUYER-017",
  "design_hash": "...",
  "license_type": "exclusive"
}
```

or:

```json
{
  "transaction_id": "TX-2026-0042",
  "seller_id": "SELLER-001",
  "buyer_id": "BUYER-019",
  "design_hash": "...",
  "license_type": "non_exclusive"
}
```

Do not embed plaintext identities directly into hardware.

The hardware contains a derived transaction watermark.

---

# 6. V1 TRANSACTION WATERMARK GENERATION

The cryptographic generation layer must be modular.

V1 may use a symmetric transaction key:

`K_tx`

The authorized transaction parties may possess the credential required to reproduce the same watermark.

Conceptually:

```text
canonical_transaction_record
        +
K_tx
        |
        v
HKDF/HMAC-SHA-256 derivation
        |
        v
256-bit transaction_watermark
```

The exact implementation may use HKDF with a clearly defined context string or an equivalent HMAC-SHA-256 construction.

The critical architectural requirement is:

> The output of this module is a 256-bit `transaction_watermark`.

The embedding system must not depend on how those bits were generated.

Use an abstraction equivalent to:

```python
class TransactionWatermarkGenerator:
    def generate(
        self,
        transaction_record,
        transaction_credentials
    ) -> TransactionWatermark:
        ...
```

---

# 7. FUTURE CRYPTOGRAPHIC UPGRADE

The V1 symmetric mechanism must be replaceable later by an asymmetric/key-agreement mechanism.

A future implementation may use:

```text
seller key pair
+
buyer key pair
        |
        v
ECDH
        |
        v
shared secret
        |
        v
HKDF
        |
        v
same 256-bit transaction watermark
```

This future change must not require changes to:

- CIG construction
- watermark-to-CIG mapping
- register allocation
- RTL generation
- watermark extraction
- watermark similarity calculation
- Pedersen commitment interface

Only the transaction-watermark generation/credential layer should change.

---

# 8. WATERMARK COMMITMENT

The transaction watermark must be committed **before it is used for embedding**.

Let:

`W = transaction_watermark`

First calculate:

```text
h_W = Hash(W)
```

Then:

```text
C_W = h_W * G + r_W * H
```

where:

- `G` and `H` are fixed public generator points
- `r_W` is a fresh random blinding factor

The commitment is stored/published according to the evidence model.

Do not embed `r_W` into the hardware.

The commitment opening information must be protected appropriately.

### Critical ordering

Correct:

```text
generate W
   |
   v
commit W
   |
   v
embed W
```

Incorrect:

```text
generate W
   |
   v
embed W
   |
   v
commit W
```

The latter does not establish prior commitment.

---

# 9. WHAT THE PEDERSEN COMMITMENT DOES AND DOES NOT DO

A commitment does not reveal `W`.

If only:

```text
C_W
```

is available, the verifier cannot directly compare:

```text
W == W_extracted
```

because `W` is not known.

If `W` can independently be reconstructed from transaction credentials, then direct equality can also be checked, but that is an ordinary watermark comparison, not something provided by the commitment.

The cryptographic commitment check is:

Given:

- `W_extracted`
- `r_W`
- `C_W`

calculate:

```text
C'_W = Commit(W_extracted, r_W)
```

and verify:

```text
C'_W == C_W
```

If true, the extracted watermark is consistent with the committed watermark.

This is an **exact cryptographic check**.

There is no concept of a "95% valid commitment."

The result is:

- `VALID`
- `INVALID`
- `NOT_VERIFIABLE`

depending on available evidence.

---

# 10. TEST VECTOR COMMITMENT

Test vectors have their own independent commitment.

Let:

`V = finalized test-vector set`

Then:

```text
h_V = Hash(V)
C_V = h_V * G + r_V * H
```

Commit **before** the vectors are used for the committed verification process.

Later, if the vector set used is available:

```text
C'_V = Commit(V_used, r_V)
```

and:

```text
C'_V == C_V
```

means the vector set is consistent with the commitment.

The commitment does not reveal the test vectors.

---

# 11. TEST VECTOR SECRECY

The design being tested receives test vectors as ordinary plaintext simulation inputs.

The commitment does not make the test vectors secret from the design.

The commitment's role is:

```text
finalize vectors
      |
      v
commit vectors
      |
      v
use vectors
      |
      v
later verify same vectors were used
```

This prevents post-hoc cherry-picking.

---

# 12. TEST VECTOR GENERATION

For small designs:

Use exhaustive test vectors where feasible.

For larger designs:

Use deterministic stratified/smart vectors.

Possible categories:

- all-zero
- all-one
- walking-one
- walking-zero
- boundary values
- carry/overflow-sensitive values
- alternating patterns
- control-input combinations
- design-specific edge cases

Do not claim the neural-network Sample Discrimination Module from zk-DeepIP has a direct hardware equivalent.

Do not use random weighting as a fake substitute.

V1 generation should be deterministic and documented.

Future intelligent/LLM-based generation is outside V1.

---

# 13. CORRECT HARDWARE PIPELINE

The hardware transformation must be:

```text
DFG
  |
  v
Scheduling
  |
  v
CIG construction
  |
  v
transaction watermark -> artificial CIG constraints
  |
  v
Register allocation
  |
  v
Datapath synthesis / RTL generation
  |
  v
protected_design
```

CIG must be constructed from the **scheduled DFG**.

A raw unscheduled DFG does not provide enough information to define
control-step/liveness conflicts.

---

# 14. WATERMARK EMBEDDING LOCATION

V1 embeds the transaction watermark **only through register allocation**.

Do not modify scheduling to encode the watermark.

Do not implement the old buyer-fingerprint scheduling `x/y` mechanism.

The transaction watermark is translated into artificial CIG constraints.

Those constraints affect register binding/allocation.

The embedding should not intentionally change:

- operator type
- operator width
- functional-unit count
- control-step schedule
- algorithmic behavior

The primary structural change is register binding/allocation.

---

# 15. CIG

CIG means Compatibility/Conflict Interaction Graph.

Nodes represent storage variables.

A genuine edge represents a register-sharing conflict.

An artificial edge represents a watermark constraint.

The watermark-to-CIG mapping must be deterministic and documented.

For V1, a binary watermark can be mapped to two deterministic edge-selection rules.

Do not mix the old four-symbol seller-watermark alphabet with the new
transaction-watermark architecture.

Important reproducibility rule:

```text
same transaction watermark
+
same scheduled design
+
same embedding configuration
=
same intended watermark constraints
```

If a requested pair already has an edge, consume the corresponding
watermark bit according to the defined mapping and record that fact.

Do not silently shift the watermark bitstream without recording how
watermark positions map to constraints.

---

# 16. REGISTER ALLOCATION

Register allocation resolves the constrained CIG.

Basic rule:

> No two variables connected by a CIG edge may share a register.

The resulting register-binding information must be sufficient for the
prototype's watermark extractor to recover the transaction watermark.

---

# 17. RTL GENERATION

Generate protected RTL from:

- scheduled DFG
- resource configuration
- register allocation

Security decisions should be complete before datapath synthesis.

The generated RTL should preserve functional behavior.

V1 only needs to support the project's defined RTL subset.

Do not build a complete industrial Verilog compiler.

---

# 18. WATERMARK EXTRACTION

V1 does not implement a general-purpose Verilog parser.

Instead implement:

```python
class TransactionWatermarkExtractor:
    def extract(self, verilog_design, extraction_config):
        ...
```

It must recover structural register-binding information from the Verilog
subset generated by this prototype.

Conceptually:

```text
protected/suspicious Verilog
        |
        v
structural extraction
        |
        v
recovered watermark constraints
        |
        v
extracted transaction watermark
```

The extractor must distinguish:

- `SUCCESS`
- `PARTIAL`
- `FAILED`

Example:

```json
{
  "status": "SUCCESS",
  "bitstream": "...",
  "bit_length": 256,
  "recovered_bits": 256
}
```

Partial:

```json
{
  "status": "PARTIAL",
  "bitstream": "...",
  "bit_length": 256,
  "recovered_bits": 214
}
```

Failure:

```json
{
  "status": "FAILED",
  "reason": "Expected register-binding structure not found"
}
```

Do not equate extraction failure with "watermark absent."

---

# 19. REFERENCE WATERMARK EXTRACTION

During protection verification, extract the watermark from the legitimate
protected design.

Call it:

`reference_extracted_watermark`

Do not call it:

- `prover_watermark`
- `fingerprint_A`
- `seller_fingerprint`

This provides the known structural reference for later similarity analysis.

---

# 20. SUSPICIOUS WATERMARK EXTRACTION

During a dispute:

```text
suspicious_design
        |
        v
TransactionWatermarkExtractor
        |
        v
suspicious_extracted_watermark
```

This is compared against the reference extraction and, where possible,
the committed watermark.

---

# 21. WATERMARK SIMILARITY

Similarity is deliberately separate from Pedersen verification.

If:

- `W_reference`
- `W_suspicious`

are available, calculate a clearly defined structural similarity.

For a binary watermark:

```text
similarity =
matching_positions /
compared_positions
```

Also report:

- total expected bits
- recovered bits
- matching bits
- mismatching bits
- unavailable positions
- similarity ratio

This is **not cryptographic proof**.

Its purpose is to detect:

- exact survival
- partial removal
- corruption
- incidental structural changes
- possible watermark tampering

The implementation must explicitly document how unrecovered positions are
handled.

Do not invent a threshold and call it ownership proof.

If thresholds are used, make them configurable and support their meaning
with experiments.

---

# 22. EXACT COMMITMENT CHECK VS SIMILARITY

These mechanisms are intentionally separate.

### Exact cryptographic check

```text
C'_W == C_W
```

Result:

- `VALID`
- `INVALID`
- `NOT_VERIFIABLE`

### Similarity check

```text
W_reference vs W_suspicious
```

Result includes:

- `matching_bits`
- `mismatching_bits`
- `recovered_bits`
- `similarity`
- `extraction_status`

Example:

```text
Watermark similarity: 93.8%
Watermark commitment: INVALID
```

This is a valid result.

It means most of the watermark structure survived, but the extracted
watermark is not exactly the committed value.

Do not convert 93.8% similarity into cryptographic validity.

---

# 23. ATTACK/TAMPERING CASES

The V1 system should explicitly support analysis of:

1. Untouched watermark.
2. Partially removed watermark.
3. Fully removed watermark.
4. Corrupted/garbled watermark.
5. Watermark extraction failure.
6. Attempted fake watermark.
7. Structural changes caused by re-synthesis.

### Partial removal

Expected:

- similarity may remain high
- commitment normally becomes `INVALID`

### Complete removal

Expected:

- extraction may `FAIL`
- similarity may be `NOT_AVAILABLE`
- commitment may be `NOT_VERIFIABLE`

Do not automatically report:

```text
similarity = 0%
```

when extraction failed.

Failure to extract does not prove zero similarity.

---

# 24. PROTECTION WORKFLOW

The complete protection workflow is:

### Step 1
Receive DFG/design specification and resource configuration.

### Step 2
Generate the original/unwatermarked design representation.

### Step 3
Schedule DFG.

### Step 4
Construct genuine CIG from the scheduled DFG.

### Step 5
Generate test vectors from the original/unwatermarked design.

### Step 6
Finalize the test-vector set.

### Step 7
Commit to the test-vector set BEFORE using it for committed verification.

### Step 8
Create the transaction record.

### Step 9
Generate the transaction watermark.

### Step 10
Commit to the transaction watermark BEFORE embedding it.

### Step 11
Convert watermark bits into artificial CIG constraints.

### Step 12
Perform register allocation.

### Step 13
Generate protected RTL.

### Step 14
Run the SAME committed test vectors on:

- original design
- protected design

### Step 15
Perform behavioral verification.

### Step 16
Extract watermark from protected design.

### Step 17
Verify the protected extracted watermark against the intended
transaction watermark if it can be independently reconstructed.

### Step 18
Verify the watermark commitment using the extracted watermark and
commitment opening.

### Step 19
Package evidence.

### Failure rule

If behavioral verification fails:

Do NOT regenerate/cherry-pick test vectors merely to get a pass.

Reject/fix that protection attempt.

A completely new protection attempt may generate a new test-vector set and
new commitments, but that is a new protection attempt.

---

# 25. PROTECTION RECORD

Create a structured `ProtectionRecord`.

Conceptually:

```json
{
  "protection_id": "...",

  "design": {
    "design_hash": "...",
    "original_design": "...",
    "protected_design": "..."
  },

  "transaction": {
    "transaction_id": "...",
    "seller_id": "...",
    "buyer_id": "...",
    "license_type": "exclusive"
  },

  "test_vectors": {
    "vector_set_id": "...",
    "vector_hash": "...",
    "commitment": "...",
    "commitment_scheme": "pedersen"
  },

  "transaction_watermark": {
    "bit_length": 256,
    "watermark_hash": "...",
    "commitment": "...",
    "commitment_scheme": "pedersen"
  },

  "behavioral_verification": {
    "status": "...",
    "test_count": 0,
    "matching_outputs": 0,
    "mismatching_outputs": 0
  },

  "reference_watermark_extraction": {
    "status": "...",
    "recovered_bits": 0
  },

  "provenance": {
    "timestamps": {},
    "algorithm_versions": {}
  }
}
```

Do not expose private transaction credentials unnecessarily in the normal
evidence bundle.

---

# 26. DISPUTE WORKFLOW

Inputs:

- protected/reference design
- suspicious design
- transaction record
- required transaction credentials/opening information
- test-vector evidence/opening information as required

The original unwatermarked design is not required for the core dispute
workflow if the protected reference design is available.

---

# 27. DISPUTE STEP A: BEHAVIORAL VERIFICATION

Use the same committed test vectors.

Run:

```text
protected_design
        |
        v
reference_outputs


suspicious_design
        |
        v
suspicious_outputs
```

Then compare outputs.

Produce:

`behavioral_result`

For deterministic RTL, exact output comparison is acceptable and often
preferable to blindly reproducing neural-network correlation machinery.

---

# 28. DISPUTE STEP B: WATERMARK EXTRACTION

Extract:

```text
protected_design
        |
        v
reference_extracted_watermark
```

and:

```text
suspicious_design
        |
        v
suspicious_extracted_watermark
```

Then calculate watermark similarity.

---

# 29. DISPUTE STEP C: WATERMARK COMMITMENT VERIFICATION

If the commitment opening is available:

```text
C'_W =
Commit(
    suspicious_extracted_watermark,
    watermark_blinding_factor
)
```

Then check:

```text
C'_W == stored_watermark_commitment
```

If yes:

```text
watermark_commitment_status = VALID
```

Otherwise:

```text
INVALID
```

If the suspicious watermark cannot be sufficiently extracted:

```text
NOT_VERIFIABLE
```

Do not claim that an invalid commitment means the design definitely has
no relationship to the original.

Partial watermark removal is expected to potentially produce:

```text
high similarity
+
invalid exact commitment
```

---

# 30. DISPUTE STEP D: TEST VECTOR COMMITMENT

Where the test vectors are available:

```text
C'_V =
Commit(
    test_vectors_used,
    test_vector_blinding_factor
)
```

Check:

```text
C'_V == stored_test_vector_commitment
```

This verifies that the vector set used in verification corresponds to the
precommitted vector set.

The commitment itself does not reveal the vectors.

---

# 31. DISPUTE RESULT

Do NOT produce a single arbitrary "ownership score."

Produce separate factual results.

Example:

```json
{
  "behavioral_verification": {
    "status": "MATCH"
  },

  "watermark_analysis": {
    "reference_extraction": {
      "status": "SUCCESS"
    },

    "suspicious_extraction": {
      "status": "PARTIAL"
    },

    "similarity": {
      "matching_bits": 238,
      "mismatching_bits": 3,
      "recovered_bits": 241,
      "similarity": 0.9876
    },

    "commitment": {
      "status": "INVALID"
    }
  },

  "test_vector_commitment": {
    "status": "VALID"
  }
}
```

The system reports evidence.

It does not make a legal ownership judgment.

---

# 32. WHAT EACH MECHANISM ANSWERS

### Behavioral verification

Question:

> Do these designs produce the same/similar observed behavior under the
> selected test vectors?

It does not independently establish ownership.

### Watermark similarity

Question:

> How much of the embedded structural watermark appears to have survived
> in the suspicious design?

It is structural/forensic evidence.

It is not cryptographic proof.

### Watermark commitment

Question:

> Is the extracted watermark exactly consistent with the previously
> committed watermark?

It is an exact cryptographic check.

### Test-vector commitment

Question:

> Is the vector set used for verification consistent with the vector set
> committed before verification?

It protects against post-hoc test-vector selection.

### Transaction record

Question:

> What transaction metadata does the generated watermark correspond to?

It provides the transaction context.

---

# 33. CRYPTOGRAPHIC LAYER BOUNDARY

Keep cryptographic generation independent from hardware embedding.

```text
TransactionWatermarkGenerator
        |
        v
256-bit transaction_watermark
        |
        v
WatermarkCommitment
        |
        v
CIG embedding
        |
        v
Register allocation
```

The future cryptographic implementation can change without changing the
hardware embedding system.

---

# 34. SOFTWARE ARCHITECTURE

Maintain a stage-based architecture.

Every stage should have:

- explicit input schema
- explicit output schema
- deterministic configuration
- version identifier
- validation
- cache key

Use Pydantic models or equivalent strongly defined schemas.

Content-hash-based caching is preferred.

A cache key should depend on:

- stage identifier
- stage implementation/configuration version
- relevant input hash

Do not use timestamps as the only cache invalidation mechanism.

A stage contract mismatch should fail loudly and identify the stage.

---

# 35. RECOMMENDED PROTECTION STAGES

1. `DesignInputStage`
2. `DesignCanonicalizationStage`
3. `DesignHashStage`
4. `SchedulingStage`
5. `CIGConstructionStage`
6. `TestVectorGenerationStage`
7. `TestVectorCommitmentStage`
8. `TransactionWatermarkGenerationStage`
9. `WatermarkCommitmentStage`
10. `WatermarkConstraintStage`
11. `RegisterAllocationStage`
12. `RTLGenerationStage`
13. `BehavioralVerificationStage`
14. `ReferenceWatermarkExtractionStage`
15. `ProtectionRecordStage`

Names may be adapted to existing code conventions, but responsibilities
must remain distinct.

---

# 36. RECOMMENDED DISPUTE STAGES

1. `ReferenceDesignLoadStage`
2. `SuspiciousDesignLoadStage`
3. `TestVectorLoadVerificationStage`
4. `BehavioralVerificationStage`
5. `ReferenceWatermarkExtractionStage`
6. `SuspiciousWatermarkExtractionStage`
7. `WatermarkSimilarityStage`
8. `WatermarkCommitmentVerificationStage`
9. `TestVectorCommitmentVerificationStage`
10. `DisputeVerificationResultStage`
11. `EvidencePackagingStage`

---

# 37. V1 CRYPTOGRAPHY

Implement actual Pedersen commitment functionality.

Document:

- curve
- generator points
- scalar representation
- hash-to-scalar procedure
- random blinding generation
- commitment serialization
- opening serialization

Do not casually treat a raw SHA-256 digest as an elliptic-curve scalar
without defining the conversion.

Use an appropriate hash-to-scalar/reduction procedure.

Do not invent cryptographic primitives.

---

# 38. SECURITY BOUNDARIES

The prototype is not a complete production transaction authority.

If V1 uses a trusted transaction service to generate `K_tx` and maintain
transaction records, explicitly document that trust assumption.

The watermark demonstrates consistency with the transaction credentials
and committed transaction evidence.

Do NOT claim:

- that a watermark alone proves legal ownership
- that a Pedersen commitment alone proves legal ownership
- that the prototype proves the legal validity of a real-world contract

---

# 39. BIOMETRIC PROCESSING

Real retinal biometric acquisition and feature extraction are OUT OF
SCOPE for V1.

If deterministic placeholder generation is needed, use a clearly
labeled deterministic cryptographic test credential/seed.

Do not call the placeholder "real biometric processing."

Keep the transaction-watermark generator interface independent so a real
biometric credential/fuzzy-extractor layer could be inserted later.

Do not expose raw biometric data as part of the normal transaction record.

---

# 40. UI

Simplify the UI.

Do NOT use the old three-tab architecture involving:

- Secure design
- Suspicious design
- Pairing verification

because pairing verification is no longer a separate V1 mechanism.

Use two primary workflows.

## TAB 1: Protect Design

Inputs:

- DFG/design specification
- resource configuration
- transaction information
- transaction credentials

Outputs:

- protected design
- protection ID
- commitment/evidence information
- behavioral verification result
- reference watermark extraction result

## TAB 2: Verify Dispute

Inputs:

- protected/reference design
- suspicious design
- transaction evidence/credentials
- test-vector evidence as required

Outputs:

- behavioral verification
- watermark extraction status
- watermark similarity
- watermark commitment status
- test-vector commitment status
- structured evidence report

Do not display:

"Ownership: 98%"

Instead display factual evidence.

---

# 41. IMPLEMENTATION SCOPE

## Implement

- DFG handling
- scheduling
- CIG construction
- transaction watermark generation
- transaction watermark commitment
- watermark-to-CIG constraints
- register allocation
- protected RTL generation
- deterministic test-vector generation
- test-vector commitment
- simulation
- behavioral comparison
- watermark extraction
- partial watermark extraction status
- watermark similarity
- exact Pedersen commitment verification
- dispute verification
- structured evidence
- stage contracts
- deterministic caching

## Stub/placeholder

- real biometric processing
- production-grade transaction authority
- advanced synthesis
- general-purpose Verilog parsing

## Exclude

- zk-SNARK
- zk-STARK
- LLM
- model training
- fine-tuning
- full retinal processing
- GDSII
- gate-level fingerprinting
- production authentication infrastructure
- production legal ownership adjudication
- separate seller watermark + buyer fingerprint architecture
- old scheduling-stage buyer signature mechanism

---

# 42. REFACTORING REQUIREMENT

Before adding new features, inspect the existing codebase.

Identify occurrences of obsolete concepts such as:

- `buyer_signature`
- `buyer_fingerprint`
- `seller_watermark`
- bare `fingerprint`
- `signed_design`
- `pairing_verification`
- separate seller/buyer bitstreams
- watermark embedded during scheduling
- comparison of an unknown committed watermark directly against an
  extracted watermark

Create a refactoring report identifying:

1. Current modules/classes.
2. Obsolete terminology.
3. Obsolete architecture.
4. Reusable components.
5. Components requiring modification.
6. Components that should be removed.
7. Missing components.
8. Data-flow/schema inconsistencies.
9. Incorrect cryptographic assumptions.
10. UI flows conflicting with this specification.

Then refactor toward this architecture.

Do not simply create a second implementation alongside the old one.

---

# 43. REQUIRED INVARIANTS

Before considering V1 complete, verify:

### Invariant 1
There is exactly ONE V1 transaction watermark.

### Invariant 2
The transaction watermark binds:

seller + buyer + design + transaction + license type.

### Invariant 3
The watermark is embedded only at register allocation.

### Invariant 4
Test vectors are generated from the original/unwatermarked design.

### Invariant 5
Test vectors are committed before committed verification.

### Invariant 6
The transaction watermark is committed before embedding.

### Invariant 7
Pedersen commitment verification is exact.

### Invariant 8
Watermark similarity is separate from cryptographic commitment
verification.

### Invariant 9
Extraction failure is not automatically equivalent to zero similarity.

### Invariant 10
No ambiguous bare `fingerprint` identifiers are used.

### Invariant 11
The watermark generation algorithm can later be replaced by an
asymmetric/key-agreement mechanism without changing the embedding layer.

### Invariant 12
No single combined ownership score is presented as cryptographic proof.

### Invariant 13
The system does not claim that a watermark proves legal transaction
validity.

### Invariant 14
Test vectors are never regenerated merely to make failed functional
verification pass.

---

# 44. REQUIRED TEST CASES

## Case 1: Untouched protected design

Expected:

- behavioral verification matches
- reference watermark extraction succeeds
- watermark similarity is exact
- watermark commitment is valid

## Case 2: Partial watermark modification

Expected:

- behavior may still match
- watermark similarity < 100%
- watermark commitment is invalid

## Case 3: Complete watermark removal

Expected:

- extraction may fail
- similarity may be unavailable
- commitment may be not verifiable/invalid depending on evidence

## Case 4: Corrupted watermark

Expected:

- partial extraction or extraction failure
- non-perfect similarity
- commitment invalid

## Case 5: Different transaction watermark

Expected:

- watermark mismatch
- commitment invalid

## Case 6: Same behavioral function, independently generated design

Expected:

- behavior may match
- transaction watermark need not match

This demonstrates that behavioral evidence and structural watermark
evidence are distinct.

## Case 7: Modified test-vector set after commitment

Expected:

- test-vector commitment verification fails

## Case 8: Same test vectors as committed

Expected:

- test-vector commitment verification succeeds

---

# 45. FINAL ARCHITECTURE

## Protection

```text
                    ORIGINAL DESIGN
                           |
                           v
                          DFG
                           |
                           v
                      Scheduling
                           |
                           v
                          CIG
                           |
             +-------------+-------------+
             |                           |
             v                           v
       Test-vector generation      Transaction record
             |                           |
             v                           v
     Test-vector commitment       Transaction watermark
                                         |
                                         v
                                Watermark commitment
             |                           |
             +-------------+-------------+
                           |
                           v
                  Watermark -> CIG constraints
                           |
                           v
                  Register allocation
                           |
                           v
                    Protected RTL
                           |
                  +--------+--------+
                  |                 |
                  v                 v
        Behavioral verification   Watermark extraction
                  |                 |
                  +--------+--------+
                           |
                           v
                  Protection record
```

## Dispute

```text
Protected/reference RTL
        |
        v
Reference watermark extraction
        |
        v
W_reference


Suspicious RTL
        |
        v
Suspicious watermark extraction
        |
        v
W_suspicious
        |
        +---------------------------+
        |                           |
        v                           v
Watermark similarity       Commitment verification
                                    |
                                    v
                              C'_W == C_W?
                                    |
                                    +----------+
                                               |
                                               v
                                      Dispute evidence
```

Separately:

```text
Committed test vectors
        |
        +-------------------+
        |                   |
        v                   v
Protected design     Suspicious design
        |                   |
        v                   v
Reference outputs    Suspicious outputs
        |                   |
        +---------+---------+
                  |
                  v
        Behavioral verification
```

And separately:

```text
test vectors used
       +
test-vector opening
       |
       v
recompute C'_V
       |
       v
C'_V == C_V?
```

---

# 46. ONE-SENTENCE PROJECT DEFINITION

The project protects hardware IP by embedding a transaction-specific
cryptographic watermark into register allocation, while Pedersen
commitments provide prior binding of the watermark and test vectors, and
behavioral/structural similarity provide separate evidence during
disputes.

---

# 47. FINAL INSTRUCTION TO THE AGENT

Do not begin by blindly implementing the old architecture.

First inspect the existing repository and map its current components to
this specification.

Produce the refactoring report described above.

Then implement the architecture in stages.

After every major stage:

1. Run tests.
2. Validate schemas.
3. Check terminology.
4. Check cryptographic assumptions.
5. Confirm that downstream stages still receive the expected contracts.

Do not silently resolve architectural ambiguity by inventing a new
mechanism.

When an implementation detail is unspecified, preserve the abstraction
boundary and document the decision rather than coupling future components
to an arbitrary implementation.

The central V1 principle is:

> One transaction -> one transaction watermark -> one watermark commitment,
> with behavioral verification, watermark similarity, and cryptographic
> commitment verification kept as separate evidence mechanisms.
