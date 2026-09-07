# ECDAT — CONTRACT.md

**Status: LOCKED after kickoff. Do not change field names without asking the whole team.**
**Owner: Person B (owns M4, M5, M6 — the modules that produce and consume these shapes).**

This file exists so all three people can write code against the same JSON shapes
from hour zero, without waiting for anyone else's real code to exist. Pulled
directly from Section 6 of the design doc — nothing invented here.

There are exactly two handoff boundaries in this project. This file defines both.

---

## 1. Raw finding — A → B
*(emitted by M1, M2, M3 — same shape regardless of which scanner produced it)*

```json
{
  "sourceModule": "M1_source_scanner",
  "scanTargetId": "scan_2026_09_07_abc123",
  "filePath": "src/auth/token_signer.py",
  "lineNumber": 42,
  "language": "python",
  "library": "pyca/cryptography",
  "rawSignal": "hashes.SHA1()",
  "detectedPrimitive": "SHA1",
  "primitiveCategory": "hash",
  "keySizeBits": null,
  "mode": null,
  "confidence": 0.95,
  "detectionTier": "ast"
}
```

**Rules for A (M1/M2/M3):**
- Every finding — no matter which scanner produced it — must have every field above present. Use `null` for fields that don't apply (e.g. `keySizeBits` for a hash).
- `sourceModule` must be one of `"M1_source_scanner"`, `"M2_dep_binary_scanner"`, `"M3_container_config_scanner"` — B's M4 uses this to know how to interpret `rawSignal`.
- `detectionTier` is `"regex"` or `"ast"` for M1; use whatever's equivalent for M2/M3 (e.g. `"manifest"`, `"cert-parse"`) — just be consistent and tell B what strings you're using.
- Output a **list** of these objects, even if empty (`[]`), never `null` or a missing key.

---

## 2. Canonical CBOM asset — B → C
*(output of M4/M5/M6 — this is what M7 stores, and what M8/M9 both consume)*

```json
{
  "bom-ref": "crypto-asset-0af3e9",
  "type": "cryptographic-asset",
  "name": "SHA1",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": {
      "primitive": "hash",
      "parameterSetIdentifier": "SHA-1",
      "executionEnvironment": "software-plain-ram",
      "implementationPlatform": "generic",
      "cryptoFunctions": ["digest"],
      "classicalSecurityLevel": 80,
      "nistQuantumSecurityLevel": 0
    },
    "oid": "1.3.14.3.2.26"
  },
  "occurrences": [
    { "location": "src/auth/token_signer.py", "line": 42 }
  ],
  "ecdatEnrichment": {
    "quantumVulnerable": true,
    "vulnerabilityReason": "classically broken (collision attacks); also loses Grover margin",
    "businessCriticality": "High",
    "dataClassification": "Authentication-Token",
    "exposure": "external-facing",
    "estimatedShelfLifeYears": 2,
    "estimatedMigrationEffortYears": 0.25,
    "moscaX": 2,
    "moscaY": 0.25,
    "moscaZ": 8,
    "moscaR": 1.34,
    "moscaRiskTier": "Critical",
    "recommendedReplacement": "SHA-384 or SHA3-384",
    "referenceStandard": "N/A (deprecate; not a PQC concern, a classical-strength concern)"
  }
}
```

**Rules for B (M4/M5/M6):**
- `bom-ref`, `type`, `name`, `cryptoProperties`, `occurrences` are the CycloneDX-standard part — don't rename these, C's M9 exports this block close to verbatim as the CBOM JSON.
- `ecdatEnrichment` is B's own extension bag. **M5 must write `moscaX`, `moscaY`, `moscaZ`, `moscaR`, `moscaRiskTier`** into it (not just the tier — C's M8 heatmap needs the raw X/Y/Z/r values to recompute `r` client-side when the Z slider moves, per Section 7/M8's design).
- `moscaRiskTier` is one of `"Critical" | "High" | "Medium" | "Low"` — exact casing, C's frontend will likely switch/color on this string directly.
- M6 must write `recommendedReplacement` and `referenceStandard` into the same `ecdatEnrichment` block — don't create a separate object for it, C expects one flat enrichment bag per asset.
- Output a **list** of these objects (one CBOM document = array of assets), even if empty.

---

## 3. What "locked" means

- Once everyone has read this file once at kickoff, nobody edits it solo. If a field genuinely needs to change mid-day, say so out loud / in the group chat first — B has final say since B's modules are the ones on both sides of the wire.
- If you (A or C) discover the real shape needs a field this file doesn't have, don't just add it and push — flag it to B, B updates this file, then everyone re-pulls before continuing.
