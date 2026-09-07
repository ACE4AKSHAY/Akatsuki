# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool
### SIH 2026 · Design & Technical Document
**Version 1.0 · Prepared for team kickoff**

---

## Table of Contents
1. Executive Summary
2. Problem Restatement & Scope Boundaries
3. Key Concepts You Must Get Right
4. Prior Art — What Already Exists (and What We Reuse vs. Build)
5. High-Level Architecture
6. Core Data Model (CBOM Schema)
7. Module-by-Module Design (M1–M9)
8. Cryptographic Detection Taxonomy
9. Quantum Risk Scoring Model (Mosca's Algorithm, Operationalized)
10. PQC / Hybrid Recommendation Mapping
11. Technology Stack Summary
12. Data Flow
13. Team Structure & Role Allocation
14. 7-Day Sprint Plan
15. Demo Script & Success Metrics
16. Risks & Mitigations
17. Roadmap Beyond the Hackathon
18. Appendix — Sample CBOM JSON, Test Datasets, Detection Rule Pseudocode
19. Development Kickoff Prompts (one per module)

---

## 1. Executive Summary

ECDAT discovers, inventories, and risk-rates every cryptographic artefact an organization depends on — algorithms, keys, certificates, protocols, libraries, hardware modules, and cloud KMS references — across source code, binaries/dependencies, and container/infrastructure configuration. It then applies a quantitative, Mosca's-algorithm-based risk model to tell an organization **what to fix first**, and a recommendation engine to tell them **what to replace it with** (NIST PQC standards or hybrid classical+PQC schemes), before it ships everything into a standards-compliant **Cryptography Bill of Materials (CBOM)** and an interactive dashboard.

The output format is not invented by us — it is the **CycloneDX 1.6 CBOM** standard (an OWASP/Ecma-International standard, ECMA-424), developed originally by IBM Research and now stewarded by the **Post-Quantum Cryptography Alliance (PQCA)** under the Linux Foundation. Building to this standard means our tool's output is interoperable with existing SBOM/CBOM tooling, and it gives judges an easy "yes, this is the real industry format" signal.

This document gives the team: a scoped architecture, a precise data model, a 9-module build plan, the actual risk-scoring math, a realistic 7-day sprint calendar for a 6-person team, and copy-paste-ready prompts to kick off each module's implementation.

---

## 2. Problem Restatement & Scope Boundaries

The problem statement asks for four things: (i) discovery/cataloguing of crypto artefacts, (ii) quantum risk assessment, (iii) classification via structured frameworks (Mosca's algorithm), and (iv) recommendation of PQC/hybrid alternatives — delivered as a scanning tool + analytics + interactive GUI.

A full enterprise-grade version of this (deep binary reverse-engineering, live cloud KMS integration, agent-based network scanning of thousands of endpoints, HSM firmware inspection) is a multi-quarter engineering program, not a one-week build. **Scope deliberately, and say so explicitly in your pitch** — judges respect a clearly-bounded MVP with an honest roadmap far more than an over-promised, half-working "does everything" demo.

### In scope for the hackathon MVP
- Static scanning of **source code repositories** for 4–5 languages (Python, Java, JavaScript/TypeScript, Go — C/C++ as stretch).
- Static scanning of **dependency manifests/lockfiles** (requirements.txt, pom.xml, package.json, go.mod) cross-referenced against a curated crypto-library registry.
- Lightweight **binary inspection** (symbol/string extraction — not full disassembly) for compiled artefacts.
- **Container image** inspection (installed packages via layer extraction) and **config-file** scanning (TLS/webserver configs, Dockerfiles, Kubernetes manifests, IaC files) and **X.509 certificate** parsing.
- CBOM generation compliant with **CycloneDX 1.6** `cryptographic-asset` components.
- Quantum risk scoring using **Mosca's inequality** with a configurable threat-timeline assumption.
- A rules-based **PQC/hybrid recommendation engine** mapped to **FIPS 203/204/205** (and noting FIPS 206 / HQC as track-record items).
- An interactive **web dashboard** (inventory table, risk heatmap, drill-down, exportable report).
- Exports: CBOM JSON, PDF summary report, CSV asset list.

### Explicitly out of scope for the MVP (call these out as "Roadmap" in the pitch)
- Live authenticated scanning of production cloud accounts (AWS/Azure/GCP KMS APIs) — security-sensitive and unnecessary for a demo; static IaC scanning covers the same intent safely.
- Full binary lifting/disassembly (Ghidra/angr-grade reverse engineering) for statically-linked, stripped crypto.
- Network/TLS-handshake live scanning of running endpoints.
- Multi-tenant enterprise auth/RBAC, SSO.
- CI/CD pipeline plugin (GitHub Action/SARIF) — trivial to add later, not essential to prove the concept.

---

## 3. Key Concepts You Must Get Right

Every teammate should be able to explain these in one sentence to a judge — this is where most teams lose marks in Q&A.

| Concept | One-line explanation |
|---|---|
| **CBOM** | A structured, machine-readable inventory of cryptographic assets (algorithms, keys, certs, protocols) — the "SBOM, but for cryptography." Standardized as part of CycloneDX 1.6 (2024), published as Ecma standard ECMA-424. |
| **Harvest Now, Decrypt Later (HNDL)** | Adversaries record encrypted traffic *today* and decrypt it once a cryptographically-relevant quantum computer (CRQC) exists. This is why "no CRQC exists yet" is not a reason to delay — data with a long confidentiality shelf-life is already at risk. |
| **Shor's algorithm** | The reason RSA, DSA, Diffie-Hellman, and elliptic-curve (ECDSA/ECDH/EdDSA) cryptography are considered *broken* once a CRQC exists — it solves integer factorization and discrete log in polynomial time. |
| **Grover's algorithm** | Only *halves* the effective security margin of symmetric primitives (AES, SHA-2/3). It does **not** break AES-256 or SHA-384+; it does meaningfully weaken AES-128 and SHA-256, which is why 256-bit/384-bit+ variants are the PQC-era recommendation for symmetric crypto. |
| **Crypto-agility** | The property of a system that lets you swap cryptographic algorithms without re-architecting the system. A CBOM is the prerequisite artefact for measuring and improving crypto-agility. |
| **Mosca's inequality** | The risk-timing formula this project must implement (Section 9). |
| **PQC / Hybrid** | Post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA) can be deployed *alone* or in **hybrid mode** (combined with a classical algorithm, e.g. X25519 + ML-KEM-768) so that a break in either scheme alone doesn't compromise the session. Hybrid is the current industry-recommended transition strategy (e.g., Chrome/Firefox already ship the `X25519MLKEM768` hybrid TLS 1.3 group by default). |

---

## 4. Prior Art — What Already Exists (and What We Reuse vs. Build)

Do **not** reinvent the CBOM schema — that credibility win is free. Reference and align with:

- **CycloneDX 1.6 "Cryptographic Bill of Materials"** — the schema you should target for your export format. Component type `cryptographic-asset`, with `cryptoProperties.assetType` values of `algorithm`, `certificate`, `protocol`, `related-crypto-material`. Also standardized as **ECMA-424**.
- **PQCA CBOMkit family** (donated by IBM Research to the Post-Quantum Cryptography Alliance, a Linux Foundation project): `sonar-cryptography` (AST-based detection engine for Java/Python/Go as a SonarQube plugin), `cbomkit-theia` (detects certs/keys/secrets inside container images and directories — explicitly *not* source-code scanning), `cbomkit-lib`/`cbomkit-action`/`cbomkit` (aggregation service + viewer).

**Why we don't just deploy CBOMkit wholesale for the hackathon:** it's built as a SonarQube plugin — spinning up SonarQube infra, learning its plugin SDK, and getting a demo-stable install in a week is a bigger risk than writing our own lightweight, purpose-built scanner. **Our differentiated value-add over CBOMkit** (worth stating explicitly in the pitch) is:
1. An integrated, configurable **quantitative Mosca risk score** (business criticality + exposure + data-sensitivity weighted) — CBOMkit inventories, it does not score/prioritize the way we do.
2. A **recommendation engine** that goes beyond "this is quantum-vulnerable" to "replace with X, here's the latency/size/cost trade-off, here's the compliance target it satisfies."
3. **Binary + container + IaC coverage in one unified pipeline**, feeding one dashboard.
4. An interactive **what-if risk simulator** in the UI (drag the "CRQC arrives in ___ years" slider and watch the heatmap recompute live) — a strong, cheap-to-build demo moment.

We *do* reuse: the CycloneDX schema and vocabulary, the general "AST > regex for precision" lesson from `sonar-cryptography`, and open dependency-scanning tools (Syft/Grype/Trivy concepts) for container layer inspection where time allows.

---

## 5. High-Level Architecture

```
                        ┌───────────────────────────────────────────┐
                        │              INGESTION LAYER               │
                        │  (Git URL / ZIP upload / image ref / path) │
                        └───────────────────────┬───────────────────┘
                                                 │
            ┌────────────────────────────────────┼────────────────────────────────────┐
            ▼                                    ▼                                    ▼
 ┌─────────────────────┐          ┌──────────────────────────┐         ┌──────────────────────────┐
 │  M1  Source Code     │          │  M2  Binary / Dependency  │         │  M3  Container / Infra    │
 │  Repo Scanner        │          │  & Library Scanner        │         │  & Certificate Scanner    │
 │  (regex + AST tiers) │          │  (manifests + symbols)    │         │  (Dockerfiles, TLS cfg,   │
 │                      │          │                            │         │   X.509 certs, IaC)       │
 └──────────┬───────────┘          └─────────────┬──────────────┘         └─────────────┬──────────────┘
            │  raw findings                       │  raw findings                        │  raw findings
            └────────────────────────┬────────────┴───────────────────┬────────────────────┘
                                      ▼                                ▼
                        ┌───────────────────────────────────────────────────┐
                        │   M4  CBOM Aggregation & Normalization Engine       │
                        │   (dedupe, map to CycloneDX 1.6 cryptographic-asset)│
                        └───────────────────────┬─────────────────────────────┘
                                                 ▼
                        ┌───────────────────────────────────────────────────┐
                        │   M7  Backend API & Orchestration (FastAPI +       │
                        │       Celery/Redis job queue + PostgreSQL)          │
                        └───────┬───────────────────────────┬───────────────┘
                                ▼                             ▼
              ┌───────────────────────────────┐   ┌───────────────────────────────┐
              │  M5  Quantum Risk Engine        │   │  M6  PQC Recommendation Engine │
              │  (Mosca's inequality scoring)   │   │  (mapping table + constraints) │
              └───────────────┬─────────────────┘   └───────────────┬───────────────┘
                               └───────────────┬───────────────────┘
                                                ▼
                        ┌───────────────────────────────────────────────────┐
                        │   M8  Interactive Dashboard (React + Tailwind +    │
                        │       Recharts) — Inventory, Heatmap, Drilldown    │
                        └───────────────────────┬─────────────────────────────┘
                                                 ▼
                        ┌───────────────────────────────────────────────────┐
                        │   M9  Reporting & Export (CBOM JSON / PDF / CSV)   │
                        └───────────────────────────────────────────────────┘
```

Everything downstream of M4 speaks one contract — the internal CBOM object — so M1/M2/M3 can be built fully in parallel by different people without blocking each other, as long as each emits the "raw finding" shape defined in Section 6.

---

## 6. Core Data Model (CBOM Schema)

Two layers: (a) the **raw finding** each scanner emits (simple, scanner-specific), and (b) the **canonical CBOM asset** that M4 normalizes everything into (CycloneDX-aligned, plus our own enrichment fields for risk scoring).

### 6.1 Raw finding (emitted by M1/M2/M3 — internal contract only)
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

### 6.2 Canonical CBOM asset (CycloneDX 1.6-aligned, output of M4)
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
    "moscaRiskTier": "Critical",
    "recommendedReplacement": "SHA-384 or SHA3-384",
    "referenceStandard": "N/A (deprecate; not a PQC concern, a classical-strength concern)"
  }
}
```

Keep `ecdatEnrichment` as a **CycloneDX property/extension bag**, not a schema violation — this preserves interoperability (any standard CBOM consumer can still parse the core fields; only our own tooling reads the enrichment block).

---

## 7. Module-by-Module Design

### M1 — Source Code Repository Scanner
**Objective:** Statically detect cryptographic API usage inside source repositories across multiple languages.

**Design — two detection tiers (cheap first, precise second):**
- **Tier 1 (regex/keyword pass, fast, full-repo):** scans every text file for known signal strings — import statements (`from cryptography.hazmat...`, `import javax.crypto`, `require('crypto')`, `crypto/rsa`), algorithm name literals (`"DES"`, `"RC4"`, `"MD5"`, `Cipher.getInstance("AES/ECB/PKCS5Padding")`), and key-material fingerprints (`-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN CERTIFICATE-----`). This is your gitleaks/TruffleHog-style pass — cheap, high-recall, some false positives.
- **Tier 2 (AST pass, precise, only on files that Tier 1 flagged):** use **tree-sitter** grammars (Python, Java, JavaScript/TypeScript, Go all have mature tree-sitter grammars, and one library gives you a unified query interface across languages) to resolve whether the flagged string is actually a crypto API *call* (vs. a comment, a string in a test fixture, or dead code), and to extract the real arguments (key size, mode, padding) instead of guessing from surrounding text. This mirrors the "AST, not raw text" lesson from IBM's `sonar-cryptography` engine.

**Input:** Git URL, uploaded ZIP, or local path.
**Output:** list of raw findings (Section 6.1) → M4.
**Languages for MVP:** Python, Java, JavaScript/TypeScript, Go. (C/C++, C# as stretch — note System.Security.Cryptography and OpenSSL C-API coverage as roadmap.)
**Libraries to detect per language:** see Section 8.
**Acceptance criteria:** ≥85% recall and reasonable precision against your own curated seed corpus (Appendix 18.2) — measure this explicitly, it's a great demo/judge-answer statistic.

### M2 — Binary, Dependency & Library Scanner
**Objective:** Identify crypto libraries/versions from dependency manifests and lightweight binary inspection.

**Design:**
- **Manifest parsing:** parse `requirements.txt`/`Pipfile.lock`, `pom.xml`/`build.gradle`, `package.json`/`package-lock.json`, `go.mod`/`go.sum` to extract (library, version) pairs. Cross-reference against an internally curated **crypto library registry** (JSON: library name → algorithms it implements → known-deprecated version ranges → CVE references, seeded manually plus optional live NVD API lookups).
- **Binary inspection (lightweight, MVP-scoped):** run `strings`/ELF or PE symbol-table extraction to find embedded version banners (`"OpenSSL 1.0.2k"`) and recognizable crypto function symbols (`RSA_new`, `EVP_EncryptInit_ex`, `MD5_Init`). Explicitly **not** doing full disassembly/lifting in the MVP — call this out as intentional scope, not a gap you didn't notice. (YARA rulesets for statically-linked, stripped crypto constant tables such as AES S-boxes are a good roadmap item.)
**Output:** library inventory + flagged deprecated/vulnerable entries → M4.

### M3 — Container, Infra Config & Certificate Scanner
**Objective:** Detect crypto exposure in deployment artefacts: container images, TLS/webserver configs, IaC, and X.509 certificates.

**Design:**
- **Container images:** extract installed package lists per layer (reuse the Syft/Grype/Trivy approach conceptually — even shelling out to Trivy for the package-listing step is a legitimate, fast MVP choice) → cross-reference against the M2 library registry.
- **Config files:** regex/structured parsing of `nginx.conf`, Apache `httpd.conf`, `application.yml`, Dockerfiles, and Kubernetes manifests for TLS protocol versions (flag SSLv2/3, TLS 1.0/1.1) and cipher suite strings.
- **IaC (Terraform/CloudFormation):** parse for KMS key resource declarations (`aws_kms_key`, Azure Key Vault key specs) to catalogue managed-key crypto **without** needing live cloud credentials — this is the safe, demo-friendly substitute for live cloud API scanning.
- **X.509 certificates:** parse with `cryptography`/`pyOpenSSL` to extract public-key algorithm, key size, signature algorithm, validity window, issuer/subject. Flag RSA < 2048-bit, SHA-1-signed certs, self-signed certs, and long-validity certs (a long validity window is itself a quantum-risk amplifier under HNDL).
**Output:** raw findings → M4.

### M4 — CBOM Aggregation & Normalization Engine
**Objective:** Merge M1–M3 raw findings into deduplicated, CycloneDX 1.6-compliant CBOM assets (Section 6.2), plus enrichment fields.
**Design:** normalize algorithm names against a canonical lookup table (map `"SHA1"`, `"sha-1"`, `"SHA_1"` → one canonical `SHA-1` entry with its OID); deduplicate identical (algorithm, file, line) triples across tiers/scanners; build the occurrence list; attach `ecdatEnrichment` fields sourced from a user-provided or default **asset tagging config** (business criticality, data classification, exposure) keyed by path/service pattern.
**Output:** canonical per-scan CBOM (`cbom.json`) + write-through to the database for the enterprise-wide merged view.

### M5 — Quantum Risk Assessment Engine
**Objective:** Score every CBOM asset using Mosca's inequality plus business-context weighting (full math in Section 9).
**Input:** canonical CBOM assets + a configurable **threat-model config** (default CRQC arrival window, default shelf-life per data classification, default migration-time estimates per asset type).
**Output:** `moscaRiskTier`, numeric `riskScore`, and the underlying (X, Y, Z, ratio) breakdown attached to each asset — the UI must be able to show *why* an asset scored the way it did, not just the final number.

### M6 — PQC / Hybrid Recommendation Engine
**Objective:** For every quantum-vulnerable asset, output a concrete replacement recommendation (Section 10 has the full mapping table).
**Design:** a rules table keyed on `(primitiveCategory, currentAlgorithm)` → `{recommendedAlgorithm, mode: pure-PQC | hybrid, complexity: Low/Med/High, rationale, referenceStandard}`, with constraint overrides for latency-sensitive contexts (recommend hybrid + smaller parameter set) vs. CNSA-2.0-compliance contexts (force the higher parameter sets, e.g. ML-KEM-1024/ML-DSA-87).
**Output:** recommendation record attached to each asset → surfaced in dashboard drill-down and the exported report.

### M7 — Backend API & Orchestration Layer
**Objective:** Own the async scan lifecycle and expose everything the frontend needs.
**Stack:** FastAPI; Celery + Redis for async scan jobs (scans can run for minutes — never block an HTTP request on a scan); PostgreSQL (JSONB columns for raw CBOM blobs, relational columns for filterable fields).
**Core endpoints:**
| Method & Path | Purpose |
|---|---|
| `POST /scans` | Start a scan job: `{sourceType, target}` (git URL / upload ref / image ref) |
| `GET /scans/{id}` | Poll job status |
| `GET /assets?risk=Critical&exposure=external` | Filterable asset inventory |
| `GET /assets/{id}` | Full asset detail incl. Mosca breakdown + recommendation |
| `GET /cbom/{scanId}` | Raw CycloneDX 1.6 JSON export |
| `GET /reports/{scanId}?format=pdf\|csv\|json` | Generated report |
| `PATCH /config/threat-model` | Update default X/Y/Z assumptions (drives the "what-if" slider) |

### M8 — Interactive Dashboard (GUI)
**Objective:** Make the inventory and risk model legible and explorable, and provide the single strongest demo moment.
**Views:**
1. **Overview** — total assets scanned, risk-tier distribution, top 10 highest-risk assets.
2. **Asset Inventory table** — sortable/filterable (type, algorithm, file/location, library, key size, risk tier, business unit).
3. **Risk Heatmap (the money view)** — a quadrant/bubble chart of *business criticality* (Y-axis) vs. *urgency ratio* (X-axis), bubble size = number of assets; include a live slider for "years until CRQC" (Z) that recomputes every bubble's position in real time — this single interaction demonstrates the entire Mosca methodology to a judge in 10 seconds.
4. **Asset Detail drill-down** — exact file/line, the X/Y/Z numbers and the resulting ratio, and the M6 recommendation with a side-by-side comparison (current vs. recommended: key/signature size, relative latency, standard reference).
5. **Recommendations / Migration Roadmap report page** — exportable, sorted by risk tier.
**Stack:** React + TypeScript, Tailwind CSS, Recharts (bar/donut/quadrant), a data-grid component for the inventory table.

### M9 — Reporting & Export Engine
**Objective:** Produce shareable, standardized outputs.
**Formats:** CycloneDX 1.6 CBOM JSON (importable into other SBOM tooling — a strong "we're not a walled garden" talking point); PDF executive summary (WeasyPrint or ReportLab: risk distribution, top risks, recommended roadmap); CSV/XLSX full asset list (openpyxl). SARIF export is a good one-line roadmap mention for CI/CD judges.

---

## 8. Cryptographic Detection Taxonomy

| Category | Examples to detect | Quantum-vulnerable? | Notes |
|---|---|---|---|
| Asymmetric key exchange | RSA, DH, ECDH, X25519/X448 | **Yes** (Shor's algorithm) | Highest-priority replacement target |
| Digital signatures | RSA-sign, DSA, ECDSA, EdDSA (Ed25519/Ed448) | **Yes** (Shor's algorithm) | Replace with ML-DSA / SLH-DSA |
| Symmetric ciphers | AES-128/192/256, ChaCha20 | Partially — Grover halves margin | AES-256/ChaCha20 remain safe; flag AES-128 |
| Legacy/broken symmetric | DES, 3DES, RC2, RC4, Blowfish | Already broken classically | Flag as Critical regardless of quantum framing |
| Hash functions | MD5, SHA-1, SHA-2 (224/256/384/512), SHA-3, BLAKE2/3 | Partially — Grover halves margin | MD5/SHA-1 already broken classically; recommend SHA-384+/SHA3-384+ |
| MAC / KDF | HMAC, PBKDF2, bcrypt, scrypt, Argon2 | Depends on underlying hash | Fine if built on strong hash + sufficient work factor |
| Protocols | SSLv2/3, TLS 1.0/1.1/1.2/1.3, IPsec/IKE, SSH, PGP/GPG | Depends on negotiated ciphers | Flag deprecated protocol versions outright |
| PQC / Hybrid (target state) | ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+), FN-DSA (Falcon, draft), HQC, hybrid `X25519MLKEM768` | No | Detect early adopters too (e.g. liboqs / Open Quantum Safe bindings) |
| Certificates & PKI | X.509 fields: public-key algorithm, key size, signature algorithm, validity period | Inherits from contained algorithm | Long-validity certs amplify HNDL risk |
| Hardware/Cloud | HSM (PKCS#11) references, AWS KMS, Azure Key Vault, GCP Cloud KMS, TPM | Depends on configured algorithm | MVP: static IaC detection only |

**Libraries to register per language (seed list for M1/M2):**
- Python: `cryptography` (pyca), `hashlib`, `PyCryptodome`/`Crypto`, `PyNaCl`/libsodium
- Java: `javax.crypto` (JCA/JCE), Bouncy Castle
- Go: standard `crypto/*`, `golang.org/x/crypto`
- JavaScript/TypeScript: Node `crypto`, `node-forge`, `libsodium-wrappers`
- C#: `System.Security.Cryptography` (roadmap)
- C/C++: OpenSSL, mbedTLS, wolfSSL, libsodium (roadmap — symbol-scan tier only in MVP)

---

## 9. Quantum Risk Scoring Model (Mosca's Algorithm, Operationalized)

### 9.1 The base inequality
Mosca's theorem (first proposed 2018) states an asset is **at risk today** if:

```
X + Y > Z
```

Where (use this convention consistently across the whole team — sources vary in labeling, so document it once and stick to it):
- **X = Security Shelf-Life** — how many years this asset's *data* must remain confidential/authentic.
- **Y = Migration Time** — how many years it will realistically take your organization to migrate *this specific asset* to a PQC/hybrid scheme.
- **Z = Threat Timeline** — how many years until a cryptographically-relevant quantum computer (CRQC) exists.

Z is genuinely uncertain — expert estimates commonly cluster in the **2030–2035** range, and this uncertainty is exactly why Mosca framed it as an inequality with a *configurable* variable rather than a fixed date. **Make Z a UI slider with a sane default, not a hardcoded constant** — this is both technically correct and a great interactive demo feature.

### 9.2 From binary inequality to a continuous score
A pure yes/no from the inequality is too coarse for prioritization across hundreds of assets. Compute a continuous **urgency ratio**:

```
r = (X + Y) / Z
```

- `r ≥ 1.2` → **Critical** (already past the Mosca threshold with margin)
- `0.9 ≤ r < 1.2` → **High** (at or near the threshold)
- `0.6 ≤ r < 0.9` → **Medium**
- `r < 0.6` → **Low**

Independently: **any classically-broken algorithm (MD5, SHA-1, DES, 3DES, RC4)** is auto-escalated to **Critical**, regardless of `r` — those are not "at risk once quantum computers arrive," they're already exploitable today, and the model should never let a favorable Mosca ratio mask that.

### 9.3 Composite risk score (adds business context)
```
RiskScore = 0.40 × QuantumVulnerabilityScore
          + 0.25 × normalize(r)
          + 0.20 × BusinessCriticalityScore
          + 0.15 × ExposureScore
```
- `QuantumVulnerabilityScore`: 1.0 if broken by Shor's (asymmetric), 0.6 if Grover-weakened (e.g. AES-128/SHA-256), 0.0 if already at recommended strength or already PQC.
- `BusinessCriticalityScore`: from asset tagging (Critical=1.0, High=0.75, Medium=0.5, Low=0.25).
- `ExposureScore`: external/internet-facing = 1.0, internal-only = 0.4.

**Make the weights configurable in the UI** (a simple set of sliders/inputs) — this converts "we picked arbitrary weights" from a weakness into a feature ("the framework is tunable to your organization's risk appetite").

### 9.4 Worked example (put this in your pitch deck)
| Asset | Algorithm | X (shelf-life) | Y (migration time) | Z (threat timeline) | r | Tier |
|---|---|---|---|---|---|---|
| Customer PII field encryption | RSA-2048 key exchange | 15 yrs | 1.5 yrs | 8 yrs | 2.06 | **Critical** |
| Internal microservice mTLS | ECDSA-P256 cert | 3 yrs | 0.5 yrs | 8 yrs | 0.44 | Low |
| Firmware signing | RSA-2048 signature | 10 yrs | 2 yrs | 8 yrs | 1.5 | **Critical** |
| Session token hashing | SHA-1 | n/a | n/a | n/a | — | **Critical** (auto-escalated, classically broken) |

---

## 10. PQC / Hybrid Recommendation Mapping

Standards reference: NIST finalized **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)**, and **FIPS 205 (SLH-DSA)** on **August 13, 2024**. **FIPS 206 (FN-DSA, based on Falcon)** is still in draft. **HQC** was selected in **March 2025** as an additional, structurally-different backup KEM (code-based, vs. lattice-based ML-KEM) for long-term algorithm diversity.

| Current algorithm | Function | Recommended replacement | Mode | Notes |
|---|---|---|---|---|
| RSA / DH / ECDH / X25519 key exchange | Key establishment | **ML-KEM-768** (FIPS 203) | Hybrid: `X25519MLKEM768` for general TLS; pure ML-KEM where policy requires | Matches the default already shipped by Chrome/Firefox in TLS 1.3 |
| RSA-sign / ECDSA / EdDSA | Digital signature | **ML-DSA-65** (FIPS 204) | Hybrid or pure, per compliance target | Default general-purpose signature choice |
| High-assurance/firmware signing needing hash-based conservatism | Digital signature | **SLH-DSA** (FIPS 205) | Pure | Larger/slower but relies only on hash-function security assumptions |
| CNSA 2.0 / national-security-grade systems | Key exchange / signature | **ML-KEM-1024** / **ML-DSA-87** | Pure, per CNSA 2.0 mandate | CNSA 2.0 targets full PQC migration by 2030–2033 |
| AES-128 | Symmetric encryption | **AES-256** | — | Restores full margin against Grover's algorithm |
| MD5 / SHA-1 | Hash | **SHA-384 / SHA3-384** or larger | — | Already classically broken; not a "wait for quantum" item |
| (Future) compact-signature need | Digital signature | **FN-DSA (Falcon)** once FIPS 206 finalizes | — | Track as roadmap; do not ship as primary recommendation while still draft |
| (Future) KEM diversification | Key exchange | **HQC** | Hybrid, alongside ML-KEM | Roadmap item — code-based, hedges against a lattice-cryptanalysis break |

Recommendation records should also carry: relative key/ciphertext/signature **size delta** (PQC artefacts are meaningfully larger — this affects bandwidth/storage cost, and is worth surfacing explicitly), a **migration complexity** estimate (Low/Med/High, informed by whether the current library already has a PQC-capable version available), and the **referenceStandard** field for compliance reporting.

---

## 11. Technology Stack Summary

| Layer | Choice | Why |
|---|---|---|
| Scanning engines (M1–M3) | Python + `tree-sitter` (multi-language AST) + regex tier | One language for the whole scanning codebase; tree-sitter grammars exist for all MVP target languages |
| Backend API (M7) | FastAPI (Python) | Fast to build, async-native, auto-generates OpenAPI docs for free (useful for parallel frontend work) |
| Job queue | Celery + Redis | Scans are long-running; never block HTTP requests |
| Database | PostgreSQL (JSONB for raw CBOM, relational for filters) | One database, minimal ops overhead for a week-long build |
| CBOM schema | CycloneDX 1.6 (JSON) | Industry standard, interoperability win |
| Container/package inspection | Shell out to existing OSS (e.g., Trivy) for layer/package listing where time allows | Don't rebuild a package-layer parser from scratch under time pressure |
| Certificate parsing | Python `cryptography` / `pyOpenSSL` | Mature, well-documented |
| Frontend | React + TypeScript + Tailwind CSS | Fast iteration, consistent design tokens |
| Charts | Recharts (bar/donut) + a custom quadrant/bubble component for the risk heatmap | Recharts covers 80% of needs quickly |
| Reporting | WeasyPrint or ReportLab (PDF), `openpyxl` (XLSX/CSV) | Lightweight, no external service dependency |
| Test datasets | OpenSSL (GitHub), OWASP Juice Shop, OWASP WebGoat, a **hand-written seed corpus** per language | See Appendix 18.2 |

---

## 12. Data Flow

```mermaid
flowchart LR
    A[Git repo / ZIP / image ref] --> B(M1 Source Scanner)
    A --> C(M2 Binary+Dependency Scanner)
    A --> D(M3 Container+Config+Cert Scanner)
    B --> E[M4 CBOM Normalizer]
    C --> E
    D --> E
    E --> F[(PostgreSQL)]
    F --> G(M5 Risk Engine)
    F --> H(M6 Recommendation Engine)
    G --> I(M7 API Layer)
    H --> I
    I --> J[M8 Dashboard]
    I --> K[M9 Reports: CBOM JSON / PDF / CSV]
```
*(This block is a Mermaid diagram — renders natively in GitHub, VS Code, and most Markdown viewers.)*

---

## 13. Team Structure & Role Allocation (assumes 6 developers)

| Role | Owns | Primary skills needed |
|---|---|---|
| Backend/Scanning Lead | M1, overall architecture, M7 skeleton | Python, AST/parsing, API design |
| Scanning Engineer | M2, M3 | Python, binary basics, regex, container internals |
| Data/Platform Engineer | M4, M7 (DB + queue), M9 | Python, PostgreSQL, Celery |
| Risk/Algorithms Engineer | M5, M6, threat-model research | Comfortable with the math in Section 9, NIST standards research |
| Frontend Engineer 1 | M8 core views (Overview, Inventory, Heatmap) | React, Recharts, Tailwind |
| Frontend Engineer 2 | M8 secondary views (Drilldown, Recommendations), documentation, pitch deck coordination | React, technical writing, presentation |

If your team is 4–5 people, merge Data/Platform into Backend/Scanning Lead, and merge the two frontend roles — the module list stays the same; only the parallelism shrinks.

---

## 14. 7-Day Sprint Plan

| Day | Backend/Scanning (M1) | Scanning (M2/M3) | Data/Risk/Recs (M4/M5/M6/M7) | Frontend (M8/M9) |
|---|---|---|---|---|
| **Day 1 — Foundations** | Repo scaffold, finalize CBOM schema (Sec. 6), define API contract (OpenAPI skeleton) | Collect test datasets: clone OpenSSL, Juice Shop, WebGoat; start writing the seed corpus (Appendix 18.2) | Finalize threat-model defaults (X/Y/Z assumptions), draft DB schema | Wireframes for all 5 dashboard views; design tokens/theme |
| **Day 2** | M1 Tier-1 regex scanner (Python, JS) | Start M2 manifest parsers (requirements.txt, package.json) | M7 skeleton API + DB models; M4 skeleton normalizer | Frontend scaffold (routing, layout), wire to mock JSON matching the API contract |
| **Day 3** | M1 add Tier-2 tree-sitter AST pass (Python, Java) | Finish M2 manifest parsing incl. crypto library registry; start binary strings/symbol scan | M4 producing valid CycloneDX output from real M1 findings; M5 core Mosca calculator | Build Inventory table view wired to staged API |
| **Day 4** | M1 extend to JS/TS + Go | Finish M2 binary tier; start M3 (Dockerfiles, TLS configs, X.509 parsing) | M5 add business-criticality/exposure weighting; start M6 recommendation mapping table | Build Overview dashboard + start Risk Heatmap (quadrant chart) |
| **Day 5 — Integration** | Bug-fix M1 against seed corpus, measure recall/precision | Finish M3 (IaC KMS detection); container layer inspection via Trivy shell-out | Wire M2/M3 outputs into M4; finish M6 with constraint overrides; async job queue end-to-end | Finish Risk Heatmap incl. live Z-slider; build Asset Detail drilldown |
| **Day 6** | End-to-end test against 3–4 real targets (a Java repo, a Python repo, a Docker image, a cert bundle) | Same — full team bug bash | M9 reporting (PDF/CSV/CBOM export) | Recommendations/report page; polish loading & empty states |
| **Day 7 — Freeze & Rehearse** | Code freeze — no new features | Fix only demo-breaking bugs found in rehearsal | Prepare Q&A anticipation notes (Section 15) | Two full dry-run demos; record a backup demo video; finalize pitch deck |

Run a **15-minute daily standup** at a fixed time — the biggest risk to a 4-track parallel plan is silent drift on the shared contracts (CBOM schema, API shape). If M4's output shape needs to change after Day 2, that change must be announced to all four tracks the same day.

---

## 15. Demo Script & Success Metrics

**Suggested 5-minute live demo flow:**
1. Kick off a live scan against a real, imperfect codebase (e.g., a deliberately-vulnerable sample or a slightly outdated OpenSSL-using project) — show the scan running asynchronously.
2. Show the generated **CBOM JSON** and note it's CycloneDX 1.6-compliant (say this explicitly — it signals rigor).
3. Jump to the **Risk Heatmap**; drag the "years until CRQC" slider and watch bubbles move — this is your best 10 seconds.
4. Drill into one Critical asset; show the X/Y/Z breakdown and the concrete recommendation (e.g., "RSA-2048 → ML-KEM-768 hybrid, FIPS 203").
5. Export the PDF report.

**Metrics worth quoting to judges (measure these for real before the demo, don't estimate on stage):**
- Detection recall/precision against your seed corpus (target ≥85% recall).
- Number of languages/ecosystems covered.
- Scan time for a representative repo.
- CBOM schema validation pass (validate your output against the CycloneDX JSON schema programmatically — trivial to add, strong credibility signal).

**Anticipated judge questions:** "How is this different from IBM's CBOMkit?" (answer with Section 4's differentiation list); "How do you know your quantum timeline assumption is right?" (answer: we don't claim to — it's a configurable, transparent assumption, which is the point of Mosca's framework); "What about false positives?" (answer with your measured precision number and the seed-corpus methodology).

---

## 16. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| AST parsing across 4 languages is more work than a week allows | Regex tier ships first and works standalone; AST tier is additive precision, not a blocker to a working demo |
| False positives undermine the "risk assessment" credibility | Curated seed corpus with known ground truth; report precision/recall honestly |
| Deep binary/HSM scanning is a rabbit hole | Explicitly scoped out of MVP (Section 2); symbol/string-level only |
| Live cloud scanning raises credential-handling concerns for a demo | Static IaC scanning instead — no live cloud credentials needed anywhere in the system |
| Frontend blocked waiting on real backend data | API contract (OpenAPI) frozen Day 1; frontend builds against mock data matching that contract from Day 2 |
| Team split too thin across 9 modules | Modules are grouped into 4 tracks (Section 13), not 9 separate owners; several modules share an owner |

---

## 17. Roadmap Beyond the Hackathon

- Broader language coverage: Rust, C++, C#, PHP, Ruby.
- Full binary lifting (Ghidra/angr) for statically-linked, stripped crypto detection.
- Live, read-only cloud connector scanning (AWS KMS/ACM, Azure Key Vault, GCP Cloud KMS) under a dedicated least-privilege IAM role.
- Live TLS-handshake scanning of running network endpoints.
- CI/CD integration: a GitHub Action / GitLab CI job emitting SARIF, with policy gates ("fail build if a new Critical asset is introduced").
- Continuous CVE/NVD feed integration for real-time crypto-library vulnerability alerts.
- LLM-assisted detection to catch custom wrapper functions around crypto calls that pure AST rules miss (recent academic work has combined regex scanning with LLM enrichment for exactly this gap) — a good "we're aware of the state of the art" line for judges, framed as future work rather than an MVP claim.
- Multi-tenant RBAC/SSO for genuine enterprise deployment.
- Historical trend tracking — show migration progress over repeated scans, not just a point-in-time snapshot.
- Auto-remediation: generate a draft pull request for low-risk, mechanical fixes (e.g., bumping a TLS config's cipher suite list).

---

## 18. Appendix

### 18.1 Detection rule pseudocode (illustrative, for M1)
```python
# Tier 1: fast regex pass
CRYPTO_SIGNALS = {
    "SHA1": r"\b(SHA-?1|hashlib\.sha1|SHA1)\b",
    "MD5":  r"\b(MD5|hashlib\.md5)\b",
    "DES":  r"\bDES(?!3)\b",
    "RSA":  r"\bRSA\b",
    # ... full table lives in a config file, not hardcoded in logic
}

def tier1_scan(file_text: str) -> list[dict]:
    hits = []
    for label, pattern in CRYPTO_SIGNALS.items():
        for m in re.finditer(pattern, file_text):
            hits.append({"primitive": label, "offset": m.start()})
    return hits

# Tier 2: AST pass (tree-sitter), only run on files with Tier-1 hits
def tier2_confirm(file_path: str, hits: list[dict]) -> list[Finding]:
    tree = parse_with_treesitter(file_path)
    confirmed = []
    for hit in hits:
        node = find_enclosing_call_node(tree, hit["offset"])
        if node and is_crypto_api_call(node):
            confirmed.append(build_finding(node, hit))
        # else: likely a comment/string literal/test fixture — drop it
    return confirmed
```

### 18.2 Test datasets / seed corpus
- **OpenSSL** (GitHub) — real-world C crypto usage, config file examples.
- **OWASP Juice Shop**, **OWASP WebGoat** — intentionally vulnerable apps, useful for validating detection of weak crypto in realistic app code.
- **NVD/CVE API** — for enriching the library-version vulnerability registry (M2).
- **Hand-written seed corpus (build this yourselves, Day 1):** one small file per language × per algorithm in Section 8, with a known ground-truth label, so you can compute real recall/precision numbers instead of guessing. This is the single highest-leverage thing to build early — it de-risks your Day 6 demo far more than any extra feature would.

### 18.3 Sample CBOM JSON
See Section 6.2 for a full example asset. A minimal CycloneDX 1.6 document wrapper looks like:
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:generated-per-scan",
  "version": 1,
  "components": [
    { "...": "one cryptographic-asset object per Section 6.2, per finding" }
  ]
}
```

---

## 19. Development Kickoff Prompts

Each block below is written to be pasted directly into an AI coding assistant (e.g., Claude Code) to bootstrap that module. Paste the relevant section(s) of this document alongside the prompt for full context — each prompt assumes the assistant can see Sections 6, 8, 9, and 10 above.

### Prompt 0 — Project Scaffolding
```
Set up a monorepo for a project called ECDAT (Enterprise Cryptographic Discovery
& Analysis Tool). Structure:

  /backend        - Python 3.11, FastAPI app
  /backend/scanners  - one subpackage per scanner module (source, binary, container)
  /backend/engine     - CBOM normalization, risk scoring, recommendation engine
  /backend/api        - FastAPI routers
  /backend/models     - SQLAlchemy models + Pydantic schemas
  /frontend       - React + TypeScript + Vite + Tailwind CSS
  /shared/schemas - JSON Schema files for: the "raw finding" object and the
                    "canonical CBOM asset" object (I'll paste both shapes below)
  /docs           - this design document

Set up: FastAPI skeleton with a health-check endpoint, PostgreSQL connection via
SQLAlchemy with Alembic migrations, a Celery app configured against Redis, a
pytest test scaffold, and a React app scaffold with Tailwind configured and
React Router set up with placeholder pages for: Overview, Inventory, Risk
Heatmap, Asset Detail, Recommendations. Add a docker-compose.yml that brings up
Postgres, Redis, the backend, and the frontend dev server together.

Here is the "raw finding" JSON shape every scanner must emit: [paste Section 6.1]
Here is the canonical CBOM asset shape M4 must produce: [paste Section 6.2]
```

### Prompt 1 — M1: Source Code Repository Scanner
```
Build the source-code scanner module for ECDAT (see attached design doc,
Section 7 / M1 and Section 8 for the detection taxonomy).

Requirements:
1. Input: a local directory path (repo already cloned/extracted upstream).
2. Tier 1: a fast regex-based pass across every text file, using a
   configuration-driven signal table (label -> regex pattern) loaded from a
   YAML/JSON config file, NOT hardcoded in the scanning logic - I want to be
   able to add new algorithm signals without touching code. Seed the config
   with entries for every algorithm/library in Section 8 of the design doc,
   for Python, Java, JavaScript/TypeScript, and Go.
3. Tier 2: for every file with at least one Tier-1 hit, run a tree-sitter-based
   AST pass (use the `tree-sitter` Python bindings with the appropriate
   language grammars) to confirm the hit is a real API call (not a comment,
   string literal, or test fixture) and to extract real arguments where
   possible (key size, mode/padding literals passed to the call).
4. Output: a list of "raw finding" objects matching the exact schema in
   Section 6.1 of the design doc [paste it].
5. Write this as a clean, testable Python package (`backend/scanners/source/`)
   with a single public entrypoint function `scan_repository(path: str) ->
   list[RawFinding]`.
6. Write unit tests using a small fixture directory with 2-3 example files per
   language, each with a known expected finding, so recall/precision can be
   computed automatically in CI.

Do not implement M2/M3/M4 - just this scanner and its output contract.
```

### Prompt 2 — M2: Binary, Dependency & Library Scanner
```
Build the dependency-manifest and lightweight binary scanner module for ECDAT
(design doc Section 7 / M2).

Requirements:
1. Manifest parsers for: requirements.txt / Pipfile.lock (Python), pom.xml /
   build.gradle (Java), package.json / package-lock.json (Node), go.mod /
   go.sum (Go). Each parser extracts (library name, version) pairs.
2. A "crypto library registry" as a versioned JSON config file mapping library
   name -> {algorithms it implements, known-deprecated version ranges,
   optional CVE references}. Seed it with the libraries listed in Section 8 of
   the design doc. Write a small loader/lookup module for this registry, kept
   separate from the parsing logic so the registry can be extended without
   code changes.
3. A lightweight binary inspector: given a path to a compiled binary or shared
   library (ELF or PE), extract printable strings and the dynamic symbol
   table, and flag matches against a curated list of crypto version banners
   (e.g. "OpenSSL 1.0.2") and known crypto function symbol names (e.g.
   RSA_new, EVP_EncryptInit_ex, MD5_Init). Do NOT attempt disassembly or
   binary lifting - string/symbol extraction only, this is an explicit scope
   boundary.
4. Output: the same "raw finding" schema as M1 (Section 6.1) - reuse that
   exact shape so M4 doesn't need per-scanner-type logic.
5. Package as `backend/scanners/binary_deps/` with a public entrypoint
   `scan_dependencies(path: str) -> list[RawFinding]` and
   `scan_binary(path: str) -> list[RawFinding]`.
6. Unit tests against a couple of small sample manifests and a tiny test
   binary you can build inline in the test (e.g., a minimal C program linked
   against OpenSSL) to confirm string/symbol extraction works.
```

### Prompt 3 — M3: Container, Infra Config & Certificate Scanner
```
Build the container/infra/certificate scanner module for ECDAT (design doc
Section 7 / M3).

Requirements:
1. Container image inspection: given a Docker image reference or a local
   Dockerfile, extract the installed package list. For the MVP, shell out to
   an existing tool (e.g. Trivy, if available in the environment) to get the
   package listing per layer rather than reimplementing OCI layer parsing;
   fall back to parsing the Dockerfile's package-manager install lines
   (apt-get install, pip install, etc.) if the external tool isn't available.
   Cross-reference extracted packages against the same crypto library
   registry built for M2.
2. Config file scanning: regex/structured parsers for nginx.conf, Apache
   httpd.conf-style configs, and Kubernetes manifests (YAML) that extract
   TLS protocol version directives and cipher-suite strings. Flag SSLv2,
   SSLv3, TLS 1.0, and TLS 1.1 explicitly as deprecated.
3. IaC scanning: a Terraform HCL parser (or regex-based extraction if a full
   HCL parser is too heavy for the timeline) that finds KMS key resource
   blocks (e.g. aws_kms_key, azurerm_key_vault_key) and extracts the
   configured key spec/algorithm - this is a static substitute for live
   cloud API scanning, and must not require any cloud credentials.
4. X.509 certificate parsing: given a .pem/.crt file or a directory of them,
   use the `cryptography` library to extract public-key algorithm, key size,
   signature algorithm, validity window, issuer, and subject. Flag RSA keys
   under 2048 bits, SHA-1 signature algorithms, self-signed certificates, and
   certificates with a validity window longer than 2 years.
5. Output: the same "raw finding" schema as M1/M2 (Section 6.1).
6. Package as `backend/scanners/infra/` with clearly separated entrypoints per
   sub-scanner (`scan_container_image`, `scan_configs`, `scan_iac`,
   `scan_certificates`), each returning `list[RawFinding]`.
7. Unit tests using small fixture files for each sub-scanner (a sample nginx
   config with TLS 1.0 enabled, a sample self-signed cert, a sample Terraform
   snippet with an RSA-2048 KMS key, etc.).
```

### Prompt 4 — M4: CBOM Aggregation & Normalization Engine
```
Build the CBOM normalization engine for ECDAT (design doc Section 7 / M4,
schema in Section 6).

Requirements:
1. Input: a list of "raw finding" objects (Section 6.1 schema) coming from
   any combination of the M1/M2/M3 scanners.
2. Normalize algorithm names against a canonical lookup table (e.g. "SHA1",
   "sha-1", "SHA_1" all map to one canonical "SHA-1" entry with its OID -
   seed this table for every algorithm listed in Section 8 of the design
   doc). Include each canonical entry's OID where a well-known one exists.
3. Deduplicate: findings that share the same (canonical algorithm, file path,
   line number) across tiers or scanners should collapse into a single
   canonical asset with a combined occurrence list, not duplicate entries.
4. Produce one canonical "CBOM asset" object per unique finding, matching the
   exact schema in Section 6.2 of the design doc [paste it], including the
   CycloneDX-required fields (bom-ref, type: "cryptographic-asset",
   cryptoProperties.assetType, algorithmProperties) AND our own
   "ecdatEnrichment" extension block.
5. For the ecdatEnrichment block, accept an optional "asset tagging config"
   (a JSON file mapping file-path glob patterns to
   {businessCriticality, dataClassification, exposure}) and apply it by
   matching each finding's file path; fall back to sensible defaults
   (businessCriticality: "Medium", exposure: "internal-only") when no rule
   matches.
6. Wrap the full set of assets into a valid CycloneDX 1.6 BOM document:
   {bomFormat: "CycloneDX", specVersion: "1.6", serialNumber, version,
   components: [...]}.
7. Write a validator that checks the produced document against the official
   CycloneDX 1.6 JSON schema (fetch or vendor the schema file) and fails
   loudly if it doesn't validate - this validation pass is something we want
   to be able to point to as evidence of standards compliance.
8. Package as `backend/engine/normalizer/` with a public entrypoint
   `normalize(findings: list[RawFinding], tagging_config: dict | None) ->
   CBOMDocument`.
9. Unit tests: feed in a handful of raw findings including intentional
   duplicates and near-duplicate name variants, and assert the deduplication
   and canonicalization behave correctly.
```

### Prompt 5 — M5: Quantum Risk Assessment Engine
```
Build the quantum risk scoring engine for ECDAT, implementing the model in
Section 9 of the attached design doc exactly as specified.

Requirements:
1. Input: a canonical CBOM asset (Section 6.2 schema) plus a "threat model
   config" object: {threatTimelineYears (Z, default configurable e.g. 8),
   defaultShelfLifeByDataClassification: {...}, defaultMigrationTimeByAssetType:
   {...}}.
2. Implement Mosca's inequality exactly as defined: X = security shelf-life
   (years), Y = migration time (years), Z = threat timeline (years to CRQC).
   Compute the continuous urgency ratio r = (X + Y) / Z.
3. Classify into tiers using these exact thresholds: r >= 1.2 -> "Critical",
   0.9 <= r < 1.2 -> "High", 0.6 <= r < 0.9 -> "Medium", r < 0.6 -> "Low".
4. Implement the auto-escalation rule: if the asset's algorithm is in a
   hardcoded "classically broken" set (MD5, SHA-1, DES, 3DES, RC4, RC2),
   force the tier to "Critical" regardless of the computed ratio, and set a
   human-readable reason field explaining why (e.g. "classically broken,
   independent of quantum timeline").
5. Implement the composite RiskScore formula exactly as given in Section 9.3:
   RiskScore = 0.40*QuantumVulnerabilityScore + 0.25*normalize(r) +
   0.20*BusinessCriticalityScore + 0.15*ExposureScore, with the four weights
   exposed as configurable parameters (not hardcoded constants) so the API
   can let a user adjust them later.
6. QuantumVulnerabilityScore should be 1.0 for Shor-vulnerable primitives
   (RSA, DH, ECDH, ECDSA, EdDSA, DSA), 0.6 for Grover-weakened primitives at
   an insufficient parameter size (AES-128, SHA-256 in a security-critical
   context), and 0.0 for already-strong or PQC primitives (AES-256, SHA-384+,
   SHA3-384+, ML-KEM, ML-DSA, SLH-DSA).
7. Output an enriched asset object that adds: {X, Y, Z, r, moscaRiskTier,
   riskScore, autoEscalated: bool, escalationReason: str | null} - the API and
   UI need every one of these fields individually (not just the final tier),
   so the frontend can show the "why" breakdown from Section 15's demo script.
8. Package as `backend/engine/risk/` with entrypoint
   `score_asset(asset: CBOMAsset, threat_model: ThreatModelConfig,
   weights: RiskWeights) -> ScoredAsset`.
9. Unit tests reproducing the worked example table in Section 9.4 of the
   design doc exactly, asserting the computed tiers match.
```

### Prompt 6 — M6: PQC / Hybrid Recommendation Engine
```
Build the recommendation engine for ECDAT, using the mapping table in
Section 10 of the attached design doc as the source of truth.

Requirements:
1. Input: a scored CBOM asset (output of M5) plus optional constraint flags:
   {complianceTarget: "NIST-general" | "CNSA2.0", latencySensitive: bool}.
2. Implement a rules table keyed on (primitiveCategory, currentAlgorithm) that
   returns {recommendedAlgorithm, mode: "hybrid" | "pure", complexity: "Low" |
   "Medium" | "High", rationale, referenceStandard} exactly per the mapping
   table in Section 10 (RSA/DH/ECDH -> ML-KEM-768 hybrid via X25519MLKEM768
   by default; RSA-sign/ECDSA/EdDSA -> ML-DSA-65; conservative/firmware
   signing context -> SLH-DSA; AES-128 -> AES-256; MD5/SHA-1 -> SHA-384 or
   SHA3-384).
3. If complianceTarget == "CNSA2.0", override the parameter set choice to the
   higher-security variants (ML-KEM-1024, ML-DSA-87) per Section 10.
4. If latencySensitive is true, prefer the smaller parameter set within the
   compliant range and note the trade-off explicitly in the rationale string.
5. Include a rough relative size-delta estimate in the output (e.g. "public
   key ~5.9x larger than RSA-2048") - hardcode approximate figures from the
   FIPS 203/204/205 parameter tables as constants, sourced and commented in
   the code.
6. Only recommend PQC algorithms that are actually finalized (ML-KEM, ML-DSA,
   SLH-DSA). If asked to reason about FN-DSA/Falcon or HQC, only ever
   surface them under a clearly-labeled "future/track" recommendation field,
   never as the primary recommendation, since FIPS 206 is still draft.
7. Package as `backend/engine/recommend/` with entrypoint
   `recommend(asset: ScoredAsset, constraints: Constraints) ->
   Recommendation`.
8. Unit tests covering at least one case per row of the Section 10 mapping
   table, plus one CNSA 2.0 override case and one latency-sensitive case.
```

### Prompt 7 — M7: Backend API & Orchestration Layer
```
Build the FastAPI backend for ECDAT, wiring together the scanner modules
(M1/M2/M3), the normalizer (M4), the risk engine (M5), and the recommendation
engine (M6) into an async scan pipeline.

Requirements:
1. POST /scans - accepts {sourceType: "git" | "upload" | "image" | "path",
   target: str}, enqueues a Celery task that: clones/extracts the target,
   runs the relevant scanners from M1/M2/M3 based on what's present (source
   files -> M1, manifests/binaries -> M2, Dockerfiles/configs/certs -> M3),
   passes all raw findings into M4's normalize(), then runs every resulting
   asset through M5's score_asset() and M6's recommend(), and persists the
   final enriched CBOM to Postgres (JSONB column for the full document, plus
   indexed columns for scanId, riskTier, businessCriticality, exposure to
   support fast filtering). Returns a scanId immediately; the task runs in
   the background.
2. GET /scans/{id} - returns job status: queued | running | completed | failed,
   plus a progress indicator if feasible.
3. GET /assets - supports query params for filtering by riskTier, exposure,
   businessCriticality, algorithm, scanId; paginated.
4. GET /assets/{id} - full asset detail including the M5 breakdown (X, Y, Z,
   r, riskScore) and the M6 recommendation object.
5. GET /cbom/{scanId} - returns the raw CycloneDX 1.6 JSON document for that
   scan, as a downloadable file (Content-Disposition: attachment).
6. GET /reports/{scanId}?format=pdf|csv|json - delegates to the M9 reporting
   module (assume it exists as `backend/engine/reporting.generate_report()`
   for now - stub it if not yet built).
7. PATCH /config/threat-model - updates the stored default threat-model
   config (Z, default shelf-life/migration-time assumptions) used by M5 for
   future scans; also support passing a one-off override threat-model on the
   GET /assets response computation for the frontend's "what-if" slider,
   WITHOUT requiring a full re-scan (i.e., risk re-scoring given a different Z
   should be cheap and computable from already-stored X/Y values, not require
   re-running the scanners).
8. Use SQLAlchemy models + Alembic migrations for: Scan, Asset, Recommendation,
   ThreatModelConfig.
9. Auto-generate OpenAPI docs (FastAPI does this by default - just make sure
   every endpoint has proper Pydantic request/response models so the docs are
   actually useful to the frontend team from Day 2).
10. Write integration tests that run the whole pipeline against one small
    fixture repo end-to-end and assert a CBOM document with at least one
    scored, recommended asset comes out the other end.
```

### Prompt 8 — M8: Interactive Dashboard (GUI)
```
Build the React + TypeScript + Tailwind frontend for ECDAT against the API
contract below (from the design doc, Section 7 / M8 and Section 7 / M7's
endpoint table - paste the actual OpenAPI spec once M7 generates it).

Build these five views:
1. Overview - summary cards (total assets scanned, count per risk tier),
   a donut chart of risk-tier distribution, and a "top 10 highest risk
   assets" list linking to their detail view.
2. Asset Inventory - a sortable, filterable data table (filter by risk tier,
   exposure, business criticality, algorithm) showing type, algorithm,
   file/location, library, key size, risk tier, business unit per row,
   fetched from GET /assets with pagination.
3. Risk Heatmap - a quadrant/bubble chart: X-axis = urgency ratio (r), Y-axis
   = business criticality, bubble size = number of assets at that
   (r, criticality) coordinate, colored by risk tier. Include a slider
   labeled "Years until a quantum computer breaks current crypto (Z)" that,
   on change, recomputes every bubble's X position live using the already-
   fetched X/Y values (do this recomputation client-side using the formula
   r = (X+Y)/Z from Section 9 - do NOT require a server round-trip for this
   interaction, it needs to feel instant).
4. Asset Detail - given an asset id, show file/line location, the full
   Mosca breakdown (X, Y, Z, r) as a small labeled diagram, the assigned risk
   tier and why (including the auto-escalation reason if applicable), and the
   recommendation card: current algorithm vs. recommended algorithm/mode,
   size delta, migration complexity, and the reference standard (e.g.
   "FIPS 203 / ML-KEM-768").
5. Recommendations / Migration Roadmap - a report-style page listing all
   assets with a recommendation, sorted by risk tier descending, with an
   "Export PDF" and "Export CSV" button calling GET /reports/{scanId}.

Use Tailwind CSS for styling with a coherent, intentional visual identity
(not default browser styling) - dark, technical/security-tool aesthetic is
appropriate for this domain. Use Recharts for the donut and any standard
charts; build the quadrant/bubble chart as a custom component since Recharts
doesn't have a built-in quadrant chart type. Handle loading and empty states
explicitly on every view (a scan in progress, zero assets found, etc.).
```

### Prompt 9 — M9: Reporting & Export Engine
```
Build the reporting/export module for ECDAT (design doc Section 7 / M9).

Requirements:
1. CBOM JSON export: given a scanId, return the already-generated CycloneDX
   1.6 document (this may already exist from M4/M7 - just expose it as a
   clean, downloadable file with correct filename and content-type).
2. PDF executive summary report: given a scanId, generate a PDF (using
   WeasyPrint or ReportLab - pick whichever is easier to get producing clean
   output quickly) containing: a title page, a risk-tier distribution summary
   (counts + simple bar representation), a table of the top 15 highest-risk
   assets with their recommendation, and a one-paragraph plain-language
   summary of the overall posture (e.g. "X of Y cryptographic assets are
   quantum-vulnerable; Z are Critical and require action within
   [migration-time] to remain safe under a [Z-year] threat-timeline
   assumption").
3. CSV/XLSX export: given a scanId, produce a flat spreadsheet (use openpyxl)
   with one row per asset: type, algorithm, file/location, library, key size,
   business criticality, exposure, risk tier, risk score, recommended
   algorithm, migration complexity.
4. Expose all three as a single function
   `generate_report(scan_id: str, format: Literal["pdf","csv","json"]) ->
   bytes` in `backend/engine/reporting/`, so M7's
   GET /reports/{scanId}?format=... endpoint is a thin wrapper around this.
5. Unit tests: generate a report from a small fixture CBOM document (2-3
   assets) for each format and assert the output is well-formed (valid PDF
   header, valid XLSX opens with openpyxl, valid JSON parses).
```

---

*End of document. Good luck — scope the MVP honestly, get the CBOM schema and API contract frozen on Day 1, and let the four tracks run in parallel from Day 2 onward.*
