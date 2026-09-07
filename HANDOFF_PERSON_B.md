# M1/M2/M3 → Person B — Handoff Package

## What you're getting

1. **`backend/scanners/_finding.py`** — Pydantic `RawFinding` model pinned to
   CONTRACT.md §1. This is the **lock-point file** — if CONTRACT.md v1.1
   adds/removes/renames a field, this is the only M1/M2/M3 file that
   changes, plus the parallel schema below.
2. **`shared/schemas/raw_finding.schema.json`** — JSON Schema mirroring
   CONTRACT.md §1. Use this for runtime validation on the M4 side.
3. **`backend/scanners/cli.py`** — CLI signature:
   `python -m backend.scanners <path> [--scan-target-id ID] [--out file.json]`
4. **`t17_sample_findings.json`** — 40-finding sample output from running
   the CLI against `seed_corpus/`.
5. **`detectionTier` vocabulary** — the published set of strings M1/M2/M3
   emit today (wire contract — changing these is a breaking change for M4).

## `detectionTier` vocabulary (wire contract)

The exact strings currently emitted, with the module that uses them:

| `detectionTier`   | Emitted by | Meaning |
|-------------------|-----------|---------|
| `regex`           | M1 Tier-1 | Cheap regex pre-filter, not AST-confirmed |
| `ast`             | M1 Tier-2 | tree-sitter AST-confirmed call site |
| `manifest`        | M2        | `(library, version)` row from requirements.txt / package.json / go.mod / pom.xml |
| `symbol-scan`     | M2 binary | crypto symbol from ELF/PE symbol table (higher confidence) |
| `binary-string`   | M2 binary | crypto string matched by pure-Python strings fallback |
| `dockerfile`      | M3        | FROM / RUN install line in a Dockerfile |
| `config-parse`    | M3        | ssl_protocols / ssl_ciphers directive |
| `iac-parse`       | M3        | aws_kms_key / azurerm_key_vault_key / google_kms_key_ring resource |
| `cert-parse`      | M3        | X.509 rule firing on a parsed cert |

## `sourceModule` allowed values (wire contract)

`M1_source_scanner` | `M2_dep_binary_scanner` | `M3_container_config_scanner`

## Measured metrics against `seed_corpus/`

```
M1 Tier-1+Tier-2: recall=0.92  precision=0.86
M2 manifests:      recall=1.00  precision=1.00
M3 certs:          recall=1.00  precision=1.00
M3 configs:        recall=1.00  precision=1.00
M3 IaC:            recall=1.00  precision=1.00
```

M1 target was ≥0.85 — both recall and precision clear the bar.

## Open questions (not blockers, please weigh in)

1. **Cert `flagReason` field.** CONTRACT.md §1 has no field for *why* a
   cert was flagged. M3 certs currently encodes the reason in the
   `library` field as a free-form string like
   `"flag:small-rsa-key-1024-bits"`. Proposal for v1.1: add a
   `flagReason: str` field to `RawFinding` so the reason is structured
   rather than smuggled. (You can also see this in every `cert-parse`
   finding's `library` value in `t17_sample_findings.json`.)
2. **Container image scanning** — `M3.scan_container_image` raises
   `NotImplementedError` (Trivy shell-out is §17 roadmap). It will
   surface loudly to anyone calling it.
3. **CLI vs. import preference** — M4 can either call the
   `python -m backend.scanners <path>` CLI, or import directly via
   `from backend.scanners.source.scanner import scan_repository` etc.
   The three `scan_*` entrypoints are the public surfaces.

## Day-1 done criteria

- [x] `python -m backend.scanners seed_corpus/` exits 0, emits valid JSON array
- [x] `pytest backend/tests/` exits 0 (26/26)
- [x] Per-module recall ≥ 0.85 against `seed_corpus/`
- [x] Every emitted RawFinding has every CONTRACT.md §1 field present
- [x] `sourceModule` ∈ {M1, M2, M3}
- [x] `detectionTier` vocabulary documented
- [x] `seed_corpus/` has fixtures for every cell of the T1 matrix
- [x] Handoff package delivered
