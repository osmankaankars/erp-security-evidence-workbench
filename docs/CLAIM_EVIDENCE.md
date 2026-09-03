# Claim-to-evidence map

This map separates implemented behavior, environment-qualified observations, and release state. A
passing check supports only the exercised contract; it is not a certification, compliance opinion,
security guarantee, or conclusion about an unobserved environment.

| Statement | Evidence | Permitted status |
| --- | --- | --- |
| Runtime analysis is offline and declares no third-party dependency | `dependencies = []`; source-import review; network/process-denial tests; installed-wheel smoke under a focused audit hook | Implemented for exercised CLI paths; not an OS sandbox |
| Only fixed synthetic CSV, JSON, and JSONL evidence is accepted | Strict normalization and adapter tests; validation fixtures; [SYNTHETIC_DATA_POLICY.md](SYNTHETIC_DATA_POLICY.md) | Implemented contract; origin labels cannot be independently proven |
| Multi-file ingestion fails closed | Malformed-tail, duplicate-ID, missing-coverage, mutation, and aggregate-limit tests | Implemented for documented bounds |
| Six evidence rules and three replay rules are deterministic and evidence-linked | Registry/catalog, parameter, boundary, replay, ordering, dedupe, window, and fingerprint tests | Implemented for supplied accepted evidence |
| Digest-pinned multi-source replay remains synthetic and offline | Manifest/adapter failure tests, documentation-range enforcement, local indicator tests, installed-wheel audit guard | Implemented for the documented contract; digests are not signatures |
| JSON, HTML, and SARIF describe one validated engine outcome | Cross-format oracles for v1 and v2, SARIF schema validation, HTML self-containment and escaping checks | Implemented; downstream viewers remain separate trust boundaries |
| Existing reports are not overwritten and successful reports use mode `0600` | Filesystem race, interruption, collision, mode, and publication-state tests | Implemented under documented POSIX and same-host assumptions |
| Generated scenarios and example reports are reproducible | Generator check modes, SHA-256 manifests, repeated byte-for-byte report runs | Locally verified; not source authenticity |
| Wheel and source distribution are reproducible | Two independently staged builds compared at fixed `SOURCE_DATE_EPOCH`, followed by manifest and checksum verification | Environment-qualified build evidence |
| CPython 3.11–3.14 are targeted | Historical `0.1.0rc1` local/remote matrix; current `0.2.0rc1` local CPython 3.11.14 result; fresh macOS/Linux exact-revision matrix remains a release gate | Supported target only after the candidate matrix passes; current local evidence is CPython 3.11.14 |
| The tool has a documented performance observation | Deterministic 900-record synthetic JSONL run measured from an installed package | One local observation; not an SLA or cross-machine benchmark |
| Release artifacts have bounded contents, SPDX metadata, and checksums | Exact archive-member policies, deterministic SPDX JSON, SHA-256 list, and artifact safety tests | Inventory and integrity evidence; not vulnerability or legal clearance |
| The source snapshot is bound to one committed revision | Resolved-`HEAD` tree/blob hashing; no-fallback, dirty-state, hidden-index-flag, linked-worktree, ignored-file, symlink, and gitlink regression tests | Commit-bound integrity evidence; not a signed attestation or independent Git-object verification |
| The project is MIT licensed | `LICENSE`, package metadata, and packaged license-file checks | Implemented for this project's original material |
| A GitHub prerelease exists for a revision | Repository tag, release metadata, attached assets, and successful CI history for that revision | Claim only after those remote artifacts are observable |

## Prohibited extrapolations

Do not describe this work as an ERP connector, live scanner, autonomous remediation system,
certified control framework, production SOC platform, complete detector, penetration-testing tool,
or proof of NIS2, DORA, ISO/IEC 27001, or another regulatory requirement. Do not call a local timing
observation a benchmark across machines or workloads. Do not call an SPDX or dependency inventory
a vulnerability audit or legal opinion.
