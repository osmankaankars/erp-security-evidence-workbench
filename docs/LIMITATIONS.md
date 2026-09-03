# Limitations

## Product and evidence limitations

- This is a prerelease reference implementation, not a production-ready product or service.
- It analyzes only explicitly supplied synthetic files. It does not connect to SAP, Oracle, an ERP,
  a database, a cloud service, a log platform, or any live system.
- It does not collect credentials, discover assets, scan a network, exploit a target, change an
  account/configuration, or remediate a finding.
- Nine generic project rules are not a vendor audit method, organization policy, regulatory mapping,
  complete risk assessment, or proof of compliance.
- `coverage: complete` means only that the supplied files were completely processed and contained
  the minimum record types required by the selected rules. A clean report does not prove absence of
  risk, source-system completeness, security, or compliance.
- `dataset_classification: synthetic` is validated as a schema value; the tool cannot prove the
  origin or privacy of the bytes. Real, transformed, anonymized, employer, or customer data remains
  prohibited.
- Replay consumes only local, digest-pinned files and documentation-range IP indicators. It does
  not update a feed, establish indicator quality, identify a real attacker, or prove that a timing
  pattern is malicious. Correlation hashes are reproducible identifiers, not signatures.
- Source identity checks detect changes around the checked read, but they do not authenticate who
  created the source. SHA-256 records the consumed bytes; it is not a signature, attestation, or
  proof that the file is authoritative. The tool does not lock the source against other processes.

## Filesystem and platform limitations

- Filesystem hardening targets local POSIX semantics exercised on macOS/Linux with Python
  3.11+. Windows, remote/network filesystems, FUSE implementations, unusual hard-link semantics,
  and filesystems without the required descriptor-relative APIs are not supported or claimed.
- Final-component input symlinks and non-regular files are refused. Symlinked ancestor directories
  are resolved to one real parent directory and then descriptor-anchored.
- Successful reads compare device, inode, type/mode, owner/group, size, `mtime_ns`, and `ctime_ns`
  before/after parsing. Access time is intentionally excluded and may change when the OS reads a
  file. “Unchanged input” claims cover bytes, permission bits, and modification time, not atime.
- These checks detect mutation at defined checkpoints; they do not create a kernel-enforced
  immutable snapshot. A same-UID attacker may race after the last check or alter a textual namespace
  after the directory binding was verified.
- The publisher rejects group- or world-writable non-sticky output directories. Sticky shared
  directories such as the system temporary directory and operator-controlled directories without
  shared write bits are supported. This mode-bit check does not inspect POSIX ACLs, extended
  permissions, or another host access-control layer; the operator must still choose a directory
  whose effective access is trusted. Sticky-bit enforcement remains subject to the host filesystem.
- Portable Python 3.11 cannot hard-link directly from an unnamed/open file descriptor on both macOS
  and Linux. Publication therefore requests a random named temporary inode no broader than `0600`,
  forces exact mode `0600` before writing, then uses descriptor-relative linking and pre/post
  identity checks. A malicious process with unrestricted access as
  the same user remains outside the protection claim.
- Existing outputs are never intentionally replaced. No overwrite option exists.
- On the normal, single-threaded POSIX CLI path using Python's default
  `SIGINT`-to-`KeyboardInterrupt` handler, `SIGINT` is blocked before either descriptor-anchored
  input or publication flow can acquire a descriptor and remains blocked through its complete
  descriptor/name-owning scope. Bounded safe-point checks inspect for a pending signal during input
  and immediately before report linking and commit; outer cleanup makes bounded close attempts for
  every recorded descriptor and identity-aware name-removal attempts before the prior thread mask is restored and
  `KeyboardInterrupt` propagates. The input reader keeps sole descriptor ownership outside its
  non-owning binary wrapper, and acquisition helpers additionally record a returned descriptor
  before they return. Cooperative Python exceptions raised by the protected worker also reach the
  outer cleanup. This is not a blanket arbitrary-`BaseException` guarantee: a replaced/interposed
  call that creates a kernel descriptor and raises before returning it, or an interposed cleanup
  primitive that itself raises a non-OS exception, is a compromised-runtime case outside the boundary.
  A signal that first becomes pending after the publisher's last pre-commit safe-point check is
  treated as post-commit: it may propagate after cleanup while the verified complete final remains.
  This guarantee does not extend to a multithreaded embedding host with another
  `SIGINT`-unblocked thread or to a custom signal handler: process-directed delivery through another
  thread can cause Python to run the handler before a returned descriptor is recorded, and a custom
  handler defines its own semantics. Such hosts must establish their own process-wide signal policy
  before calling the lower-level modules. If `SIGINT` was already blocked on entry, the prior mask
  and pending-signal policy are preserved and no `KeyboardInterrupt` is synthesized. Interruption
  is checkpoint-based: the signal remains deferred during resolve/parse/write/`fsync`/verify/cleanup
  work, repeated standard signals may coalesce, and this mechanism cannot cancel a hung syscall.
  Other fatal signals, `SIGKILL`, power loss, kernel panic, hardware failure, secure erasure, and
  crash-durable directory entries are not guaranteed. Parent-directory `fsync` is not performed.
- A persistent post-commit cleanup failure can leave a hidden mode-`0600` temporary hard link next
  to the complete final report. The report remains authoritative; cleanup failure is not reported as
  a false publication failure.
- All pre-commit cleanup is also bounded best effort within that supported runtime boundary.
  Interruption immediately after creation and repeated unlink failure can leave an empty temporary
  whose mode is no broader than `0600`; the
  caller may not yet have forced exact mode. If a descriptor write, file synchronization, or temporary
  verification later fails and unlink repeatedly fails, a partial or complete exact-`0600`
  temporary report can remain. If a fully written final link was created but
  its verification failed, independent cleanup attempts can leave one or both of the complete final
  and temporary names even though the operation reports failure. No partial report is deliberately
  promoted to the requested name, but the operator must inspect and remove private residual names.
- Basename uniqueness is exact and case-sensitive on the supported host. Unicode normalization and
  case-fold collisions may behave differently if artifacts are copied to another filesystem.

The implemented filesystem checks are in
`adapters.parse_source` and `reporting.write_new_report` plus their private descriptor helpers.

## Resource and performance limitations

- `analyze` accepts at most 32 evidence files; `replay` accepts one manifest plus 2–32 declared
  source files. Each file is limited to 1 MiB/1,000 parser records. The 32 MiB replay byte ceiling
  counts manifest and source bytes together, while the 5,000-record ceiling counts normalized
  evidence records. JSONL lines/CSV physical rows are limited to 64 KiB, scalars to 4,096
  characters, objects to 32 fields, and JSON depth to 8 (`adapters.IngestLimits`).
- A run is rejected before rendering if its retained findings would exceed 30,000 evidence
  references (`rules.MAX_FINDING_EVIDENCE_REFS` and `rules.evaluate_rules`).
- These are denial-of-service ceilings, not throughput, latency, or memory guarantees. A valid
  maximum input and multi-format report can still be large. Parsing, canonical records, findings,
  and rendered report bytes are held in ordinary process memory. There is no cross-machine
  benchmark, runtime timeout, hard process-memory limit, or SLA. The recorded local performance
  observation is environment-qualified.
- The evidence-reference budget is checked after one fixed rule evaluator returns its bounded
  candidate tuple and before findings are retained/rendered. It prevents pathological fixed-rule
  fan-out from becoming a report, but it is not a general-purpose sandbox.

## Privacy and reporting limitations

- CLI orchestration checks the input/output relationship and pairs ingestion, evaluation,
  rendering, and publication. Direct Python use is lower level: report builders return ordinary
  in-memory bytes, and `write_new_report` enforces filesystem publication properties but accepts
  arbitrary bytes. Embedding callers own sequencing, signal/thread policy, matching rule
  parameters, retention, and any transport.
- JSON always discloses minimized source and evidence manifests with basenames, digests, bounded
  counts, format/adapter IDs, record IDs, and exact locators, including on clean runs. SARIF always
  discloses the minimized source inventory and adds record IDs/locators only for findings. HTML
  limits provenance to each rendered finding and a clean HTML report omits the source inventory.
  Every format must be treated as potentially sensitive and is not automatically secret-redacted.
- HTML escaping and a restrictive self-contained design reduce injection/network risk, but do not
  certify every downstream browser or viewer.
- SARIF conformance testing uses a local pinned schema; it does not certify every consumer or imply
  OASIS endorsement.
- SHA-256 is used for deterministic identity and integrity provenance, not encryption or
  anonymization.

## Development and release limitations

- Runtime dependencies are empty. The RC SPDX document records the wheel's exact unresolved
  dependency declarations, including optional `dev` extras, but development/bootstrap dependencies
  are not represented by a fully resolved, hash-locked, platform-specific transitive lockfile.
- The CI definition pins its actions, limits the GitHub token to `contents: read`, and disables
  checkout credential persistence. Those controls do not make runner execution read-only:
  checked-out pull-request code and
  development dependencies write the ephemeral workspace and execute with runner process and
  available network authority. Self-hosted runners require a separately reviewed trust boundary.
- The normal CLI is not an operating-system sandbox. Local installed-command verification injects a
  focused hook for `socket.*` and selected process-launch audit events; it does not cover every
  primitive and is regression evidence, not containment.
- A local `pip check` and metadata inventory are consistency evidence, not a vulnerability audit or
  legal opinion.
- Release-candidate checks, source manifests, SPDX metadata, and checksums are bounded engineering
  evidence. They do not establish production readiness, legal or vulnerability clearance,
  cryptographic provenance, or publication to a package index.
- Source snapshots require the local Git executable and a resolvable committed `HEAD`; they reject
  dirty tracked/index state, hidden index flags, symlinks, gitlinks, and special tree entries. They
  hash committed blobs rather than working-tree bytes, but they do not independently validate a
  compromised Git executable or object database and are not signed attestations.
- Tag-to-commit identity and uploaded asset checks remain separate GitHub release-stage
  verifications; a local source-snapshot manifest alone does not prove publication state.
