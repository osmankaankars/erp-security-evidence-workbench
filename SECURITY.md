# Security policy

## Supported versions

This project is currently a prerelease. Security reports are accepted for the following version:

| Version | Security reports |
| --- | --- |
| `0.2.0rc1` | Accepted |
| `0.1.0rc1` | Not supported |
| Earlier development snapshots | Not supported |

## Reporting a vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/osmankaankars/erp-security-evidence-workbench/security/advisories/new).
Do not disclose a suspected vulnerability in a public issue, discussion, pull request, sample file,
or generated report.

Include only the minimum information needed to reproduce the concern:

- affected version and operating system;
- a concise impact description;
- synthetic reproduction steps or a synthetic fixture;
- relevant logs with paths, identifiers, tokens, and personal data removed.

Do not send secrets, real ERP evidence, exploit payloads targeting third parties, customer details,
or sensitive filesystem paths. The maintainer will acknowledge a usable report when practical and
will coordinate validation and disclosure through the private advisory.

## Security boundary

The CLI accepts explicit local synthetic CSV, JSON, or JSONL files, and a digest-pinned local replay
manifest, validates fixed schemas, evaluates deterministic rules, and may publish one new local
JSON, HTML, or SARIF report. It has no
ERP connector, credential collection, network scanner, writeback, remediation, telemetry, or
third-party runtime dependency.

Filesystem controls target documented local POSIX behavior. They do not isolate root, another
process with the same user identity, a compromised interpreter or kernel, a hostile network
filesystem, or an embedding host with incompatible signal/thread handling. Development bootstrap
and CI tooling are separate supply-chain boundaries and may use the network.

Only independently authored, non-secret synthetic input is permitted. Generated reports retain
limited provenance and must still be handled as potentially sensitive. See the
[threat model](docs/THREAT_MODEL.md), [privacy model](docs/PRIVACY_MODEL.md), and
[limitations](docs/LIMITATIONS.md) for assumptions and residual risks.
