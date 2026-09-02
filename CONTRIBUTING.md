# Contributing

Contributions are welcome when they preserve the project's synthetic-only, offline, input-read-only
boundary. For a bug or feature proposal, use the repository issue forms before starting a large
change. Security vulnerabilities belong in a private report under [SECURITY.md](SECURITY.md), not a
public issue.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Non-negotiable boundaries

- Use only fictional evidence authored independently for this repository.
- Do not submit employer, customer, production, test-tenant, training, anonymized, transformed,
  redacted, or otherwise real data.
- Do not add credentials, hostnames, account identifiers, vendor transaction codes, screenshots,
  logos, proprietary role matrices, or copied control mappings.
- Preserve the offline, input-read-only, non-remediating application runtime.
- Do not add a runtime dependency, connector, telemetry path, dynamic plugin, or network behavior
  without a focused design, provenance, privacy, dependency, and threat-model review.
- Do not weaken fail-closed validation, resource ceilings, deterministic ordering, or no-overwrite
  report publication.

## Local workflow

Use a supported POSIX host and CPython 3.11–3.14:

```bash
make bootstrap
make check
```

The default bootstrap may contact the configured Python package index for development-only tools.
To use an approved local wheelhouse instead:

```bash
make bootstrap PIP_INSTALL_ARGS="--no-index --find-links /absolute/path/to/wheelhouse"
```

Before opening a pull request:

1. Add the smallest regression test that proves the intended behavior.
2. Run `make check` and record any platform-specific gaps.
3. Update documentation when a schema, rule, report, privacy, threat, or limitation contract changes.
4. Confirm new fixtures follow [docs/SYNTHETIC_DATA_POLICY.md](docs/SYNTHETIC_DATA_POLICY.md).
5. Keep the pull request focused and complete its checklist.

## Rules and fixtures

Follow [docs/RULE_AUTHORING.md](docs/RULE_AUTHORING.md) for rule changes. Rule identifiers and
versions are externally visible report data; do not renumber them or silently change their
semantics. Expected fixture outcomes must be explicit reviewed constants rather than values derived
by asking the evaluator to grade its own input.

## Review checklist

- The change has a bounded purpose and explicit failure behavior.
- New data and text have clear, independent provenance and publication rights.
- Diagnostics do not echo untrusted values, paths, record content, or exception text.
- Report bytes remain deterministic for identical accepted inputs and options.
- New output is exclusive and never overwrites an existing path.
- Tests cover clean, finding, malformed, incomplete, privacy, and boundary behavior as applicable.
- Documentation distinguishes implemented behavior, measured observations, and unsupported claims.
