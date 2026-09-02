# Dependency and CI review

## Scope and conclusion

The `0.1.0rc1` candidate declares no application runtime dependencies:

```toml
dependencies = []
```

Runtime imports are limited to the Python standard library and this package. The wheel declares
seven optional `dev` requirements and no unconditional `Requires-Dist` entry. Release SPDX
metadata records these exact unresolved declarations; it is not a resolved-environment or
vulnerability inventory.

## Declared Python tooling

| Layer | Exact declaration | Purpose | Runtime status |
| --- | --- | --- | --- |
| Build | `setuptools==84.0.0` | PEP 517 build backend | Development/build only |
| Development | `build==1.6.0` | PEP 517 frontend | Not imported at runtime |
| Development | `jsonschema==4.26.0` | Offline SARIF schema validation | Not imported at runtime |
| Development | `mypy==1.20.2` | Static type checking | Not imported at runtime |
| Development | `pytest==8.4.2` | Tests | Synthetic fixtures only |
| Development | `ruff==0.16.5` | Lint and format checks | Not imported at runtime |
| Development | `wheel==0.48.0` | Build and package smoke | Not imported at runtime |

A local candidate matrix exercised exact CPython `3.11.14`, `3.12.12`, `3.13.7`, and
`3.14.5` environments with compilation, Ruff, strict mypy, pytest, index-disabled installed-package
smoke, and `pip check`. This is environment-qualified engineering evidence, not legal advice or a
vulnerability audit.

Observed transitive development packages include `attrs`, `iniconfig`,
`jsonschema-specifications`, `librt`, `mypy_extensions`, `packaging`, `pathspec`, `pluggy`,
`Pygments`, `pyproject_hooks`, `referencing`, `rpds-py`, and `typing_extensions`. Their
platform wheels, hashes, controlling notices, and complete transitive license obligations are not
locked by this document. No project virtual environment belongs in source control.

## Release VCS tooling

Git is not an application runtime dependency. The local `git` executable and repository object
database are required only when producing the commit-bound source-snapshot release asset. That
operation resolves `HEAD`, reads regular-file tree/blob objects, and fails closed on dirty tracked
state, hidden index flags, unsupported entries, or Git errors. It does not fall back to recursively
reading the working tree.

## Bootstrap and installed-wheel boundary

`make bootstrap` may contact the configured Python package index for development tooling. That is
a development supply-chain action, not application runtime behavior. An approved local wheelhouse
can be selected through explicit pip options documented in the README.

`scripts/package_smoke.py` builds and installs the project in a fresh temporary environment with
package-index access and runtime dependency resolution disabled. Installed commands run under a
verification hook that rejects `socket.*`, `subprocess.Popen`, `os.system`, `os.posix_spawn`,
and `os.posix_spawnp` audit events. The hook covers the exercised paths only; it is not an
operating-system sandbox and does not establish trust in bootstrap tooling.

## CI action policy

The workflow in `.github/workflows/ci.yml`:

- pins `actions/checkout` and `actions/setup-python` to full commit SHAs;
- limits GitHub token permissions to `contents: read`;
- disables checkout credential persistence;
- runs only on `push` and `pull_request`;
- declares `ubuntu-24.04` and `macos-15` with Python 3.11–3.14;
- invokes the same `make check` gate used locally;
- grants no repository write, secret, artifact-upload, or OIDC permission.

`contents: read` constrains the GitHub token, not the runner. A job still creates a virtual
environment, resolves development tools, writes its ephemeral filesystem, and executes checked-out
code with the runner's process and available network authority. Pull-request trust and dependency
installation therefore remain supply-chain boundaries. Self-hosted runners are outside this
review.

The repository's GitHub Actions run history, rather than this static document, is the authority for
whether a particular revision completed the remote matrix.

## Residual supply-chain limits

- There is no hash-locked, platform-specific transitive development lock.
- The SPDX file inventories wheel declarations, not resolved installations or vulnerabilities.
- No independent vulnerability-database result is claimed.
- Reproducible bytes, checksums, and `pip check` do not mean “secure,” “vulnerability-free,” or
  legally cleared.
- A tag is not cryptographically signed unless its signature can be verified.

See [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) for the notice inventory and
[REPRODUCIBILITY.md](REPRODUCIBILITY.md) for the build contract.
