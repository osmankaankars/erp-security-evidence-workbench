# Third-party notices

## Scope

This inventory covers the `0.1.0rc1` prerelease candidate and distinguishes the application runtime
from build and test tooling. It is not legal advice and is not a vulnerability-clearance report.

## Runtime dependencies

The project declares no third-party runtime dependencies (`dependencies = []`). The runtime wheel
contains this project's Python package and distribution metadata. This statement does not
reclassify the Python standard library as project code and does not establish that an artifact is
vulnerability-free.

## Python standard library and platform

Python, its standard library, and operating-system components are platform prerequisites; they are
not vendored into this project's wheel or source distribution. Python is distributed under the
Python Software Foundation license terms and additional notices supplied with the selected Python
distribution. Platform components remain under their distributors' terms.

## Build and development tools

The following direct tools are pinned in `pyproject.toml`. They are used only for build, test, lint,
type checking, or local validation and are not included in the runtime wheel.

| Tool | Pinned version | Role | Recorded upstream license identifier |
| --- | --- | --- | --- |
| `build` | `1.6.0` | PEP 517 frontend | MIT |
| `jsonschema` | `4.26.0` | Offline SARIF schema tests | MIT |
| `mypy` | `1.20.2` | Static type checking | MIT |
| `pytest` | `8.4.2` | Test runner | MIT |
| `ruff` | `0.16.5` | Lint and format checks | MIT |
| `setuptools` | `84.0.0` | PEP 517 build backend | MIT |
| `wheel` | `0.48.0` | Wheel build support | MIT |

These labels are an inventory aid, not a legal conclusion. Development-tool transitive
dependencies are not a runtime dependency set and are not fully locked or reproduced here. A
release operator remains responsible for reviewing the exact build environment, transitive
inventory, controlling licenses, and notices.

## OASIS SARIF 2.1.0 test schema

`tests/schemas/oasis/sarif/2.1.0/sarif-schema-2.1.0.json` is an unchanged, development-only copy of
the OASIS Standard SARIF 2.1.0 schema, acquired from the OASIS publication dated 27 March 2020. It is
used for offline conformance tests and is not included in the runtime wheel or minimal source
distribution.

Copyright © OASIS Open 2020. All Rights Reserved.

OASIS permits the work product to be copied and furnished, in whole or in part, when its copyright
and notice terms are retained; the document may not be modified and is supplied on an “AS IS”
basis. The controlling provenance, checksum, and notice link are recorded in
`tests/schemas/oasis/sarif/2.1.0/SOURCE.md`.

## Project license and public-release status

ERP Security Evidence Workbench is licensed under the MIT License; see [LICENSE](LICENSE). The MIT
License covers this project's original material and does not replace third-party terms.

The GitHub prerelease and its checksums or SPDX inventory do not constitute legal, security, or
vulnerability clearance. Public package publication, including publication to PyPI or another
package index, is a separate release action and is not implied by repository availability.
