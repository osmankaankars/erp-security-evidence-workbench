BOOTSTRAP_PYTHON ?= python3.11
VENV ?= .venv
VENV_PYTHON ?= $(VENV)/bin/python
PIP_INSTALL_ARGS ?=

.PHONY: bootstrap check ci compile format-check lint package-smoke test typecheck

bootstrap:
	$(BOOTSTRAP_PYTHON) -m venv "$(VENV)"
	"$(VENV_PYTHON)" -m pip --disable-pip-version-check install --upgrade \
		$(PIP_INSTALL_ARGS) --editable ".[dev]"

check: compile lint format-check typecheck test package-smoke

ci: check

compile:
	"$(VENV_PYTHON)" -m compileall -q src tests scripts

lint:
	"$(VENV_PYTHON)" -m ruff check .

format-check:
	"$(VENV_PYTHON)" -m ruff format --check .

typecheck:
	"$(VENV_PYTHON)" -m mypy --strict --no-incremental src

test:
	"$(VENV_PYTHON)" -m pytest -q

package-smoke:
	"$(VENV_PYTHON)" scripts/package_smoke.py
