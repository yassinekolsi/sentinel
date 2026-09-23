# SENTINEL developer commands. All targets run offline after `make setup`.
UV ?= uv
DEFENSE ?= provenance
SCENARIO ?= scenarios/public/finance/finance_false_approval.yaml

.PHONY: help setup check lint format typecheck test test-security test-kits run-baseline eval-public \
        eval-validation scenarios fixtures schema clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

setup: ## Install Python 3.12 environment with dev tools (uses uv.lock)
	$(UV) sync --frozen --python 3.12

check: ## Run the full local CI gate: lint, types, tests, starter kits, and scenarios
	$(UV) run --frozen python scripts/dev.py check

lint: ## Ruff lint + format check
	$(UV) run --frozen ruff check src tests scripts starter-kits
	$(UV) run --frozen ruff format --check src tests scripts starter-kits

format: ## Apply ruff formatting and safe fixes
	$(UV) run --frozen ruff check --fix src tests scripts starter-kits
	$(UV) run --frozen ruff format src tests scripts starter-kits

typecheck: ## mypy on the sentinel package
	$(UV) run --frozen mypy

test: ## Full offline test suite (unit, integration, security) plus starter kits
	$(UV) run --frozen pytest
	$(MAKE) test-kits

test-security: ## Security regression tests only
	$(UV) run --frozen pytest tests/security -m security

test-kits: ## Starter kit test suites
	cd starter-kits/python-defense && $(UV) run --project ../.. --frozen pytest -q
	cd starter-kits/learned-monitor && $(UV) run --project ../.. --frozen pytest -q

run-baseline: ## Run one scenario with a baseline defense and print the timeline
	$(UV) run --frozen sentinel run --scenario $(SCENARIO) --defense $(DEFENSE)

eval-public: ## Deterministic scorecard on public scenarios (in-process baseline defense)
	$(UV) run --frozen sentinel eval public --defense $(DEFENSE)

eval-validation: ## Scorecard on validation scenarios
	$(UV) run --frozen sentinel eval validation --defense $(DEFENSE)

scenarios: ## Validate all public and validation scenarios
	$(UV) run --frozen sentinel scenarios validate scenarios

fixtures: ## Regenerate synthetic fixtures and public/validation scenarios
	$(UV) run --frozen sentinel fixtures generate --scenarios

schema: ## Export scenario JSON Schema
	$(UV) run --frozen sentinel scenarios schema --out scenarios/schemas/scenario.schema.json

clean: ## Remove generated artifacts and caches
	rm -rf artifacts dist .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
