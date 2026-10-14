# Local quality pipeline. CI runs the same target.
# Every target fails the build on the first error.

GITLEAKS_VERSION := 8.30.1
ACTIONLINT_VERSION := 1.7.12
MUTATION_PATHS := src/scenario_tools/domain/policy src/scenario_tools/domain/verification

.PHONY: check lint format types imports tests coverage-domain security audit secrets sheets mutation

check: lint format types imports tests coverage-domain security audit secrets sheets workflows mutation
	@echo "Local pipeline: all checks passed."

lint:
	uv run ruff check .

format:
	uv run ruff format --check .

types:
	uv run mypy

imports:
	uv run lint-imports

tests:
	uv run pytest --cov --cov-report=term-missing

# The domain layer must be fully covered (branches included), measured on the run above.
coverage-domain: tests
	uv run coverage report --include='src/scenario_tools/domain/*' --fail-under=100

security:
	uv run bandit -q -c pyproject.toml -r src

audit:
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	uv export --frozen --format requirements-txt --no-emit-project --quiet -o "$$tmp/requirements.txt" && \
	uv run pip-audit --strict --disable-pip --require-hashes -r "$$tmp/requirements.txt"

# Every entry's sheet is the one render writes, whatever changed it: an exception granted in
# another pull request leaves a sheet out of date that the entry's own checks never read.
sheets:
	find scenarios -mindepth 2 -maxdepth 2 \( -type d -o -type l \) \
		-exec uv run scenario-tools render --check -- {} +

# The working copy's secrets, a check for the author: what gates a pull request is its workflow's
# scan, with the target branch's rules, of its entries and of every commit it brings.
secrets:
	@gitleaks version | grep -qx '$(GITLEAKS_VERSION)' || { echo "gitleaks $(GITLEAKS_VERSION) required"; exit 1; }
	gitleaks dir . --config .gitleaks.local.toml --no-banner --redact

# The workflows: actionlint for their syntax and expressions, zizmor for their security.
workflows:
	@actionlint -version | head -1 | grep -qx '$(ACTIONLINT_VERSION)' || { echo "actionlint $(ACTIONLINT_VERSION) required"; exit 1; }
	actionlint
	uv run zizmor --offline --min-severity informational .github/workflows/

# Mutation testing on the security-critical bounded contexts, once they hold code.
# `mutmut results` lists every mutant that was not killed; any line fails the build.
mutation:
	@if find $(MUTATION_PATHS) -name '*.py' ! -name '__init__.py' 2>/dev/null | grep -q .; then \
		uv run mutmut run && \
		survivors=$$(uv run mutmut results) && \
		if [ -n "$$survivors" ]; then echo "$$survivors"; echo "mutation: surviving mutants"; exit 1; fi; \
	else \
		echo "mutation: no policy or verification module yet, skipped"; \
	fi
