.PHONY: lint flake build help all test test-quick test-check-plugs test-updateDuckDns test-archer1200 test-duckdns test-noip

MAKEPATH := $(abspath $(lastword $(MAKEFILE_LIST)))
PWD := $(dir $(MAKEPATH))


# Use venv python if available
PYTHON := .venv/bin/python
ifeq ($(shell which $(PYTHON) 2>/dev/null),)
PYTHON := python
endif

#help:
#		@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/^# Fichiers/,/^# Base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$'

# https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help: ## generate help list
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

all: lint flake build

lint: ## lint python files
		pylint .

flake: ## lint python files
		flake8 .

outdated: ## check dep versions
		pip list --outdated

deps-check: ## check dependencies with pipdeptree, safety, and pip-review
	@echo "=== Checking dependency tree ==="
	@pipdeptree
	@echo -e "\n=== Checking for security vulnerabilities ==="
	@safety check || true
	@echo -e "\n=== Checking for outdated packages ==="
	@pip-review
	@echo -e "\n=== Done ==="

test: ## run all unit tests with coverage
		@echo "Running all unit tests with coverage..."
		# Install coverage if not available (for CI)
		[[ -z ${CI_JOB_ID:-} ]] && sudo apt install -y --no-install-recommends python3-coverage || true
		# Run all tests with coverage
		$(PYTHON) -m coverage run -m pytest tests/ -v
		# Generate coverage reports
		$(PYTHON) -m coverage html
		$(PYTHON) -m coverage report
		@echo "Tests completed. Open htmlcov/index.html to view coverage report."

test-quick: ## run all unit tests quickly without coverage
		@echo "Running all unit tests without coverage..."
		$(PYTHON) -m pytest tests/ -v

test-check-plugs: ## run check_plugs tests only
		@echo "Running check_plugs tests..."
		$(PYTHON) -m pytest tests/test_check_plugs.py -v

test-updateDuckDns: ## run updateDuckDns tests only
		@echo "Running updateDuckDns tests..."
		$(PYTHON) -m pytest tests/test_updateDuckDns.py -v

test-archer1200: ## run archer1200 tests only
		@echo "Running archer1200 tests..."
		$(PYTHON) -m pytest tests/test_archer1200.py -v

test-duckdns: ## run duckdns tests only
		@echo "Running duckdns tests..."
		$(PYTHON) -m pytest tests/test_duckdns.py -v

test-noip: ## run noip tests only
		@echo "Running noip tests..."
		$(PYTHON) -m pytest tests/test_noip.py -v

func: ## run archer functionnal tests
		./tests/test_archer1200.py -f

report: ## get cover report
		coverage json
		coverage html
		coverage report

up:
		docker compose -f compose.yml up

updt:
		pip3 list -o --format json | jq -r .[].name | xargs -I % pip3 install --upgrade %;
