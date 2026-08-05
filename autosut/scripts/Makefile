# =============================================================================
# Makefile - Complete Campaign Execution Pipeline
#
# Targets:
#   make infra-up         - Start infrastructure (Caldera + agents)
#   make infra-down       - Stop infrastructure
#   make execute          - Execute all campaigns
#   make execute-one      - Execute single campaign (CAMPAIGN=name)
#   make clean            - Clean results
#   make status           - Show status
#
# Examples:
#   make infra-up
#   make execute CAMPAIGNS="solarwinds operation_wocao"
#   make execute-one CAMPAIGN=0.solarwinds_compromise RUNS=10
# =============================================================================

# Configuration
DOCKER_COMPOSE := docker compose -f measurement/sut/docker-compose.caldera.yml
PYTHON := python3
SCRIPTS_DIR := measurement/sut/scripts
PROJECT_ROOT := $(shell pwd)

# Default campaigns (top 10)
CAMPAIGNS ?= 0.solarwinds_compromise 0.operation_wocao 0.operation_dream_job 0.sharepoint_toolshell_exploitation 0.c0015 0.3cx_supply_chain_attack 0.apt28_nearest_neighbor_campaign 0.apt41_dust 0.arcanedoor 0.c0010

# Default runs
RUNS ?= 5

# =============================================================================
# INFRASTRUCTURE
# =============================================================================

.PHONY: infra-up infra-down infra-restart status

infra-up:
	@echo "=== Starting Infrastructure ==="
	cd measurement/sut && $(DOCKER_COMPOSE) up -d
	@echo "=== Waiting for Caldera ==="
	@for i in $$(seq 1 30); do \
		if curl -s http://localhost:8888 > /dev/null 2>&1; then \
			echo "Caldera is ready!"; \
			exit 0; \
		fi; \
		echo "  Waiting... ($$i/30)"; \
		sleep 5; \
	done; \
	echo "ERROR: Caldera not ready"; \
	exit 1

infra-down:
	@echo "=== Stopping Infrastructure ==="
	cd measurement/sut && $(DOCKER_COMPOSE) down

infra-restart: infra-down infra-up

status:
	@echo "=== Infrastructure Status ==="
	@cd measurement/sut && $(DOCKER_COMPOSE) ps
	@echo ""
	@echo "=== Testing Caldera ==="
	@curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" http://localhost:8888 || echo "Caldera not responding"

# =============================================================================
# EXECUTION
# =============================================================================

.PHONY: execute execute-one execute-all

execute: infra-up
	@echo "=== Executing Campaigns ==="
	@for campaign in $(CAMPAIGNS); do \
		echo ""; \
		echo ">>> Campaign: $$campaign"; \
		$(PYTHON) $(SCRIPTS_DIR)/execute_campaign.py \
			--campaign $$campaign \
			--runs $(RUNS) \
			--caldera-url http://localhost:8888 \
			|| echo "FAILED: $$campaign"; \
	done

execute-one:
	@if [ -z "$(CAMPAIGN)" ]; then \
		echo "ERROR: CAMPAIGN not set. Usage: make execute-one CAMPAIGN=0.solarwinds_compromise RUNS=10"; \
		exit 1; \
	fi
	@echo "=== Executing Campaign: $(CAMPAIGN) ($(RUNS) runs) ==="
	@$(PYTHON) $(SCRIPTS_DIR)/execute_campaign.py \
		--campaign $(CAMPAIGN) \
		--runs $(RUNS) \
		--caldera-url http://localhost:8888

execute-all: execute

# =============================================================================
# ANALYSIS
# =============================================================================

.PHONY: analyze-results analyze-summary

analyze-results:
	@echo "=== Analyzing Results ==="
	@$(PYTHON) -c "import json; from pathlib import Path; d=Path('$(SCRIPTS_DIR)/results/executions'); rs=[(json.load(open(f)),f) for f in d.glob('*_executions.json')]; t=sum(len(r[0].get('results',[])) for r in rs); s=sum(1 for r in rs for x in r[0].get('results',[]) if x.get('success')); print(f'Total: {t}, Success: {s}, Rate: {s/t*100:.1f}%' if t else 'No results')"

analyze-summary:
	@echo "=== Campaign Summary ==="
	@ls -la $(SCRIPTS_DIR)/results/executions/*.json 2>/dev/null | wc -l | xargs echo "Result files:"

# =============================================================================
# PAPER ARTIFACT VALIDATION (for reviewers)
# =============================================================================

.PHONY: test measurement-pipeline release-check

test:
	@echo "=== Running STICKS Tests ==="
	@$(PYTHON) sticks/tests/test_stix_parser.py
	@$(PYTHON) sticks/tests/test_data.py
	@echo ""
	@echo "=== All tests passed ==="

measurement-pipeline:
	@echo "=== AutoSUT measurement pipeline ==="
	@cd $(SCRIPTS_DIR) && $(PYTHON) generate_sut_specs.py

release-check:
	@echo "=== AutoSUT release check ==="
	@cd $(SCRIPTS_DIR) && bash release_check.sh

# =============================================================================
# CLEANUP
# =============================================================================

.PHONY: clean clean-results clean-all

clean-results:
	@echo "=== Cleaning Results ==="
	@rm -rf $(SCRIPTS_DIR)/results/executions/*
	@mkdir -p $(SCRIPTS_DIR)/results/executions

clean-all: clean-results
	@echo "=== Cleaning Infrastructure ==="
	cd measurement/sut && $(DOCKER_COMPOSE) down -v

# =============================================================================
# HELP
# =============================================================================

.PHONY: help

help:
	@echo "Available targets:"
	@echo ""
	@echo "  Reviewer validation (no infrastructure required):"
	@echo "    make test                - Run unit tests"
	@echo "    make measurement-pipeline - Reproduce the AutoSUT measurement pipeline"
	@echo "    make release-check        - Full AutoSUT release validation"
	@echo ""
	@echo "  Campaign execution (requires Docker + Caldera):"
	@echo "    make infra-up            - Start Caldera + agents"
	@echo "    make infra-down          - Stop infrastructure"
	@echo "    make execute             - Execute all campaigns"
	@echo "    make execute-one         - Execute single campaign (CAMPAIGN=name RUNS=n)"
	@echo "    make analyze-results     - Analyze execution results"
	@echo ""
	@echo "  Cleanup:"
	@echo "    make clean-results       - Clean execution results only"
	@echo "    make clean-all           - Clean everything including infrastructure"
