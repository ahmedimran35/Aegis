SHELL := /bin/bash

.PHONY: help build test tidy dashboard audit fuzz ci-test vet sbom

help:
	@echo "Aegis WAF make targets:"
	@echo "  build      - compile waf-engine binary"
	@echo "  test       - go test ./..."
	@echo "  fuzz       - run fuzz tests for 5s each (CI gate)"
	@echo "  ci-test    - run test + fuzz + vet + sbom in CI order"
	@echo "  tidy       - go mod tidy"
	@echo "  dashboard  - build dashboard SPA"
	@echo "  audit      - flag TODO/FIXME/XXX in shipped code"
	@echo "  sbom       - generate SPDX SBOM (requires syft: brew install syft)"

build:
	go build -o waf-engine ./cmd/waf-engine

test:
	go test ./...

fuzz:
	@echo "Running fuzz tests (5s each)..."
	@set -e; for tgt in FuzzComputeJA4 FuzzComputeJA4H FuzzDetectSQLi FuzzDetectXSS FuzzTokenizeSQL FuzzCalculateDepth FuzzCalculateComplexity; do \
		echo "  $$tgt..."; \
		go test ./internal/middleware/ -fuzz=$$tgt -fuzztime=5s -run=^$$ || exit 1; \
	done

ci-test: test vet fuzz sbom

tidy:
	go mod tidy

dashboard:
	cd dashboard && npm run build

audit:
	@echo "Scanning for tech debt markers..."
	@rg -n --no-heading "TODO|FIXME|XXX|HACK" --type go . | grep -v "_test.go" || (echo "Clean." && exit 0)

vet:
	go vet ./...

# P-FIX (M-28): emit an SPDX SBOM for the project so downstream consumers
# can audit dependencies. Requires syft (brew install syft / go install
# github.com/anchore/syft@latest). The output file sbom.spdx.json is the
# canonical artifact referenced by the CI pipeline.
sbom:
	@if ! command -v syft >/dev/null 2>&1; then \
		echo "syft not found; install with: brew install syft"; \
		exit 1; \
	fi
	syft dir:. -o spdx-json=sbom.spdx.json
	@echo "SBOM written to sbom.spdx.json"
