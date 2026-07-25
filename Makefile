.PHONY: lint lint-all lint-install setup-hooks test-unit test-privileged \
	dev-volumes dev-format dev-test-fast dev-vet dev-security \
	dev-test-race dev-mod-check dev-dashboard-deps dev-dashboard-format dev-dashboard-check \
	dev-dashboard-security dev-dashboard-build \
	dev-test-local-integrations \
	dev-conflict-report dev-conflict-report-dashboard dev-verify dev-clean
GOLANGCI_LINT := $(shell pwd)/bin/golangci-lint

DEV_GO_IMAGE ?= golang:1.25.12
DEV_NODE_IMAGE ?= node:22-bookworm
DEV_GO_MOD_VOLUME ?= netbird-dev-go-mod
DEV_GO_BUILD_VOLUME ?= netbird-dev-go-build
DEV_DASHBOARD_VOLUME ?= netbird-dev-dashboard-deps

# The fast suite intentionally avoids packages whose tests start PostgreSQL,
# Redis, or privileged network containers. It covers local auth, LDAP, and the
# embedded Dex MFA policy adapter
# customization path and is suitable for the normal inner development loop.
DEV_FAST_GO_PACKAGES := \
	./combined/cmd \
	./management/server/http/middleware \
	./management/server/http/handlers/users \
	./management/server/http/handlers/idp \
	./management/server/types \
	./management/server/idp \
	./idp/dex \
	./client/internal/auth \
	./management/server/http \
	./management/internals/server \
	./management/server/localintegrations/ldapsync \
	./management/server/localintegrations/scim \
	./management/server/outbound \
	./shared/management/http/api

DEV_RACE_GO_PACKAGES := \
	./management/server/http/middleware \
	./management/server/idp \
	./idp/dex \
	./management/internals/server \
	./management/server/localintegrations/scim

# Install golangci-lint locally if needed
$(GOLANGCI_LINT):
	@echo "Installing golangci-lint..."
	@mkdir -p ./bin
	@GOBIN=$(shell pwd)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

# Lint only changed files (fast, for pre-push)
lint: $(GOLANGCI_LINT)
	@echo "Running lint on changed files..."
	@$(GOLANGCI_LINT) run --new-from-rev=origin/main --timeout=2m

# Lint entire codebase (slow, matches CI)
lint-all: $(GOLANGCI_LINT)
	@echo "Running lint on all files..."
	@$(GOLANGCI_LINT) run --timeout=12m

# Just install the linter
lint-install: $(GOLANGCI_LINT)

# Setup git hooks for all developers
setup-hooks:
	@git config core.hooksPath .githooks
	@chmod +x .githooks/pre-push
	@echo "✅ Git hooks configured! Pre-push will now run 'make lint'"

# Host-safe unit tests: excludes the privileged-tagged tests (root / system-mutating).
# Runs as a normal user with no sudo and leaves host networking untouched.
test-unit:
	@go test -tags devcert -timeout 10m ./...

# Privileged suite: runs the `privileged`-tagged tests inside a --privileged
# --cap-add=NET_ADMIN container via the ory/dockertest harness. Requires Docker.
# Narrow the run with env vars, e.g.:
#   PRIV_RUN=TestNftablesManager PRIV_PKGS=./client/firewall/nftables/... make test-privileged
test-privileged:
	@go test -tags 'devcert privileged' -timeout 30m -run TestRunPrivilegedSuiteInDocker -v ./client/testutil/privileged/...

# Container-only local development targets. These targets never install Go or
# Node dependencies on the host and do not mount the Docker socket.
dev-volumes:
	@docker volume create $(DEV_GO_MOD_VOLUME) >/dev/null
	@docker volume create $(DEV_GO_BUILD_VOLUME) >/dev/null
	@docker volume create $(DEV_DASHBOARD_VOLUME) >/dev/null

# Usage: make dev-format GO_FILES="management/internals/server/mfa_policy.go idp/dex/ldap_config.go"
dev-format: dev-volumes
	@test -n "$(GO_FILES)" || (echo 'GO_FILES is required' >&2; exit 2)
	@docker run --rm \
		-e "GO_FILES=$(GO_FILES)" \
		-v "$(CURDIR):/workspace" \
		-w /workspace \
		$(DEV_GO_IMAGE) bash -c 'read -r -a files <<< "$$GO_FILES"; gofmt -w "$${files[@]}"'

dev-test-fast: dev-volumes
	@docker run --rm \
		-v "$(CURDIR):/workspace:ro" \
		-v $(DEV_GO_MOD_VOLUME):/go/pkg/mod \
		-v $(DEV_GO_BUILD_VOLUME):/root/.cache/go-build \
		-w /workspace \
		$(DEV_GO_IMAGE) go test -count=1 $(DEV_FAST_GO_PACKAGES)

dev-test-race: dev-volumes
	@docker run --rm \
		-v "$(CURDIR):/workspace:ro" \
		-v $(DEV_GO_MOD_VOLUME):/go/pkg/mod \
		-v $(DEV_GO_BUILD_VOLUME):/root/.cache/go-build \
		-w /workspace \
		$(DEV_GO_IMAGE) go test -race -count=1 $(DEV_RACE_GO_PACKAGES)

dev-vet: dev-volumes
	@docker run --rm \
		-v "$(CURDIR):/workspace:ro" \
		-v $(DEV_GO_MOD_VOLUME):/go/pkg/mod \
		-v $(DEV_GO_BUILD_VOLUME):/root/.cache/go-build \
		-w /workspace \
		$(DEV_GO_IMAGE) go vet $(DEV_FAST_GO_PACKAGES)

dev-mod-check: dev-volumes
	@docker run --rm \
		-v "$(CURDIR):/workspace:ro" \
		-v $(DEV_GO_MOD_VOLUME):/go/pkg/mod \
		-v $(DEV_GO_BUILD_VOLUME):/root/.cache/go-build \
		-w /workspace \
		$(DEV_GO_IMAGE) go mod tidy -diff

dev-security: dev-volumes
	@docker run --rm \
		-v "$(CURDIR):/workspace:ro" \
		-v $(DEV_GO_MOD_VOLUME):/go/pkg/mod \
		-v $(DEV_GO_BUILD_VOLUME):/root/.cache/go-build \
		-w /workspace \
		$(DEV_GO_IMAGE) bash -c 'go run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 -quiet -exclude=G104,G115,G117,G124,G304,G404,G505 ./management/server/... ./idp/dex/... ./client/internal/auth/...'

dev-dashboard-deps: dev-volumes
	@docker run --rm \
		-v "$(CURDIR)/dashboard:/src:ro" \
		-v $(DEV_DASHBOARD_VOLUME):/deps \
		$(DEV_NODE_IMAGE) bash -c 'lock_hash=$$(sha256sum /src/package-lock.json | cut -d" " -f1); \
			if [ "$$(cat /deps/package-lock.sha256 2>/dev/null)" != "$$lock_hash" ]; then \
				rm -rf /deps/app && mkdir -p /deps/app && \
				cp /src/package.json /src/package-lock.json /deps/app/ && \
				cd /deps/app && npm ci && printf "%s" "$$lock_hash" > /deps/package-lock.sha256; \
			fi'

# Usage: make dev-dashboard-format DASHBOARD_FILES="src/layouts/DashboardLayout.tsx"
dev-dashboard-format: dev-dashboard-deps
	@test -n "$(DASHBOARD_FILES)" || (echo 'DASHBOARD_FILES is required' >&2; exit 2)
	@docker run --rm \
		-e "DASHBOARD_FILES=$(DASHBOARD_FILES)" \
		-v "$(CURDIR)/dashboard:/src" \
		-v $(DEV_DASHBOARD_VOLUME):/deps:ro \
		$(DEV_NODE_IMAGE) bash -c 'read -r -a files <<< "$$DASHBOARD_FILES"; cd /src && /deps/app/node_modules/.bin/prettier --cache-location /tmp/prettier-cache --write "$${files[@]}"'

# Usage: make dev-dashboard-check DASHBOARD_FILES="src/layouts/DashboardLayout.tsx"
dev-dashboard-check: dev-dashboard-deps
	@test -n "$(DASHBOARD_FILES)" || (echo 'DASHBOARD_FILES is required' >&2; exit 2)
	@docker run --rm \
		-e "DASHBOARD_FILES=$(DASHBOARD_FILES)" \
		-v "$(CURDIR)/dashboard:/src:ro" \
		-v $(DEV_DASHBOARD_VOLUME):/deps:ro \
		$(DEV_NODE_IMAGE) bash -c 'read -r -a files <<< "$$DASHBOARD_FILES"; cd /src && /deps/app/node_modules/.bin/prettier --cache-location /tmp/prettier-cache --check "$${files[@]}"'

dev-dashboard-security: dev-dashboard-deps
	@docker run --rm \
		-v $(DEV_DASHBOARD_VOLUME):/deps \
		$(DEV_NODE_IMAGE) bash -c 'cd /deps/app && npm audit --audit-level=high'

dev-dashboard-build: dev-dashboard-deps
	@docker run --rm \
		-v "$(CURDIR)/dashboard:/src:ro" \
		--mount type=volume,src=$(DEV_DASHBOARD_VOLUME),dst=/work/node_modules,volume-subpath=app/node_modules,readonly \
		$(DEV_NODE_IMAGE) bash -c 'tar --exclude="./.git" --exclude="./node_modules" --exclude="./.next" --exclude="./out" -C /src -cf - . | tar -C /work -xf - && cd /work && npm run build'

dev-test-local-integrations: dev-volumes
	@DEV_GO_IMAGE=$(DEV_GO_IMAGE) \
		DEV_GO_MOD_VOLUME=$(DEV_GO_MOD_VOLUME) \
		DEV_GO_BUILD_VOLUME=$(DEV_GO_BUILD_VOLUME) \
		bash tools/localdev/test-local-integrations.sh

# Read-only Git analysis. No toolchain or dependency is installed on the host.
dev-conflict-report:
	@bash tools/localdev/conflict-report.sh . $${BASE:-origin/main}

dev-conflict-report-dashboard:
	@bash tools/localdev/conflict-report.sh dashboard $${BASE:-origin/main}

dev-verify: dev-mod-check dev-test-fast dev-vet dev-security dev-dashboard-security dev-dashboard-build

dev-clean:
	@docker volume rm $(DEV_GO_MOD_VOLUME) $(DEV_GO_BUILD_VOLUME) $(DEV_DASHBOARD_VOLUME) 2>/dev/null || true
