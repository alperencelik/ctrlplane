TENANT_IMG   ?= tenant-apiserver:dev
PLATFORM_IMG ?= platform:dev
PORT    ?= 26443

.PHONY: help manifests generate build test lint setup-envtest run-local image clean

help: ## Show targets
	@grep -E '^[a-z0-9-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

manifests: controller-gen ## Generate the CRDs (config/crd) and ClusterRole rules (config/rbac) from api/ and +kubebuilder markers
	"$(CONTROLLER_GEN)" rbac:roleName=platform crd paths="./api/...;./cmd/..." output:crd:artifacts:config=config/crd output:rbac:artifacts:config=config/rbac

generate: controller-gen ## Generate DeepCopy methods (api/v1alpha1/zz_generated.deepcopy.go)
	"$(CONTROLLER_GEN)" object paths="./api/..."

build: ## Build bin/tenant-apiserver and bin/platform
	go build -o bin/ ./cmd/...

test: manifests generate setup-envtest ## go vet + unit tests + envtest (the Tenant controller against a real API server), race detector on
	go vet ./... && KUBEBUILDER_ASSETS="$$("$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test -race ./...

lint: ## gofmt, staticcheck, actionlint
	@test -z "$$(gofmt -l api cmd pkg)" || { gofmt -l api cmd pkg; echo "run gofmt -w on the files above"; exit 1; }
	go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...
	$(if $(wildcard .github/workflows),go run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION))

run-local: build ## Run one tenant API server locally in .local/standalone (no cluster needed)
	mkdir -p .local/standalone && cd .local/standalone && ../../bin/tenant-apiserver --secure-port=$(PORT)

image: ## Build both container images
	docker build --target tenant-apiserver -t $(TENANT_IMG) .
	docker build --target platform -t $(PLATFORM_IMG) .


clean: ## Remove build output and local state
	rm -rf bin .local dist

# Build tools (controller-gen, setup-envtest), installed into bin/ at pinned versions.

LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
CONTROLLER_TOOLS_VERSION ?= v0.22.0
STATICCHECK_VERSION ?= v0.8.1
ACTIONLINT_VERSION ?= v1.7.12
# setup-envtest from the release branch of the controller-runtime in go.mod (its module isn't tagged
# per patch release); the Kubernetes version (1.x) from k8s.io/api.
ENVTEST_VERSION ?= $(shell echo '$(call gomodver,sigs.k8s.io/controller-runtime)' | sed -E 's/^v?([0-9]+)\.([0-9]+).*/release-\1.\2/')
ENVTEST_K8S_VERSION ?= $(shell echo '$(call gomodver,k8s.io/api)' | sed -E 's/^v?[0-9]+\.([0-9]+).*/1.\1/')

.PHONY: controller-gen envtest
controller-gen: $(CONTROLLER_GEN)
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

envtest: $(ENVTEST)
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

setup-envtest: envtest ## Download the envtest binaries (API server, etcd) into bin/k8s
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path >/dev/null

# go-install-tool installs package $(2)@$(3) as $(1)-$(3), linked from $(1).
define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" ;\
GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(LOCALBIN)/$$(basename "$(1)")" "$(1)-$(3)" ;\
} ;\
ln -sf "$$(realpath "$(1)-$(3)")" "$(1)"
endef

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef
