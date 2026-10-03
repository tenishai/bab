FGA_VERSION ?= 0.7.20
OS   := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
FGA ?= ./fga
PY ?= python3
CATALOGUE ?= catalogues/example.yaml

.PHONY: fga model test-model
fga:
	curl -sL https://github.com/openfga/cli/releases/download/v$(FGA_VERSION)/fga_$(FGA_VERSION)_$(OS)_$(ARCH).tar.gz | tar xz fga

model:
	$(PY) -m bab.cli model $(CATALOGUE) > model/example.fga
	$(FGA) model validate --file model/example.fga

test-model: model
	$(FGA) model test --tests model/example.fga.yaml

# ---- live demo: a real OpenFGA in Docker, the example profile loaded, six verdicts ----
DEMO_PORT ?= 18080
DEMO_URL  := http://localhost:$(DEMO_PORT)
.PHONY: demo demo-up demo-down
demo-up:
	@$(PY) -c 'import bab' 2>/dev/null || { echo 'bab is not installed for $(PY): run  pip install -e .  (or set PY=venv/bin/python)'; exit 1; }
	@test -x $(FGA) || $(MAKE) -s fga
	docker rm -f bab-demo >/dev/null 2>&1 || true
	docker run -d --name bab-demo -p $(DEMO_PORT):8080 openfga/openfga:latest run >/dev/null
	@for i in $$(seq 1 30); do curl -sf $(DEMO_URL)/healthz >/dev/null && break; sleep 1; done
	@curl -sf $(DEMO_URL)/healthz >/dev/null || { echo "openfga did not come up on $(DEMO_URL)"; docker logs bab-demo | tail -20; exit 1; }
	@$(FGA) store import --api-url $(DEMO_URL) --file model/example.fga.yaml > .demo-import.json 2> .demo-import.log \
	  || { echo "store import failed:"; cat .demo-import.log; exit 1; }
	@$(PY) -c "import json; d=json.load(open('.demo-import.json')); print(d.get('store',{}).get('id') or d['id'])" > .demo-store
	@echo "openfga up at $(DEMO_URL), store $$(cat .demo-store)"

demo: demo-up
	@for spec in "atlas pod_delete namespace:platform-dev/ingest" \
	             "atlas pod_delete namespace:platform-prod/ingest" \
	             "beacon pod_delete namespace:data-kafka/streams" \
	             "beacon kafka_topic_config_update project:acme-data-prod" \
	             "beacon log_read cluster:platform-dev-legacy" \
	             "atlas reboot_world cluster:platform-prod"; do \
	  set -- $$spec; printf "%-8s %-26s %-32s -> " $$1 $$2 $$3; \
	  $(PY) -m bab.cli check --url $(DEMO_URL) --store-id $$(cat .demo-store) --agent $$1 --action $$2 --object $$3 || true; \
	done
	@echo "--- store unreachable (fail-closed):"
	@$(PY) -m bab.cli check --url http://localhost:1 --store-id x --agent atlas --action pod_delete \
	  --object namespace:platform-prod/ingest --fallback-approver user:alice@example.com 2>/dev/null || true

demo-down:
	docker rm -f bab-demo >/dev/null 2>&1 || true
	rm -f .demo-store .demo-import.json .demo-import.log
