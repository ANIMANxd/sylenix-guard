.PHONY: build fmt vet selftest check harness-scripted

build:
	CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard

fmt:
	@test -z "$$(gofmt -l cmd)" || (echo "gofmt needed for:"; gofmt -l cmd; exit 1)

vet:
	CGO_ENABLED=0 go vet ./...

selftest: build
	python3 demo/selftest.py

check: fmt vet selftest

harness-scripted: build
	.venv/bin/python demo/harness.py --agent scripted --runs 3 --out results-scripted
