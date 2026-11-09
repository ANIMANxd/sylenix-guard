.PHONY: build fmt vet selftest probe-test profile-test replay-test summary-test doctor-test clear-taint-test stats-test check harness-scripted

build:
	CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard
ifeq ($(OS),Windows_NT)
	CGO_ENABLED=0 go build -o bin/sylenix-guard.exe ./cmd/sylenix-guard
endif

fmt:
	@test -z "$$(gofmt -l cmd)" || (echo "gofmt needed for:"; gofmt -l cmd; exit 1)

vet:
	CGO_ENABLED=0 go vet ./...

selftest: build
	python3 demo/selftest.py
	python3 demo/selftest.py --policy

probe-test: build
	python3 tests/probes/test_scratch_grant_bypass.py
	python3 tests/probes/test_protected_targets.py
	python3 tests/probes/test_policy.py
	python3 tests/probes/test_allowlist.py
	python3 tests/probes/test_install.py

profile-test: build
	python3 tests/probes/test_profiles.py

replay-test: build
	python3 scripts/replay_profile_session.py

summary-test:
	python3 scripts/summarize_audit.py --file demo/fixtures/audit_sample.jsonl | tr -d '\r' | diff - demo/fixtures/audit_sample.expected.txt

doctor-test: build
	python3 tests/probes/test_doctor.py

clear-taint-test: build
	python3 tests/probes/test_clear_taint.py

stats-test: build
	python3 tests/probes/test_stats.py

check: fmt vet selftest probe-test profile-test replay-test summary-test doctor-test clear-taint-test stats-test

harness-scripted: build
	.venv/bin/python demo/harness.py --agent scripted --runs 3 --out results-scripted
