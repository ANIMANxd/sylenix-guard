.PHONY: build fmt vet selftest probe-test proxy-test signing-test profile-test replay-test summary-test doctor-test clear-taint-test stats-test team-test check harness-scripted

build:
	CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard
	CGO_ENABLED=0 go build -o bin/sylenix-teams ./teams/cmd/sylenix-teams
ifeq ($(OS),Windows_NT)
	CGO_ENABLED=0 go build -o bin/sylenix-guard.exe ./cmd/sylenix-guard
	CGO_ENABLED=0 go build -o bin/sylenix-teams.exe ./teams/cmd/sylenix-teams
endif

fmt:
	@test -z "$$(gofmt -l cmd teams)" || (echo "gofmt needed for:"; gofmt -l cmd teams; exit 1)

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

proxy-test: build
	python3 tests/probes/test_http_proxy.py

signing-test: build
	python3 tests/probes/test_signing.py

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

team-test: build
	go test ./teams/... -count=1

check: fmt vet selftest probe-test proxy-test signing-test profile-test replay-test summary-test doctor-test clear-taint-test stats-test team-test

harness-scripted: build
	.venv/bin/python demo/harness.py --agent scripted --runs 3 --out results-scripted
