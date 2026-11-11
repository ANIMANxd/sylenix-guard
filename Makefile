.PHONY: build fmt spdx-check vet selftest probe-test proxy-test signing-test profile-test replay-test summary-test doctor-test clear-taint-test stats-test team-test check harness-scripted gif

build:
	CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard
	CGO_ENABLED=0 go build -o bin/sylenix-teams ./teams/cmd/sylenix-teams
ifeq ($(OS),Windows_NT)
	CGO_ENABLED=0 go build -o bin/sylenix-guard.exe ./cmd/sylenix-guard
	CGO_ENABLED=0 go build -o bin/sylenix-teams.exe ./teams/cmd/sylenix-teams
endif

fmt:
	@test -z "$$(gofmt -l cmd teams demo)" || (echo "gofmt needed for:"; gofmt -l cmd teams demo; exit 1)

spdx-check:
	@missing=$$(find cmd teams demo scripts tests -type f \( -name '*.go' -o -name '*.py' \) -exec grep -L 'SPDX-License-Identifier: Apache-2.0' {} +); \
	if [ -n "$$missing" ]; then \
		echo "SPDX header missing from:"; echo "$$missing"; exit 1; \
	fi

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
	python3 tests/probes/test_version.py

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

# CGO_ENABLED=0 keeps the test binaries internally linked. cgo external linking
# on newer macOS SDKs produced dyld "missing LC_UUID" failures for these tests.
team-test: build
	CGO_ENABLED=0 go test ./teams/... -count=1

check: fmt spdx-check vet selftest probe-test proxy-test signing-test profile-test replay-test summary-test doctor-test clear-taint-test stats-test team-test

harness-scripted: build
	.venv/bin/python demo/harness.py --agent scripted --runs 3 --out results-scripted

gif: build
	go build -o bin/gifrunner ./demo/gifrunner
	vhs demo/quickstart.tape
