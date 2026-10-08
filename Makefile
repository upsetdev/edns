# Local equivalents of the CI checks. `make check` before opening a PR.
#
# The Redis tests run when EDNS_TEST_REDIS_URL is set; `make test-redis`
# starts a throwaway Redis in Docker for them.

.PHONY: build test test-redis lint vuln check fmt docker

build:
	cargo build --release --locked

test:
	cargo test --locked

test-redis:
	@docker run -d --rm --name edns-test-redis -p 127.0.0.1:56379:6379 redis:8-alpine >/dev/null
	@sleep 1
	EDNS_TEST_REDIS_URL=redis://127.0.0.1:56379 cargo test --locked; \
		status=$$?; docker stop edns-test-redis >/dev/null; exit $$status

fmt:
	cargo fmt

lint:
	cargo fmt --check
	cargo clippy --all-targets --locked -- -D warnings

vuln:
	cargo audit

check: lint test vuln

docker:
	docker build -t edns .
