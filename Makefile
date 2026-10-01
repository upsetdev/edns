# Local equivalents of the CI checks. `make check` before opening a PR.

STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.8.0

.PHONY: build test lint vuln check fmt docker

build:
	CGO_ENABLED=0 go build -trimpath -o edns .

test:
	go test -race -count=1 ./...

fmt:
	gofmt -w .

lint:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	go vet ./...
	go run $(STATICCHECK) ./...

vuln:
	go run $(GOVULNCHECK) ./...

check: lint test vuln

docker:
	docker build -t edns .
