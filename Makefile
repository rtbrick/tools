.PHONY: all build test fmt lint vet fix clean snapshot

BIN      := rtb-buddy
MODULE   := ./cmd/rtb-buddy
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -s -w -X github.com/rtbrick/tools/cmd/rtb-buddy/config.VERSION=$(VERSION)

all: fix lint test build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) $(MODULE)

snapshot:
	goreleaser release --snapshot --clean --skip=publish

test:
	go test -cover -coverprofile=coverage.out ./...
	#go tool cover -func=coverage.out

fmt:
	gofmt -s -w .

lint:
	go tool golangci-lint run ./...

vet:
	go vet ./...

fix:
	go fix ./...

clean:
	rm -f $(BIN) coverage.out