.PHONY: all build test fmt lint vet fix clean

BIN    := rtb-buddy
MODULE := ./cmd/rtb-buddy

all: fix lint test build

build:
	go build -o $(BIN) $(MODULE)

test:
	go test ./...

fmt:
	gofmt -s -w .

lint:
	go tool golangci-lint run ./...

vet:
	go vet ./...

fix:
	go fix ./...

clean:
	rm -f $(BIN)