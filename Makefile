.PHONY: all build test fmt vet clean

GO ?= go
BIN := bin/tup

all: vet test build

build:
	$(GO) build -o $(BIN) ./cmd/tup

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

clean:
	rm -rf bin/
