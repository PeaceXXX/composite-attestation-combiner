GO ?= go

.PHONY: build test vet demo server keygen clean

build:
	$(GO) build ./...

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

demo:
	$(GO) run ./cmd/demo

server:
	$(GO) run ./cmd/server

keygen:
	$(GO) run ./cmd/keygen inference-worker-01

clean:
	$(GO) clean
