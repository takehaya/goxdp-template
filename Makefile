NAME := goxdp

#brunch name version
VERSION := $(shell git rev-parse --abbrev-ref HEAD)

PKG_NAME=$(shell basename `pwd`)

LDFLAGS := -ldflags="-s -w  -X \"github.com/takehaya/goxdp-template/pkg/version.Version=$(VERSION)\" -extldflags \"-static\""
SRCS    := $(shell find . -type f -name '*.go')

CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

.DEFAULT_GOAL := build
build: $(SRCS) gen
	go build $(LDFLAGS) -o ./bin/$(NAME) ./cmd/$(NAME)

.PHONY: run
run:
	go run $(LDFLAGS) ./cmd/$(NAME)

.PHONY: gen
gen: export BPF_CLANG := $(CLANG)
gen: export BPF_CFLAGS := $(CFLAGS) $(CEXTRA_FLAGS)
gen:
	go generate pkg/coreelf/elf.go

.PHONY: clean
clean:
	rm -rf ./bin/$(NAME)

.PHONY: test
test:
	go test -v -exec sudo -race ./pkg/...

.PHONY: remove-ebpfmap 
remove-ebpfmap:
	sudo rm -rf /sys/fs/bpf/*

.PHONY: show-trace_pipe
show-trace_pipe:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

.PHONY: fmt
fmt:
	go fmt ./...
	find . -iname *.h -o -iname *.c | xargs clang-format -i -style=Google 