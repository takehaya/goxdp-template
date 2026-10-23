NAME := goxdp
VERSION := $(shell git describe --always --dirty)
LDFLAGS := -ldflags="-s -w -X github.com/takehaya/goxdp-template/pkg/version.Version=$(VERSION)"

CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Werror
CPUMAP ?= 1
ifeq ($(CPUMAP),0)
BUILD_TAGS := nocpumap
else ifeq ($(CPUMAP),1)
BUILD_TAGS :=
else
$(error CPUMAP must be 0 or 1)
endif
# Linux UAPI headers include asm/types.h from the host multiarch directory.
MULTIARCH := $(shell $(CC) -print-multiarch)
TEST_EXEC ?= sudo unshare --net

.DEFAULT_GOAL := build
.PHONY: build run gen clean test test-integration test-scenario bench-tools fmt show-trace_pipe

build: gen
	go build -tags "$(BUILD_TAGS)" $(LDFLAGS) -o ./bin/$(NAME) ./cmd/$(NAME)

run: build
	sudo ./bin/$(NAME) $(ARGS)

gen: export BPF2GO_CC = $(CLANG)
gen: export BPF2GO_CFLAGS = $(CFLAGS) -I/usr/include/$(MULTIARCH) $(CEXTRA_FLAGS)
gen:
	go generate ./pkg/coreelf
	go generate ./pkg/coreelf/mock.go

clean:
	rm -f ./bin/$(NAME) ./bin/goxdp-perf-counters ./pkg/coreelf/*_bpf.go ./pkg/coreelf/*_bpf.o

test: gen
	go test -race -tags "$(BUILD_TAGS)" ./...

test-integration: gen
	go test -count=1 -race -tags "integration $(BUILD_TAGS)" -exec "$(TEST_EXEC)" ./...

test-scenario: build
	go test -count=1 -v -race -tags "scenario $(BUILD_TAGS)" -exec "$(TEST_EXEC)" ./tests/scenarios -args -goxdp-binary "$(abspath bin/$(NAME))"

bench-tools: build
	go build -o ./bin/goxdp-perf-counters ./tests/benchmarks/counters

show-trace_pipe:
	sudo cat /sys/kernel/tracing/trace_pipe

fmt:
	go fmt ./...
	find src -type f \( -name '*.h' -o -name '*.c' \) -exec clang-format -i {} +
