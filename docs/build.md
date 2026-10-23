# Building

Use Linux, Go 1.25 or later, and Clang/LLVM with the BPF backend.
The default XDP broadcast example requires Linux 5.14 or later, native XDP on the ingress interface, and devmap XDP transmit support on the egress interfaces.
The broadcast flags are present in the [Linux 5.14 UAPI](https://github.com/torvalds/linux/blob/v5.14/include/uapi/linux/bpf.h).
The VXLAN example uses 32 bytes of custom metadata and requires driver support for metadata and sufficient headroom for encapsulation.
Its metadata fits within the [Linux 5.14 limit](https://github.com/torvalds/linux/blob/v5.14/net/core/filter.c#L3650-L3662).

The optional [TC backend](tc.md) requires Linux 6.6 or later for TCX ingress links.
It also requires native XDP and custom metadata support.
The full integration and scenario suites exercise both backends and therefore require TCX.

On Debian or Ubuntu, install the build dependencies:

```shell
sudo apt install clang llvm libbpf-dev linux-libc-dev build-essential iproute2 clang-format
make
```

`make` generates the BPF objects and Go bindings, then builds `bin/goxdp`.
Install the libbpf headers through `libbpf-dev`.
There is no need to download or configure a kernel source tree.
The version of `bpf2go` is pinned with the cilium/ebpf library in `go.mod`.
If Clang has a versioned executable name, use `make CLANG=clang-18`.

Run commands in these documents from the repository root.

## CPUMAP build option

Use `CPUMAP=0` to compile out CPU redirect support:

```shell
make build CPUMAP=0 CLANG=clang-18
make test test-integration test-scenario CPUMAP=0 CLANG=clang-18
```

This variant omits CPUMAPs, CPU selection maps, CPU dispatch programs, and the ingress CPU redirect branch from the FIB, XDP VXLAN, and TC VXLAN objects.
Direct forwarding, devmap replication, VXLAN processing, and local delivery remain available.
The CLI rejects `--cpu-redirect`, and the Go loaders reject explicit CPU targets, before loading BPF objects.
`coreelf.CPUMAPEnabled` reports the selected build capability.

`CPUMAP=1` is the default and retains the runtime `--cpu-redirect` option.
Omitting that runtime option keeps forwarding on the ingress CPU, while the build still includes CPU redirect objects.
Switch builds with `make build CPUMAP=1`; cleaning generated files is unnecessary.
Make passes the Go build tag `nocpumap` for `CPUMAP=0`, including integration and scenario test commands.
When invoking Go directly, use the same tag to select the matching generated bindings.

## Generated objects

The FIB production and mocked objects use separate output files and mutually exclusive Go build tags.
The build generates both variants with explicit preprocessor flags.
Changing the target order or running make in parallel cannot select the mocked datapath for a production binary.
For example, run `make test test-integration build CLANG=clang-18` to combine targets.
A regression test checks both variants and verifies that the production object contains the FIB helper calls and excludes the mock map.

CPUMAP-enabled and direct-only objects also have separate output files and mutually exclusive Go tags.
Generation always produces both capabilities, independently of the selected build option.
FIB production and mock objects therefore have four combinations, each with matching generated bindings.
Tests inspect all eight FIB/VXLAN/TC variant ELFs and the actual objects selected by Go tags.
They check that direct-only ELFs contain no CPUMAP, CPU dispatch map, CPUMAP program, or CPU-count constant.

The XDP and TC backends also have separate generated objects.
The TC VXLAN source compiles the shared XDP parser with a handoff to TC, while the default object retains devmap forwarding.
Selecting the XDP backend does not load a TC program.

## Debug logging

For BPF debug logging, build with `CEXTRA_FLAGS=-DXDP_DEBUG make`, then use `make show-trace_pipe`.

See [testing](testing.md) for unit, kernel integration, and network namespace checks.
