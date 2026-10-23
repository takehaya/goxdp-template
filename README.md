# goxdp

These examples pair C XDP programs with a Go loader built on [cilium/ebpf](https://github.com/cilium/ebpf).
Use them to replicate packets, rewrite individual copies, and deliver a copy to a local application using existing kernel features.
The default backend forwards entirely in XDP; `--backend tc` selects an XDP and TC variant for comparison.

## What this repository demonstrates

| Learn how to | Mechanism and example |
| --- | --- |
| Replicate a frame to several outputs in XDP | [DEVMAP and `BPF_F_BROADCAST`](docs/broadcast.md), including ingress exclusion |
| Send the same inner frame to different unicast destinations | [DEVMAP egress programs with VXLAN encapsulation and decapsulation](docs/vxlan.md) |
| Scope BUM replication by VLAN on a shared trunk | [VID-to-VNI bindings and per-VNI devmaps](docs/vlan-bum.md), with tag-preserving VXLAN forwarding |
| Compare XDP replication with skb cloning | [The optional TC backend](docs/tc.md), using the same forwarding configuration |
| Receive a local copy while forwarding other copies | [A local veth output and ingress `XDP_PASS`](docs/local-delivery.md) |
| Move forwarding to a selected CPU | [CPUMAP and forwarding on the target CPU](docs/pipeline.md#cpu-redirect-and-program-dispatch), optionally [omitted at build time](docs/build.md#cpumap-build-option) |
| Dispatch work between XDP programs | [A 32-byte metadata command and tail calls](docs/pipeline.md#cpu-redirect-and-program-dispatch) |
| Reuse state across replicated copies | [Per-CPU LRU caches with reconstruction on a miss](docs/pipeline.md#per-cpu-caches) |

Start with the [broadcast program](src/xdp_broadcast.c) and its [Go loader](pkg/coreelf/broadcast.go), then follow the VXLAN example for per-copy processing.
For FIB forwarding, the [FIB example](docs/pipeline.md#fib-example) includes both direct and CPU redirect variants.

## Try the examples

Use Linux, Go 1.25 or later, and Clang/LLVM with the BPF backend.
On Debian or Ubuntu:

```shell
sudo apt install clang llvm libbpf-dev linux-libc-dev build-essential iproute2
make test-scenario
```

The test target builds the production binary and runs the examples over veth pairs in isolated network namespaces.
By default, it runs 196 forwarding cases across both backends, including VLAN isolation and UDP delivery to local and remote applications.
The full scenario suite requires Linux 6.6 or later for TCX.
The tests use `sudo` and run without a physical NIC.
If Clang has a versioned executable name, use `make test-scenario CLANG=clang-18`.

Use `make` to build `bin/goxdp` separately.
See [building](docs/build.md) for kernel and driver requirements.
The [testing guide](docs/testing.md) lists the commands and explains each topology and its checks.
The [benchmark guide](docs/benchmarks.md) explains how to compare both backends with XDPerf on multiqueue veth pairs; [recorded results](docs/benchmarks/2026-10-22-flow-hash/README.md) include flow distribution, receiver rates, and graphs.
