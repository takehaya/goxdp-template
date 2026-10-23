# CPU redirect and shared state

The [VXLAN example](vxlan.md) forwards on the ingress CPU by default.
Adding `--cpu-redirect` moves forwarding to a CPUMAP target; metadata-driven tail calls select its handler.
Build with [`CPUMAP=0`](build.md#cpumap-build-option) to omit the CPU redirect objects entirely.
The handlers use per-CPU LRU maps to share cached state.
The [TC backend](tc.md) shares ingress parsing, CPUMAP dispatch, and peer lookup, then performs replication and encapsulation after `XDP_PASS`.

## CPU redirect and program dispatch

Add `--cpu-redirect` to run forwarding on CPUs selected through CPUMAP:

```shell
sudo ./bin/goxdp --mode vxlan --config examples/vxlan-unicast.json --cpu-redirect
# Select target CPUs explicitly (they must be available to this process):
sudo ./bin/goxdp --mode vxlan --config examples/vxlan-unicast.json --cpu-redirect --cpu 0 --cpu 1
```

Without `--cpu`, the loader uses the process's CPU affinity mask.
The ingress program validates and decapsulates tunnel traffic before redirecting it.
It computes a directional flow hash from the VNI and inner headers, then selects `cpu_ids[flow_hash % cpu_count]`.
This supports sparse CPU IDs and distributes flows within one VNI.
Packets with the same parsed key select the same CPU while the target list stays unchanged.
IPv4 and IPv6 packets with direct TCP or UDP headers use their addresses, protocol, and transport ports.
Other IP traffic, IPv4 fragments, and IPv6 extension-header traffic use an address/protocol key; non-IP Ethernet traffic uses a MAC/EtherType key.
Up to two VLAN tags contribute their VLAN IDs; priority and DEI bits do not change the hash.
The example uses a deterministic software hash; it does not read a NIC RSS hash.
On the selected CPU, the handler performs FDB lookup, prepares the shared header, replicates through devmap, and accesses both per-CPU caches.
The direct path runs the same forwarding function on the receiving CPU.
The [stage measurements](benchmarks/2026-10-22-stages/README.md) compare both paths, including CPU usage and queue drops.

The shared [metadata ABI](../src/xdp_dispatch.h) has a 16-byte command header and a 16-byte argument union, totaling 32 bytes:

```c
struct xdp_command {
  __u64 program;
  __u64 magic;
  union {
    __u64 raw[2];
    struct { __u32 vni; __u32 flags; __u32 inner_len; __u32 flow_hash; } vxlan;
  } args;
};
```

`PROGRAM_FORWARD` (0) performs FDB lookup and replication; `PROGRAM_REWRITE` (1) prepares each output copy.
Before CPU redirect, ingress sets `FORWARD`, the VNI/flags, inner length, and flow hash.
Before devmap redirect, forwarding changes the command to `REWRITE` and marks a prepared header or a frame received from a tunnel.
Egress reconstructs the header-cache key from the VNI and inner length.
All paths carry the same 32-byte command; the prepared header stays in `header_cache`.
Access egress discards the metadata; tunnel egress retrieves the header and attaches it to the packet before rewriting addresses.
The two redirect entry programs use the same dispatcher to tail-call the handler selected by `program`.
CPUMAP and devmap need separate program arrays because they use different XDP attach types.
One program FD cannot serve both roles.
The dispatcher drops the packet if the metadata is invalid or the handler is missing.
The legacy FIB CPU path also uses this metadata ABI and dispatcher.

Use the per-CPU `pipeline_stats` map to count CPU-handler executions and header preparations before replication.
These counters let the tests check one initial preparation per input BUM frame, regardless of how many copies it produces.
See the kernel documentation for [CPUMAP execution](https://docs.kernel.org/bpf/map_cpumap.html) and [custom metadata across redirects](https://docs.kernel.org/networking/xdp-rx-metadata.html).

## Per-CPU caches

The VXLAN program stores a shared outer-header template in `header_cache` and unicast destinations in `peer_cache`.
Both caches use `LRU_PERCPU_HASH`.
The header key is `(uint64_t)vni << 32 | inner_frame_length`; these two values determine the shared template, so packets with the same key can safely reuse it.
Each tunnel egress copies the template from its current CPU's slot before rewriting addresses.
The cached UDP source port is zero; egress fills `49152 | (flow_hash & 0x3fff)` from metadata after copying the template.
Different flows therefore share a cache entry without sharing a flow-specific source port, while all replicas of one packet use the same UDP source port.
It validates the copied template against the VNI and frame length before use.
If eviction, failed insertion, or an uninitialized CPU slot leaves no template, egress rebuilds it from the VNI and inner length and attempts to refill the cache.
Leave the entries available for the copies and let LRU eviction remove them.
There is no need to track the last copy.

For unicast, the program fills a missing or uninitialized CPU cache value from `peers`.
Evicting a cached value leaves the configured route in place.
Cache values are per CPU, while keys and the default LRU accounting are shared, as described in the [kernel hash-map documentation](https://docs.kernel.org/bpf/map_hash.html).
This example does not set `BPF_F_NO_COMMON_LRU`.

## Updating forwarding state

Call `VXLAN.UpdateMembers(vni, devices)` from Go to replace a VNI's membership without reattaching programs.
The XDP backend atomically replaces its devmap; the TC backend replaces an entry in `tc_groups`.
Call `VXLAN.UpdatePeer(vni, peer)` to update a unicast destination and advance the VNI's cache revision.
Each CPU then refreshes its cached value on the next packet.
Direct changes to `peers` must also advance that VNI's revision in `vnis` to invalidate old cached values.
For the XDP backend, userspace can also update or remove devmap entries directly.
TC membership changes require updating `tc_groups`; devmap changes do not affect that backend.
The [kernel devmap documentation](https://docs.kernel.org/bpf/map_devmap.html) describes the multicast-group and egress-program facilities used here.

## Forwarding maps

The forwarding maps are:

| Map | Key | Value |
| --- | --- | --- |
| `ports` | Interface index | Access VNI, or tunnel source IPv4; source MAC and MTU |
| `vnis` | VNI | Multicast destination, or unicast mode; cache revision |
| `vni_groups` | VNI | A `DEVMAP_HASH` containing member interfaces and the devmap egress program |
| `fdb` | VNI and destination MAC | Known local access interface index |
| `peers` | VNI and egress interface index | Configured unicast destination IP and MAC |
| `peer_cache` | VNI and egress interface index | `LRU_PERCPU_HASH`: destination and revision cached for the current CPU |
| `header_cache` | VNI and inner frame length, packed into 64 bits | `LRU_PERCPU_HASH`: validity marker and prepared 50-byte outer header |
| `cpu_ids`, `cpu_map` | CPU slot / CPU ID | Selected CPU / queue size and CPU dispatcher |
| `cpu_programs`, `devmap_programs` | Program ID | Handler with the corresponding attach type |
| `pipeline_stats` | 0, per CPU | Shared header preparations and CPU-handler executions |

## FIB example

Run the original FIB/CPUMAP example with:

```shell
sudo ./bin/goxdp --mode fib --device eth2 --device eth3
# Run the legacy CPUMAP path:
sudo ./bin/goxdp --mode fib --device eth2 --device eth3 --cpu-redirect
```

This legacy example retains its hardcoded FIB lookup interface index of 1.
After a successful lookup, direct ingress returns `XDP_TX`; the CPU handler redirects to the ingress device with `XDP_REDIRECT`, since CPUMAP does not support `XDP_TX`.
With `--cpu-redirect`, the CLI attaches `cpu_dispatch` and runs the FIB handler after CPUMAP redirect and metadata-driven tail call.
Without it, the CLI attaches the direct FIB program.
Broadcast and FIB modes require explicit `--device` flags.
The [FIB program](../src/xdp_prog.c) also retains xdpcap capture hooks through [hook.h](../src/hook.h).
