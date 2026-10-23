# Kernel profiles of replication stages

The profiles identify queue saturation and map operations as costs worth investigating before changing the forwarding design.
They contain one diagnostic trial per stage, with a two-second warmup and a ten-second sampling request.
Throughput from these instrumented trials is excluded from the [ordinary stage comparison](../README.md).

## CPUMAP drops

The enqueue tracepoints recorded drops in the trial's own CPUMAP.
The tracer filters by map ID and sums the kernel's `processed` and `drops` fields for each target CPU.
For this native XDP path, `processed` includes every attempted enqueue, including failures, so the drop fraction is `drops / processed` ([kernel enqueue implementation](https://github.com/torvalds/linux/blob/v7.0/kernel/bpf/cpumap.c#L673-L705)).
These totals span sender startup, warmup, sampling, and sender shutdown; their window differs from the receiver snapshots.

| Configuration | Enqueue drop fraction | Raw counters |
| --- | ---: | --- |
| XDP, CPU 8 | 76.38% | [Counters](run-005/cpumap-counters.json), [tracer](run-005/cpumap.bt) |
| XDP, CPUs 8–11 | 26.44% | [Counters](run-002/cpumap-counters.json), [tracer](run-002/cpumap.bt) |
| XDP + TC, CPUs 8–11 | 59.10% | [Counters](run-001/cpumap-counters.json), [tracer](run-001/cpumap.bt) |

All three traces recorded zero allocation drops and zero program `XDP_DROP` actions in the CPUMAP worker.
The XDP traces therefore directly identify enqueue overflow as a source of delivery loss.
TC receiver measurements can also reflect limits downstream of the CPU handoff; differing counter windows prevent an exact loss decomposition from these totals.
Devmap egress drop sites were not traced.

The 64-flow workload distributes unevenly across four targets.
The deterministic hash assigns 24 flows to CPU 8, 15 to CPU 9, 16 to CPU 10, and 9 to CPU 11.
The observed enqueue attempt counts follow those shares.
CPU 8 recorded 8,801,576 enqueue drops, while CPU 11 recorded none in the same trace.
The [stage comparison](../README.md) includes a separate 4096-flow control to check the effect of this workload imbalance.

## Sampled CPU cycles

Perf sampled cycles at 199 Hz on the four generator CPUs and any configured forwarding CPUs.
The records include veth receive processing, generator work, and unrelated activity on those CPUs.
The percentages below describe self samples within the stated CPU scope; they are neither isolated DUT costs nor inclusive call-chain totals.
All six recordings reported zero lost samples.

| Scope | Function | Self samples |
| --- | --- | ---: |
| Direct VXLAN, CPUs 0–3 | `lookup_nulls_elem_raw` | 6.09% |
| Direct VXLAN, CPUs 0–3 | `veth_poll` | 4.54% |
| Direct VXLAN, CPUs 0–3 | `vxlan_rewrite` | 4.07% |
| Direct VXLAN, CPUs 0–3 | `htab_lock_bucket` | 3.70% |
| Four-CPU VXLAN, CPUs 8–11 | `lookup_nulls_elem_raw` | 6.95% |
| Four-CPU VXLAN, CPUs 8–11 | `dev_map_enqueue_multi` | 5.91% |
| Four-CPU VXLAN, CPUs 8–11 | `cpu_map_bpf_prog_run_xdp` | 5.10% |
| Four-CPU VXLAN, CPUs 8–11 | `htab_lock_bucket` | 3.92% |
| Four-CPU VXLAN, CPUs 0–3 | `kernel_init_pages` | 12.43% |

The call chains attribute bucket locking to the per-packet LRU per-CPU header-cache update.
Per-CPU values still share the map's key and update machinery; updating the same VNI/length key on each packet adds work.
Avoiding an update when a valid cached template already exists is a candidate for a separate change and measurement.
The receive path, packet allocation, and copying also consume samples, so removing that update alone would not remove the other pipeline costs.

| Stage | Self-sample records | Caller stacks |
| --- | --- | --- |
| Plain devmap | [All CPUs](run-004/hotspots-all.json) | [Stacks](run-004/perf-callers-all.txt) |
| Direct VXLAN | [All CPUs](run-003/hotspots-all.json) | [Stacks](run-003/perf-callers-all.txt) |
| VXLAN, CPU 8 | [Source](run-005/hotspots-source.json), [forwarding](run-005/hotspots-forward.json) | [Forwarding stacks](run-005/perf-callers-forward.txt) |
| VXLAN, CPUs 8–11 | [Source](run-002/hotspots-source.json), [forwarding](run-002/hotspots-forward.json) | [Forwarding stacks](run-002/perf-callers-forward.txt) |
| Direct TC | [All CPUs](run-000/hotspots-all.json) | [Stacks](run-000/perf-callers-all.txt) |
| TC, CPUs 8–11 | [Source](run-001/hotspots-source.json), [forwarding](run-001/hotspots-forward.json) | [Forwarding stacks](run-001/perf-callers-forward.txt) |

Raw `perf.data` files remain local and are excluded from version control.
The [benchmark guide](../../../benchmarks.md#replication-stages-and-profiles) describes how to collect new recordings.
Each trial records its complete perf command in `result.json`.
For a local recording, inspect self samples with `sudo perf report -f -i perf.data --stdio --no-children --call-graph none --sort symbol`.
Use `--cpu 8,9,10,11` to restrict the view to the forwarding targets, and `--call-graph graph,1,caller` to inspect caller stacks.

## Supplemental controls

Two further diagnostic trials checked enqueue drops with rate-limited input and with more flows.
Both use four forwarding CPUs and include perf sampling and CPUMAP tracing, so their throughput is excluded from the ordinary comparison.
The [control script](../controls-profile/control.py) and [environment](../controls-profile/environment.json) retain the configuration.

| Workload | Enqueue drop fraction | Counters | Forwarding samples |
| --- | ---: | --- | --- |
| 64 flows, requested input 0.4 Mpps | 11.01% | [Counters](../controls-profile/run-000/cpumap-counters.json) | [Self samples](../controls-profile/run-000/hotspots-forward.json), [stacks](../controls-profile/run-000/perf-callers-forward.txt) |
| 4096 flows, unpaced input | 14.42% | [Counters](../controls-profile/run-001/cpumap-counters.json) | [Self samples](../controls-profile/run-001/hotspots-forward.json), [stacks](../controls-profile/run-001/perf-callers-forward.txt) |

The paced trace confirms that enqueue overflow occurs even at the lower average requested rate with this burst pattern.
CPU 8 received 546,134 of the 594,510 dropped inputs; CPU 11 recorded none.
All worker allocation-drop and program-drop counters remained zero.

The 4096-flow trace distributed enqueue attempts across all four targets, and every target still recorded queue overflow.
Map lookups, devmap processing, and the CPUMAP execution path remained visible in the samples.
The header-cache update also retained its bucket-lock call chain.
This trace offered 1.766 Mpps and received 3.018 Mpps, compared with medians of 1.957 and 2.793 Mpps in the uninstrumented control.
Instrumentation and shared-host variation change the operating point; these profiles locate executed paths and drops rather than providing a replacement throughput ranking.
