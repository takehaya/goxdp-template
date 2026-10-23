# XDP and TC benchmark results

These measurements cover the generator, veth forwarding, and receiver XDP programs on one host.
The XDP/TC ratio compares median aggregate received throughput for that whole pipeline; it does not isolate DUT cost.
Continuous saturation does not establish maximum loss-free capacity.

Recorded: 2026-10-21T19:16:36Z.
Kernel: `7.0.0-38-generic`; CPU: AMD EPYC 7713P 64-Core Processor; hypervisor: KVM.
Completed trials: 12; expected repetitions per point: 3.
Matrix status: complete.
Raw inputs and executable hashes are in [environment.json](environment.json) and [runs.json](runs.json).

See the [benchmark methodology](../../../benchmarks.md) for the workload and interpretation of these measurements.

![Median aggregate receiver throughput with observed minimum and maximum](throughput.svg)

[PNG](throughput.png) | [CSV with all receiver rates](summary.csv)

## Whole-pipeline comparison

The ratio divides the XDP median by the TC median for the same configuration.
Error bars show observed minimum and maximum, not confidence intervals.

| Mode | Input bytes | Fanout | Workers/queues | CPUMAP | XDP Mpps | TC Mpps | XDP/TC | Repeats XDP/TC |
| --- | ---: | ---: | --- | --- | ---: | ---: | ---: | --- |
| broadcast | 64 | 2 | 1/1 | off | 0.669 | 0.475 | 1.407 | 3/3 |
| vxlan | 64 | 2 | 1/1 | off | 0.517 | 0.350 | 1.477 | 3/3 |

## Offered and received traffic

Offered traffic is XDPerf's processed TX count; each receiver counts actual arrivals in its XDP map.
The signed deficit is `1 - aggregate_received_pps / (offered_pps * fanout)`.
Counter lookups are sequential and each rate uses its own sampling interval.
Small positive or negative deficits can result from sampling skew and packets in flight; these values alone do not establish loss or duplication.
Large positive deficits show a delivery shortfall at the observed offered load and must be reported alongside throughput.
Exact frame copies and local UDP delivery are checked separately by the integration and scenario tests.

| Mode | Bytes | Fanout | Workers/queues | CPUMAP | Backend | Offered Mpps median | Received Mpps median [min, max] | Signed deficit % median [min, max] |
| --- | ---: | ---: | --- | --- | --- | ---: | --- | --- |
| broadcast | 64 | 2 | 1/1 | off | tc | 0.238 | 0.475 [0.473, 0.477] | -0.00017 [-0.00038, +0.00087] |
| broadcast | 64 | 2 | 1/1 | off | xdp | 0.334 | 0.669 [0.639, 0.676] | +0.00055 [+0.00020, +0.00092] |
| vxlan | 64 | 2 | 1/1 | off | tc | 0.175 | 0.350 [0.345, 0.356] | +0.00070 [+0.00028, +0.00107] |
| vxlan | 64 | 2 | 1/1 | off | xdp | 0.258 | 0.517 [0.514, 0.521] | +0.00072 [+0.00047, +0.00109] |

## Whole-host CPU activity

Equivalent busy cores are CPU execution seconds divided by the counter-window duration.
One fully busy core corresponds to 1.0; idle, I/O wait, and steal time are excluded from execution time.
These system-wide observations include generation, forwarding, receivers, and unrelated activity; they do not isolate DUT CPU usage.
Softirq and steal columns use the same core-seconds-per-second scale.

| Mode | Bytes | Fanout | Backend | Busy cores median [min, max] | Softirq cores median | Steal cores median |
| --- | ---: | ---: | --- | --- | ---: | ---: |
| broadcast | 64 | 2 | tc | 1.420 [1.367, 1.444] | 0.819 | 0.010 |
| broadcast | 64 | 2 | xdp | 1.388 [1.370, 1.395] | 0.767 | 0.004 |
| vxlan | 64 | 2 | tc | 1.400 [1.378, 1.427] | 0.874 | 0.006 |
| vxlan | 64 | 2 | xdp | 1.394 [1.370, 1.418] | 0.807 | 0.004 |

Before the matrix, the 2.000-second idle baseline averaged 0.300 busy cores across the host.
This baseline is recorded for context and is not subtracted from trial measurements.

## Sampling and host activity

Per-map measurement intervals range from 5.042481 to 5.046841 seconds.
Reading all maps takes 0.088 to 0.194 ms per snapshot.
The perf event duration ranges from 5.020297 to 5.024373 seconds.
Perf and map measurement windows differ; raw records preserve both intervals.
System-wide perf and /proc/stat include generator, forwarding, receivers, and unrelated host activity.
These counters cannot establish isolated forwarding cycles per packet on a shared host.
Before/after per-CPU packet counters in runs.json show where the source and receivers processed packets.
Veth results do not establish physical NIC throughput, latency, or maximum loss-free capacity.
