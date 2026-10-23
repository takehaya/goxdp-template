# XDP and TC benchmark results

These measurements cover the generator, veth forwarding, and receiver XDP programs on one host.
The XDP/TC ratio compares median aggregate received throughput for that whole pipeline; it does not isolate DUT cost.
Continuous saturation does not establish maximum loss-free capacity.

Recorded: 2026-10-22T01:28:30Z.
Kernel: `7.0.0-38-generic`; CPU: AMD EPYC 7713P 64-Core Processor; hypervisor: KVM.
Completed trials: 12; expected repetitions per point: 3.
CPUMAP targets: 8, 9, 10, 11.
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
| vxlan | 64 | 2 | 4/4 | on | 2.652 | 0.961 | 2.761 | 3/3 |
| vxlan | 1514 | 2 | 4/4 | on | 1.908 | 0.827 | 2.308 | 3/3 |

## Offered and received traffic

Offered traffic is XDPerf's processed TX count; each receiver counts actual arrivals in its XDP map.
The signed deficit is `1 - aggregate_received_pps / (offered_pps * fanout)`.
Counter lookups are sequential and each rate uses its own sampling interval.
Small positive or negative deficits can result from sampling skew and packets in flight; these values alone do not establish loss or duplication.
Large positive deficits show a delivery shortfall at the observed offered load and must be reported alongside throughput.
Exact frame copies and local UDP delivery are checked separately by the integration and scenario tests.

| Mode | Bytes | Fanout | Workers/queues | CPUMAP | Backend | Offered Mpps median | Received Mpps median [min, max] | Signed deficit % median [min, max] |
| --- | ---: | ---: | --- | --- | --- | ---: | --- | --- |
| vxlan | 64 | 2 | 4/4 | on | tc | 2.067 | 0.961 [0.923, 0.974] | +77.10090 [+76.27739, +77.68050] |
| vxlan | 64 | 2 | 4/4 | on | xdp | 1.873 | 2.652 [2.627, 2.706] | +29.19452 [+28.06663, +32.45344] |
| vxlan | 1514 | 2 | 4/4 | on | tc | 1.364 | 0.827 [0.826, 1.027] | +68.59015 [+62.89138, +69.70619] |
| vxlan | 1514 | 2 | 4/4 | on | xdp | 1.020 | 1.908 [1.799, 2.009] | +5.61094 [+4.07462, +6.49307] |

## Receiver CPU placement

Each CPU set contains the CPUs with positive packet deltas across the receivers in one trial.
The count in parentheses is the number of trials with that set; only receiver counters contribute, and sender counters are excluded.
These counters record receiver execution and do not by themselves identify forwarding CPU placement.

| Mode | Bytes | Fanout | Backend | Active receiver CPU sets (trials) |
| --- | ---: | ---: | --- | --- |
| vxlan | 64 | 2 | tc | `8` (1); `9` (1); `11` (1) |
| vxlan | 64 | 2 | xdp | `8,9,10,11` (3) |
| vxlan | 1514 | 2 | tc | `9` (1); `11` (2) |
| vxlan | 1514 | 2 | xdp | `8,9,10,11` (3) |

## Whole-host CPU activity

Equivalent busy cores are CPU execution seconds divided by the counter-window duration.
One fully busy core corresponds to 1.0; idle, I/O wait, and steal time are excluded from execution time.
These system-wide observations include generation, forwarding, receivers, and unrelated activity; they do not isolate DUT CPU usage.
Softirq and steal columns use the same core-seconds-per-second scale.

| Mode | Bytes | Fanout | Backend | Busy cores median [min, max] | Softirq cores median | Steal cores median |
| --- | ---: | ---: | --- | --- | ---: | ---: |
| vxlan | 64 | 2 | tc | 8.744 [8.566, 9.412] | 3.124 | 0.012 |
| vxlan | 64 | 2 | xdp | 8.496 [8.465, 8.506] | 2.912 | 0.010 |
| vxlan | 1514 | 2 | tc | 8.685 [8.467, 9.103] | 2.523 | 0.013 |
| vxlan | 1514 | 2 | xdp | 7.976 [7.362, 7.976] | 2.527 | 0.014 |

Before the matrix, the 2.000-second idle baseline averaged 1.505 busy cores across the host.
This baseline is recorded for context and is not subtracted from trial measurements.

## Sampling and host activity

Per-map measurement intervals range from 5.067677 to 5.236546 seconds.
Reading all maps takes 0.106 to 0.251 ms per snapshot.
The perf event duration ranges from 5.035630 to 5.200531 seconds.
Perf and map measurement windows differ; raw records preserve both intervals.
System-wide perf and /proc/stat include generator, forwarding, receivers, and unrelated host activity.
These counters cannot establish isolated forwarding cycles per packet on a shared host.
Before/after per-CPU packet counters in runs.json show where the source and receivers processed packets.
Veth results do not establish physical NIC throughput, latency, or maximum loss-free capacity.
