# XDP and TC benchmark results

These measurements cover the generator, veth forwarding, and receiver XDP programs on one host.
The XDP/TC ratio compares median aggregate received throughput for that whole pipeline; it does not isolate DUT cost.
Continuous saturation does not establish maximum loss-free capacity.

Recorded: 2026-10-22T01:21:15Z.
Kernel: `7.0.0-38-generic`; CPU: AMD EPYC 7713P 64-Core Processor; hypervisor: KVM.
Completed trials: 12; expected repetitions per point: 3.
CPUMAP targets: disabled.
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
| vxlan | 64 | 2 | 4/4 | off | 1.861 | 1.056 | 1.763 | 3/3 |
| vxlan | 1514 | 2 | 4/4 | off | 1.454 | 0.896 | 1.622 | 3/3 |

## Offered and received traffic

Offered traffic is XDPerf's processed TX count; each receiver counts actual arrivals in its XDP map.
The signed deficit is `1 - aggregate_received_pps / (offered_pps * fanout)`.
Counter lookups are sequential and each rate uses its own sampling interval.
Small positive or negative deficits can result from sampling skew and packets in flight; these values alone do not establish loss or duplication.
Large positive deficits show a delivery shortfall at the observed offered load and must be reported alongside throughput.
Exact frame copies and local UDP delivery are checked separately by the integration and scenario tests.

| Mode | Bytes | Fanout | Workers/queues | CPUMAP | Backend | Offered Mpps median | Received Mpps median [min, max] | Signed deficit % median [min, max] |
| --- | ---: | ---: | --- | --- | --- | ---: | --- | --- |
| vxlan | 64 | 2 | 4/4 | off | tc | 0.528 | 1.056 [1.050, 1.218] | +0.00018 [+0.00011, +0.00098] |
| vxlan | 64 | 2 | 4/4 | off | xdp | 0.931 | 1.861 [1.832, 1.884] | +0.00060 [+0.00056, +0.00108] |
| vxlan | 1514 | 2 | 4/4 | off | tc | 0.448 | 0.896 [0.896, 1.015] | +0.00088 [-0.00012, +0.00163] |
| vxlan | 1514 | 2 | 4/4 | off | xdp | 0.727 | 1.454 [1.399, 1.533] | +0.00073 [+0.00024, +0.00095] |

## Receiver CPU placement

Each CPU set contains the CPUs with positive packet deltas across the receivers in one trial.
The count in parentheses is the number of trials with that set; only receiver counters contribute, and sender counters are excluded.
These counters record receiver execution and do not by themselves identify forwarding CPU placement.

| Mode | Bytes | Fanout | Backend | Active receiver CPU sets (trials) |
| --- | ---: | ---: | --- | --- |
| vxlan | 64 | 2 | tc | `0,1,2,3` (3) |
| vxlan | 64 | 2 | xdp | `0,1,2,3` (3) |
| vxlan | 1514 | 2 | tc | `0,1,2,3` (3) |
| vxlan | 1514 | 2 | xdp | `0,1,2,3` (3) |

## Whole-host CPU activity

Equivalent busy cores are CPU execution seconds divided by the counter-window duration.
One fully busy core corresponds to 1.0; idle, I/O wait, and steal time are excluded from execution time.
These system-wide observations include generation, forwarding, receivers, and unrelated activity; they do not isolate DUT CPU usage.
Softirq and steal columns use the same core-seconds-per-second scale.

| Mode | Bytes | Fanout | Backend | Busy cores median [min, max] | Softirq cores median | Steal cores median |
| --- | ---: | ---: | --- | --- | ---: | ---: |
| vxlan | 64 | 2 | tc | 4.714 [4.541, 5.266] | 3.541 | 0.022 |
| vxlan | 64 | 2 | xdp | 4.743 [4.620, 5.235] | 3.304 | 0.008 |
| vxlan | 1514 | 2 | tc | 4.504 [4.472, 4.594] | 3.120 | 0.012 |
| vxlan | 1514 | 2 | xdp | 4.410 [4.249, 4.672] | 2.702 | 0.004 |

Before the matrix, the 2.000-second idle baseline averaged 14.672 busy cores across the host.
This baseline is recorded for context and is not subtracted from trial measurements.

## Sampling and host activity

Per-map measurement intervals range from 5.058528 to 5.070319 seconds.
Reading all maps takes 0.072 to 0.182 ms per snapshot.
The perf event duration ranges from 5.031368 to 5.038230 seconds.
Perf and map measurement windows differ; raw records preserve both intervals.
System-wide perf and /proc/stat include generator, forwarding, receivers, and unrelated host activity.
These counters cannot establish isolated forwarding cycles per packet on a shared host.
Before/after per-CPU packet counters in runs.json show where the source and receivers processed packets.
Veth results do not establish physical NIC throughput, latency, or maximum loss-free capacity.
