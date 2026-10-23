# XDP and TC benchmark results

These measurements cover the generator, veth forwarding, and receiver XDP programs on one host.
The XDP/TC ratio compares median aggregate received throughput for that whole pipeline; it does not isolate DUT cost.
Continuous saturation does not establish maximum loss-free capacity.

Recorded: 2026-10-21T19:20:13Z.
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
| vxlan | 64 | 2 | 4/4 | on | 0.834 | 0.413 | 2.021 | 3/3 |
| vxlan | 1514 | 2 | 4/4 | on | 0.808 | 0.378 | 2.135 | 3/3 |

## Offered and received traffic

Offered traffic is XDPerf's processed TX count; each receiver counts actual arrivals in its XDP map.
The signed deficit is `1 - aggregate_received_pps / (offered_pps * fanout)`.
Counter lookups are sequential and each rate uses its own sampling interval.
Small positive or negative deficits can result from sampling skew and packets in flight; these values alone do not establish loss or duplication.
Large positive deficits show a delivery shortfall at the observed offered load and must be reported alongside throughput.
Exact frame copies and local UDP delivery are checked separately by the integration and scenario tests.

| Mode | Bytes | Fanout | Workers/queues | CPUMAP | Backend | Offered Mpps median | Received Mpps median [min, max] | Signed deficit % median [min, max] |
| --- | ---: | ---: | --- | --- | --- | ---: | --- | --- |
| vxlan | 64 | 2 | 4/4 | on | tc | 2.023 | 0.413 [0.398, 0.420] | +90.06635 [+89.79831, +90.41934] |
| vxlan | 64 | 2 | 4/4 | on | xdp | 1.978 | 0.834 [0.817, 0.849] | +78.68931 [+78.54354, +80.05659] |
| vxlan | 1514 | 2 | 4/4 | on | tc | 1.423 | 0.378 [0.376, 0.379] | +86.70802 [+86.52036, +86.94173] |
| vxlan | 1514 | 2 | 4/4 | on | xdp | 1.394 | 0.808 [0.764, 0.809] | +71.33352 [+71.02034, +72.52975] |

## Whole-host CPU activity

Equivalent busy cores are CPU execution seconds divided by the counter-window duration.
One fully busy core corresponds to 1.0; idle, I/O wait, and steal time are excluded from execution time.
These system-wide observations include generation, forwarding, receivers, and unrelated activity; they do not isolate DUT CPU usage.
Softirq and steal columns use the same core-seconds-per-second scale.

| Mode | Bytes | Fanout | Backend | Busy cores median [min, max] | Softirq cores median | Steal cores median |
| --- | ---: | ---: | --- | --- | ---: | ---: |
| vxlan | 64 | 2 | tc | 5.404 [5.354, 5.461] | 2.767 | 0.012 |
| vxlan | 64 | 2 | xdp | 5.458 [5.453, 5.463] | 2.632 | 0.006 |
| vxlan | 1514 | 2 | tc | 5.441 [5.408, 5.447] | 1.888 | 0.010 |
| vxlan | 1514 | 2 | xdp | 5.452 [5.369, 5.459] | 1.778 | 0.000 |

Before the matrix, the 2.000-second idle baseline averaged 0.315 busy cores across the host.
This baseline is recorded for context and is not subtracted from trial measurements.

## Sampling and host activity

Per-map measurement intervals range from 5.065000 to 5.071899 seconds.
Reading all maps takes 0.089 to 0.186 ms per snapshot.
The perf event duration ranges from 5.033003 to 5.042013 seconds.
Perf and map measurement windows differ; raw records preserve both intervals.
System-wide perf and /proc/stat include generator, forwarding, receivers, and unrelated host activity.
These counters cannot establish isolated forwarding cycles per packet on a shared host.
Before/after per-CPU packet counters in runs.json show where the source and receivers processed packets.
Veth results do not establish physical NIC throughput, latency, or maximum loss-free capacity.
