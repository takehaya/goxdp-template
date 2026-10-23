# XDP and TC benchmark results

These measurements cover the generator, veth forwarding, and receiver XDP programs on one host.
The XDP/TC ratio compares median aggregate received throughput for that whole pipeline; it does not isolate DUT cost.
Continuous saturation does not establish maximum loss-free capacity.

Recorded: 2026-10-21T18:41:06Z.
Kernel: `7.0.0-38-generic`; CPU: AMD EPYC 7713P 64-Core Processor; hypervisor: KVM.
Completed trials: 108; expected repetitions per point: 3.
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
| broadcast | 64 | 1 | 4/4 | off | 1.850 | 1.117 | 1.656 | 3/3 |
| broadcast | 64 | 2 | 4/4 | off | 2.573 | 1.376 | 1.869 | 3/3 |
| broadcast | 64 | 4 | 4/4 | off | 3.369 | 1.620 | 2.080 | 3/3 |
| broadcast | 512 | 1 | 4/4 | off | 1.634 | 1.052 | 1.554 | 3/3 |
| broadcast | 512 | 2 | 4/4 | off | 2.351 | 1.350 | 1.742 | 3/3 |
| broadcast | 512 | 4 | 4/4 | off | 3.081 | 1.626 | 1.895 | 3/3 |
| broadcast | 1514 | 1 | 4/4 | off | 1.320 | 0.915 | 1.443 | 3/3 |
| broadcast | 1514 | 2 | 4/4 | off | 2.005 | 1.154 | 1.737 | 3/3 |
| broadcast | 1514 | 4 | 4/4 | off | 2.798 | 1.394 | 2.007 | 3/3 |
| vxlan | 64 | 1 | 4/4 | off | 1.366 | 0.777 | 1.759 | 3/3 |
| vxlan | 64 | 2 | 4/4 | off | 1.905 | 1.093 | 1.742 | 3/3 |
| vxlan | 64 | 4 | 4/4 | off | 2.328 | 1.311 | 1.776 | 3/3 |
| vxlan | 512 | 1 | 4/4 | off | 1.235 | 0.732 | 1.688 | 3/3 |
| vxlan | 512 | 2 | 4/4 | off | 1.734 | 1.005 | 1.725 | 3/3 |
| vxlan | 512 | 4 | 4/4 | off | 2.304 | 1.277 | 1.804 | 3/3 |
| vxlan | 1514 | 1 | 4/4 | off | 1.054 | 0.641 | 1.646 | 3/3 |
| vxlan | 1514 | 2 | 4/4 | off | 1.559 | 0.888 | 1.756 | 3/3 |
| vxlan | 1514 | 4 | 4/4 | off | 2.142 | 1.147 | 1.868 | 3/3 |

## Offered and received traffic

Offered traffic is XDPerf's processed TX count; each receiver counts actual arrivals in its XDP map.
The signed deficit is `1 - aggregate_received_pps / (offered_pps * fanout)`.
Counter lookups are sequential and each rate uses its own sampling interval.
Small positive or negative deficits can result from sampling skew and packets in flight; these values alone do not establish loss or duplication.
Large positive deficits show a delivery shortfall at the observed offered load and must be reported alongside throughput.
Exact frame copies and local UDP delivery are checked separately by the integration and scenario tests.

| Mode | Bytes | Fanout | Workers/queues | CPUMAP | Backend | Offered Mpps median | Received Mpps median [min, max] | Signed deficit % median [min, max] |
| --- | ---: | ---: | --- | --- | --- | ---: | --- | --- |
| broadcast | 64 | 1 | 4/4 | off | tc | 1.117 | 1.117 [1.116, 1.252] | +0.00003 [-0.00126, +0.00059] |
| broadcast | 64 | 1 | 4/4 | off | xdp | 1.850 | 1.850 [1.844, 1.875] | +0.00044 [-0.00015, +0.00056] |
| broadcast | 64 | 2 | 4/4 | off | tc | 0.688 | 1.376 [1.373, 1.412] | +0.00028 [-0.00030, +0.00041] |
| broadcast | 64 | 2 | 4/4 | off | xdp | 1.286 | 2.573 [2.487, 2.591] | +0.00003 [-0.00064, +0.00069] |
| broadcast | 64 | 4 | 4/4 | off | tc | 0.405 | 1.620 [1.609, 1.624] | +0.00016 [-0.00011, +0.00073] |
| broadcast | 64 | 4 | 4/4 | off | xdp | 0.842 | 3.369 [3.338, 3.375] | +0.00065 [-0.00003, +0.00181] |
| broadcast | 512 | 1 | 4/4 | off | tc | 1.052 | 1.052 [1.047, 1.116] | +0.00012 [-0.00010, +0.00044] |
| broadcast | 512 | 1 | 4/4 | off | xdp | 1.634 | 1.634 [1.632, 1.641] | +0.00008 [+0.00004, +0.00073] |
| broadcast | 512 | 2 | 4/4 | off | tc | 0.675 | 1.350 [1.286, 1.354] | +0.00063 [+0.00052, +0.00077] |
| broadcast | 512 | 2 | 4/4 | off | xdp | 1.176 | 2.351 [2.334, 2.353] | -0.00009 [-0.00016, +0.00053] |
| broadcast | 512 | 4 | 4/4 | off | tc | 0.407 | 1.626 [1.551, 1.642] | +0.00005 [-0.00009, +0.00029] |
| broadcast | 512 | 4 | 4/4 | off | xdp | 0.770 | 3.081 [2.999, 3.155] | +0.00066 [-0.00025, +0.00101] |
| broadcast | 1514 | 1 | 4/4 | off | tc | 0.915 | 0.915 [0.904, 0.961] | -0.00015 [-0.00071, +0.00085] |
| broadcast | 1514 | 1 | 4/4 | off | xdp | 1.320 | 1.320 [1.302, 1.321] | -0.00035 [-0.00067, -0.00031] |
| broadcast | 1514 | 2 | 4/4 | off | tc | 0.577 | 1.154 [1.150, 1.287] | +0.00027 [-0.00006, +0.00048] |
| broadcast | 1514 | 2 | 4/4 | off | xdp | 1.003 | 2.005 [1.968, 2.044] | +0.00111 [+0.00089, +0.00112] |
| broadcast | 1514 | 4 | 4/4 | off | tc | 0.348 | 1.394 [1.392, 1.398] | +0.00007 [-0.00028, +0.00127] |
| broadcast | 1514 | 4 | 4/4 | off | xdp | 0.699 | 2.798 [2.771, 2.836] | +0.00001 [-0.00002, +0.00024] |
| vxlan | 64 | 1 | 4/4 | off | tc | 0.777 | 0.777 [0.776, 0.779] | -0.00014 [-0.00030, +0.00034] |
| vxlan | 64 | 1 | 4/4 | off | xdp | 1.366 | 1.366 [1.365, 1.411] | -0.00012 [-0.00038, +0.00002] |
| vxlan | 64 | 2 | 4/4 | off | tc | 0.547 | 1.093 [1.071, 1.099] | +0.00084 [+0.00080, +0.00145] |
| vxlan | 64 | 2 | 4/4 | off | xdp | 0.952 | 1.905 [1.884, 1.916] | +0.00061 [+0.00003, +0.00086] |
| vxlan | 64 | 4 | 4/4 | off | tc | 0.328 | 1.311 [1.301, 1.370] | +0.00030 [-0.00000, +0.00089] |
| vxlan | 64 | 4 | 4/4 | off | xdp | 0.582 | 2.328 [2.316, 2.496] | +0.00013 [+0.00012, +0.00093] |
| vxlan | 512 | 1 | 4/4 | off | tc | 0.732 | 0.732 [0.724, 0.734] | +0.00010 [-0.00032, +0.00011] |
| vxlan | 512 | 1 | 4/4 | off | xdp | 1.235 | 1.235 [1.216, 1.248] | -0.00040 [-0.00052, +0.00027] |
| vxlan | 512 | 2 | 4/4 | off | tc | 0.503 | 1.005 [1.002, 1.020] | +0.00005 [-0.00012, +0.00071] |
| vxlan | 512 | 2 | 4/4 | off | xdp | 0.867 | 1.734 [1.698, 1.770] | +0.00049 [-0.00032, +0.00077] |
| vxlan | 512 | 4 | 4/4 | off | tc | 0.319 | 1.277 [1.250, 1.289] | +0.00025 [+0.00010, +0.00082] |
| vxlan | 512 | 4 | 4/4 | off | xdp | 0.576 | 2.304 [2.225, 2.330] | +0.00025 [-0.00030, +0.00093] |
| vxlan | 1514 | 1 | 4/4 | off | tc | 0.641 | 0.641 [0.632, 0.647] | -0.00003 [-0.00126, +0.00022] |
| vxlan | 1514 | 1 | 4/4 | off | xdp | 1.054 | 1.054 [1.041, 1.146] | +0.00005 [-0.00056, +0.00026] |
| vxlan | 1514 | 2 | 4/4 | off | tc | 0.444 | 0.888 [0.883, 0.888] | +0.00022 [+0.00018, +0.00075] |
| vxlan | 1514 | 2 | 4/4 | off | xdp | 0.780 | 1.559 [1.542, 1.567] | +0.00072 [-0.00065, +0.00098] |
| vxlan | 1514 | 4 | 4/4 | off | tc | 0.287 | 1.147 [1.045, 1.326] | +0.00053 [-0.00094, +0.00129] |
| vxlan | 1514 | 4 | 4/4 | off | xdp | 0.535 | 2.142 [2.082, 2.200] | +0.00045 [-0.00003, +0.00069] |

## Whole-host CPU activity

Equivalent busy cores are CPU execution seconds divided by the counter-window duration.
One fully busy core corresponds to 1.0; idle, I/O wait, and steal time are excluded from execution time.
These system-wide observations include generation, forwarding, receivers, and unrelated activity; they do not isolate DUT CPU usage.
Softirq and steal columns use the same core-seconds-per-second scale.

| Mode | Bytes | Fanout | Backend | Busy cores median [min, max] | Softirq cores median | Steal cores median |
| --- | ---: | ---: | --- | --- | ---: | ---: |
| broadcast | 64 | 1 | tc | 6.505 [6.489, 6.516] | 2.902 | 0.008 |
| broadcast | 64 | 1 | xdp | 6.504 [6.471, 6.841] | 2.777 | 0.008 |
| broadcast | 64 | 2 | tc | 6.552 [6.518, 6.797] | 3.284 | 0.008 |
| broadcast | 64 | 2 | xdp | 6.461 [5.485, 6.486] | 3.104 | 0.006 |
| broadcast | 64 | 4 | tc | 5.486 [5.456, 5.527] | 3.570 | 0.008 |
| broadcast | 64 | 4 | xdp | 5.501 [5.491, 5.502] | 3.393 | 0.002 |
| broadcast | 512 | 1 | tc | 5.442 [5.412, 5.479] | 2.689 | 0.004 |
| broadcast | 512 | 1 | xdp | 5.470 [5.412, 5.479] | 2.432 | 0.000 |
| broadcast | 512 | 2 | tc | 5.503 [5.457, 5.576] | 3.112 | 0.004 |
| broadcast | 512 | 2 | xdp | 5.518 [5.479, 5.529] | 2.856 | 0.004 |
| broadcast | 512 | 4 | tc | 5.507 [5.469, 5.510] | 3.472 | 0.004 |
| broadcast | 512 | 4 | xdp | 5.476 [5.419, 5.504] | 3.207 | 0.004 |
| broadcast | 1514 | 1 | tc | 5.497 [5.478, 5.521] | 2.327 | 0.010 |
| broadcast | 1514 | 1 | xdp | 5.483 [5.204, 5.490] | 1.949 | 0.004 |
| broadcast | 1514 | 2 | tc | 4.503 [4.459, 4.536] | 2.893 | 0.008 |
| broadcast | 1514 | 2 | xdp | 4.516 [4.503, 4.761] | 2.419 | 0.010 |
| broadcast | 1514 | 4 | tc | 4.408 [4.382, 4.422] | 3.335 | 0.006 |
| broadcast | 1514 | 4 | xdp | 4.412 [4.368, 4.488] | 2.870 | 0.006 |
| vxlan | 64 | 1 | tc | 4.415 [4.415, 4.429] | 3.231 | 0.006 |
| vxlan | 64 | 1 | xdp | 4.380 [4.337, 4.395] | 3.074 | 0.006 |
| vxlan | 64 | 2 | tc | 4.392 [4.336, 4.407] | 3.436 | 0.008 |
| vxlan | 64 | 2 | xdp | 4.386 [4.364, 4.397] | 3.299 | 0.014 |
| vxlan | 64 | 4 | tc | 4.422 [4.377, 4.427] | 3.657 | 0.008 |
| vxlan | 64 | 4 | xdp | 4.399 [4.361, 4.417] | 3.553 | 0.008 |
| vxlan | 512 | 1 | tc | 4.442 [4.409, 4.470] | 3.064 | 0.012 |
| vxlan | 512 | 1 | xdp | 4.394 [4.382, 4.407] | 2.795 | 0.010 |
| vxlan | 512 | 2 | tc | 4.431 [4.409, 4.442] | 3.325 | 0.006 |
| vxlan | 512 | 2 | xdp | 4.387 [4.380, 4.405] | 3.092 | 0.008 |
| vxlan | 512 | 4 | tc | 4.408 [4.378, 4.448] | 3.576 | 0.014 |
| vxlan | 512 | 4 | xdp | 4.417 [4.369, 4.421] | 3.387 | 0.004 |
| vxlan | 1514 | 1 | tc | 4.410 [4.391, 4.426] | 2.770 | 0.012 |
| vxlan | 1514 | 1 | xdp | 4.403 [4.388, 4.429] | 2.360 | 0.002 |
| vxlan | 1514 | 2 | tc | 4.400 [4.395, 4.442] | 3.142 | 0.012 |
| vxlan | 1514 | 2 | xdp | 4.424 [4.359, 4.428] | 2.732 | 0.004 |
| vxlan | 1514 | 4 | tc | 4.402 [4.390, 4.402] | 3.339 | 0.002 |
| vxlan | 1514 | 4 | xdp | 4.409 [4.393, 4.450] | 3.122 | 0.010 |

Before the matrix, the 2.000-second idle baseline averaged 2.530 busy cores across the host.
This baseline is recorded for context and is not subtracted from trial measurements.

## Sampling and host activity

Per-map measurement intervals range from 5.057744 to 5.084773 seconds.
Reading all maps takes 0.069 to 0.266 ms per snapshot.
The perf event duration ranges from 5.030207 to 5.050044 seconds.
Perf and map measurement windows differ; raw records preserve both intervals.
System-wide perf and /proc/stat include generator, forwarding, receivers, and unrelated host activity.
These counters cannot establish isolated forwarding cycles per packet on a shared host.
Before/after per-CPU packet counters in runs.json show where the source and receivers processed packets.
Veth results do not establish physical NIC throughput, latency, or maximum loss-free capacity.
