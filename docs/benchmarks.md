# Benchmarking XDP and TC replication

The benchmark compares `--backend xdp` with `--backend tc` in the same multiqueue veth topology.
It measures aggregate packets received by all outputs while XDPerf sends continuously at saturation.
The result describes the throughput of the generator, forwarding programs, and receivers sharing one host.
A separate physical NIC experiment is needed to measure NIC throughput or isolate forwarding cost.
See [the TC backend](tc.md) for the two forwarding implementations.
The [recorded veth experiments](benchmarks/2026-10-22-veth/README.md) include the main matrix, a single-worker and single-queue configuration, and CPUMAP forwarding.
The [flow-hash experiments](benchmarks/2026-10-22-flow-hash/README.md) compare direct forwarding with one and four CPUMAP CPUs using the same updated binary.
The [stage experiment](benchmarks/2026-10-22-stages/README.md) adds plain devmap replication, paced inputs, and separate kernel profiles.

## Build and run

Build the forwarding binary and map counter reader from the repository root:

```shell
env -u GOROOT make bench-tools CLANG=clang-18
```

The host needs Linux 6.6 or later, native XDP and TCX support, `ip`, `ethtool`, `bpftool`, `perf`, Python 3, and an XDPerf build with its compiled `simpleudp.go.wasm` plugin.
Use an idle host where possible.
Finish unit, integration, and scenario tests before starting measurements; do not run them concurrently with the benchmark.
Keep packet capture sockets off the forwarding interfaces because capture adds work to the TC path.

Run the main matrix with paths to the local XDPerf executable and plugin directory:

```shell
sudo python3 tests/benchmarks/compare.py \
  --xdperf /absolute/path/to/xdperf \
  --plugins /absolute/path/to/xdperf/plugins \
  --output /absolute/path/to/results/main
```

The output directory must not exist.
Each trial creates isolated namespaces and veth pairs, installs the selected forwarding backend, and starts one receiver per output.
The script shuts down its processes and removes its namespaces at the end of each trial, including failures.
It records cleanup failures in that trial's `cleanup-errors.json`.
It discovers the sender's maps through the sender process and receiver maps through the attached programs, so unrelated XDPerf processes are not treated as part of the experiment.

The default matrix has 108 trials:

| Setting | Values |
| --- | --- |
| Forwarding mode | Broadcast, VXLAN unicast replication |
| Backend | XDP, XDP + TC |
| Input Ethernet frame bytes | 64, 512, 1514 |
| Output count | 1, 2, 4 |
| Generator workers / veth queues | 4 / 4 |
| Generator CPUs | 0, 1, 2, 3 |
| Warmup / sample request | 2 seconds / 5 seconds |
| Repetitions | 3 per configuration and backend |
| Local delivery / CPUMAP | Off / off |
| Generator batch size | 1 |

Frame sizes include the Ethernet header and exclude FCS, preamble, and interpacket gap.
VXLAN output adds 50 bytes to each input frame; broadcast output retains the input size.
Every link uses MTU 1600.
The script checks effective receive/transmit queue counts and disables GRO, LRO, GSO, TSO, and checksum offloads on both ends of every link.
Each VXLAN output has a distinct unicast outer destination.
The input is unknown-unicast IPv4/UDP traffic with 64 source ports, making replication necessary in both modes.
The ingress port is excluded from the output count.

Backend order is shuffled within each configuration and repetition using a recorded seed.
Three repetitions provide an observed range; they do not establish a confidence interval or eliminate shared-host interference.
The default batch size is 1 because XDPerf's infinite mode repeats live test runs internally, and larger batches can keep a syscall active long enough to delay sampling or shutdown.
The `--count 4096` argument supplies its packet pool; it does not bound the duration of an infinite run.

## CPU and queue experiments

Keep CPU placement and queue counts equal within each backend pair.
The generator workers run on CPUs 0–3 by default.
Pinning the Go loader does not pin forwarding work: veth receive processing, softirqs, and receiver XDP execution can run on the generator CPUs or kernel workers.
The before/after per-CPU packet counters in `runs.json` record observed source and receiver processing placement.

Use a separate directory for a single-worker, single-queue comparison:

```shell
sudo python3 tests/benchmarks/compare.py \
  --xdperf /absolute/path/to/xdperf \
  --plugins /absolute/path/to/xdperf/plugins \
  --output /absolute/path/to/results/single-queue \
  --frames 64 --fanouts 2 --workers 1 --queues 1 --cpus 0
```

For the CPUMAP comparison, use VXLAN mode and a forwarding CPU separate from the generator CPUs:

```shell
sudo python3 tests/benchmarks/compare.py \
  --xdperf /absolute/path/to/xdperf \
  --plugins /absolute/path/to/xdperf/plugins \
  --output /absolute/path/to/results/cpumap \
  --modes vxlan --frames 64,1514 --fanouts 2 \
  --cpu-redirect --forward-cpu 8
```

Use multiple forwarding CPUs to measure flow distribution within a VNI:

```shell
sudo python3 tests/benchmarks/compare.py \
  --xdperf /absolute/path/to/xdperf \
  --plugins /absolute/path/to/xdperf/plugins \
  --output /absolute/path/to/results/cpumap-four \
  --modes vxlan --frames 64,1514 --fanouts 2 \
  --cpu-redirect --forward-cpus 8,9,10,11
```

The script checks CPU availability, rejects duplicates, and requires forwarding CPUs to be separate from generator CPUs.
The VXLAN loader configures a 2048-frame CPUMAP queue for each selected forwarding CPU.
Ingress hashes the VNI and inner flow headers to choose a CPU; repeated packets in a flow retain their CPU while the target list stays unchanged.
Use the same binary for single-CPU, multiple-CPU, and direct comparisons so changes to parsing or encapsulation do not get mixed with changes to CPU placement.
Each supplemental command uses three repetitions, for 12 trials each.
Local application delivery remains off in these throughput experiments.
The [local delivery scenarios](testing.md) separately verify ordinary UDP reception with that option enabled and disabled.

## Replication stages and profiles

Run each phase separately to compare plain XDP devmap replication, direct VXLAN, and VXLAN through one or four CPUMAP CPUs:

```shell
sudo python3 tests/benchmarks/stages.py \
  --xdperf /absolute/path/to/xdperf \
  --plugins /absolute/path/to/xdperf/plugins \
  --output /absolute/path/to/results/stages-saturation \
  --phase saturation
```

Use `--phase paced --pps 400000` in a new directory for a fixed requested input rate.
XDPerf sends finite replay bursts at a nominal 100 ms interval, so compare the measured offered rates and deficits as well as the requested PPS.
This pacing does not establish smooth arrival behavior or maximum loss-free capacity.
The saturation phase uses 64- and 1514-byte inputs; the paced phase uses 64-byte inputs.
Both use three repetitions per stage and shuffle stage order within each repetition.

Use `--phase profile` in another directory to collect `perf record` stacks at 199 Hz for ten seconds per stage.
The profile phase also includes the direct and four-CPU TC configurations.
It requires `bpftrace` to aggregate CPUMAP enqueue and worker tracepoints, filtered by the trial's own map ID.
These trace totals span sender startup, warmup, sampling, and shutdown; their window differs from the receiver counter window.
The profile includes the generator CPUs and configured forwarding CPUs, including receiver processing and unrelated activity on those CPUs.
Sampling and tracing add work, so keep profile throughput separate from the ordinary throughput results.

The general comparison runner also accepts `--pps` and `--profile` for narrower experiments.
Use `--flows 4096` to enlarge the UDP source-port sweep while keeping the VNI and other flow fields unchanged.
The [recorded stage experiment](benchmarks/2026-10-22-stages/README.md#reproduction-and-scope) includes commands for the flow-count controls and the combined figure.

## Counters and sampling

The sender's TX map counts frames processed by XDPerf.
Treat that count as offered traffic: it does not establish acceptance by the DUT or successful output delivery.
Each receiver's XDP map counts packets that reached that output.
The aggregate received rate is the sum of the individual receiver rates; it scales with fanout and must be shown separately from offered input packets per second.

The counter reader samples maps in a fixed order and records a midpoint timestamp for each map lookup.
Each rate uses that map's own before/after interval.
The script records the span required to read all maps so sampling skew remains visible.
Setup diagnostics run before generation begins, outside the measurement interval.

The signed sampled deficit is:

```text
1 - aggregate_received_pps / (offered_pps * fanout)
```

Sequential snapshots and packets in flight can produce small positive or negative values.
Keep the sign and report the range; a negative sampled deficit alone does not prove duplication.
Exact inner bytes, distinct VXLAN outer headers, and local UDP delivery are verified by the integration and scenario tests.
Those correctness checks are separate from this saturation workload.
Large positive deficits show a delivery shortfall at the observed offered load and must be reported alongside throughput.
For example, four unpaced generator CPUs can offer more traffic than one CPUMAP forwarding CPU delivers.

Saturation measures the maximum throughput reached by this system under continuous load.
It does not establish maximum loss-free capacity.
That requires a paced offered-load sweep with finite packet counts, receiver draining, and sequence-based loss checks.
Latency is also outside this experiment.

`perf stat -a` and `/proc/stat` observe the entire host, including the generator, receivers, and unrelated workloads.
The counter window surrounds the perf command, so it differs from the perf event duration; both are retained in `runs.json`.
Do not divide global cycles by packet counts and label the result as DUT cycles per packet.
On a shared KVM host, CPU scheduling, steal time, and background work can change throughput even when application affinity is fixed.
Record the host conditions with any published comparison and retain the per-CPU activity counters.

## Generate the report

Install Matplotlib in the Python environment used for reporting.
The measurement script itself uses only the Python standard library.
Reporting does not require root:

```shell
python3 tests/benchmarks/report.py /absolute/path/to/results/main
python3 -m unittest discover -s tests/benchmarks -p 'test_*.py'
```

The report reads `environment.json` and `runs.json` and writes `summary.csv`, `report.md`, `throughput.svg`, and `throughput.png` in the same directory.
CSV rows retain mode, frame size, fanout, worker count, queue count, backend, CPUMAP selection, and forwarding CPU IDs when recorded by the runner.
Report different forwarding CPU sets in separate directories; the reporter rejects mixed sets in one dataset.
They include medians and observed minima/maxima for offered traffic, aggregate received traffic, every receiver, and the signed sampled deficit.
The chart shows received Mpps against fanout, with separate panels for frame sizes and forwarding configurations.
The table labels the ratio of XDP and TC median throughput as a whole-pipeline comparison.

An incomplete matrix is marked in the generated report.
Retain raw trial records and logs alongside the report, including binary and plugin hashes, kernel and CPU details, queue/offload settings, backend ordering, sampling durations, and CPU placement.
These records allow another run to distinguish a backend change from changes in the workload or host.
