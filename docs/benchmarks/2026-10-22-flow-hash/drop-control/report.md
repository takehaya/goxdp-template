# Generator and veth control

The control sent 64-byte frames through one multiqueue veth pair directly to XDPerf's receiver XDP program, which counts and drops them.
It ran no forwarding program, replication, VXLAN encapsulation, or CPUMAP.
The four generator workers used CPUs 0–3, and receiver counters advanced on CPUs 0–3 in every trial.
Both endpoints had four receive and transmit queues, MTU 1600, and the same disabled checksum and segmentation offloads as the forwarding experiments.

Three trials with two-second warmups and five-second requested measurement windows produced a median received rate of 3.834 Mpps, with an observed range of 3.825–3.854 Mpps.
This is one received packet per input, while the VXLAN experiments report the sum of two outputs.
The control uses one veth hop and no intermediate forwarding namespace, so the difference from VXLAN throughput cannot be attributed solely to the BPF forwarding code.
It measures the generator/receiver path under the recorded settings, including `--batch-size 1`; it does not establish an optimized generator limit or physical NIC performance.

The control used identical XDPerf, plugin, counter-reader, and shared-runner artifacts to the three forwarding matrices.
See [environment.json](environment.json) for hashes and configuration, [runs.json](runs.json) for all counters and durations, and [control.py](control.py) for the diagnostic script snapshot.
