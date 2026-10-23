#!/usr/bin/env python3
"""Measure replication stages, with separate paced and sampled-profile trials."""
import argparse
import copy
import itertools
import json
import os
from pathlib import Path
import platform
import random
import signal
import sys
import time

import compare


def cases(phase):
    stages = [("broadcast", "xdp", []), ("vxlan", "xdp", []),
              ("vxlan", "xdp", [8]), ("vxlan", "xdp", [8, 9, 10, 11])]
    if phase == "profile":
        stages += [("vxlan", "tc", []), ("vxlan", "tc", [8, 9, 10, 11])]
    frames = [64, 1514] if phase == "saturation" else [64]
    repetitions = 1 if phase == "profile" else 3
    result = []
    for size, repeat in itertools.product(frames, range(repetitions)):
        order = stages.copy()
        random.Random(20261022 + size + repeat).shuffle(order)
        for mode, backend, cpus in order:
            result.append(dict(mode=mode, backend=backend, frame_size=size, fanout=2,
                               repeat=repeat, workers=4, queues=4, cpu_redirect=bool(cpus), forward_cpus=cpus))
    return result


class ProfileTrial(compare.Trial):
    def setup(self):
        super().setup()
        program = compare.attached_program(self.dut, "p0")
        info = compare.json_command("bpftool", "-j", "prog", "show", "id", program)
        (self.directory / "ingress-program.json").write_text(json.dumps(info, indent=2) + "\n")
        if not self.case["cpu_redirect"]:
            return
        map_id = compare.program_map(program, "cpu_map")
        script = self.directory / "cpumap.bt"
        script.write_text(f'''BEGIN {{ printf("ready\\n"); @start_ns = nsecs; }}
tracepoint:xdp:xdp_cpumap_enqueue /args.map_id == {map_id}/ {{
  @enqueue_processed[args.to_cpu] = sum(args.processed);
  @enqueue_drops[args.to_cpu] = sum(args.drops);
}}
tracepoint:xdp:xdp_cpumap_kthread /args.map_id == {map_id}/ {{
  @thread_processed[args.cpu] = sum(args.processed);
  @thread_drops[args.cpu] = sum(args.drops);
  @xdp_drop[args.cpu] = sum(args.xdp_drop);
  @xdp_redirect[args.cpu] = sum(args.xdp_redirect);
  @xdp_pass[args.cpu] = sum(args.xdp_pass);
}}
END {{ @end_ns = nsecs; }}
''')
        tracer = self.spawn("cpumap-trace", ["bpftrace", "-q", "-f", "json", "-B", "line", script])
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            log = (self.directory / "cpumap-trace.log").read_text()
            if tracer.poll() is not None:
                raise RuntimeError(f"CPUMAP tracer stopped: {log}")
            if "ready" in log:
                return
            time.sleep(0.05)
        raise RuntimeError("CPUMAP tracer attachment timed out")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xdperf", type=Path, required=True)
    parser.add_argument("--plugins", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--phase", choices=["saturation", "paced", "profile"], required=True)
    parser.add_argument("--pps", type=int, default=400000, help="total input rate in paced trials")
    args = parser.parse_args()
    if os.geteuid() or not {0, 1, 2, 3, 8, 9, 10, 11}.issubset(os.sched_getaffinity(0)):
        parser.error("run as root with CPUs 0-3 and 8-11 available")
    if args.pps <= 0:
        parser.error("paced input rate must be positive")
    args.binary = compare.ROOT / "bin/goxdp"
    args.counters = compare.ROOT / "bin/goxdp-perf-counters"
    args.cpus, args.batch_size, args.warmup, args.flows = [0, 1, 2, 3], 1, 2, 64
    args.profile = args.phase == "profile"
    args.seconds = 10 if args.profile else 5
    if args.phase != "paced":
        args.pps = 0
    args.output.mkdir(parents=True, exist_ok=False)
    metadata = dict(time_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    kernel=platform.uname()._asdict(),
                    args={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
                    binary_sha256=compare.digest(args.binary), xdperf_sha256=compare.digest(args.xdperf),
                    plugin_sha256=compare.digest(args.plugins / "simpleudp.go.wasm"),
                    counters_sha256=compare.digest(args.counters), runner_sha256=compare.digest(compare.__file__),
                    stages_sha256=compare.digest(__file__), available_cpus=sorted(os.sched_getaffinity(0)),
                    profile_scope="Generator CPUs 0-3 plus configured forwarding CPUs; includes veth receivers and unrelated work.",
                    trace_scope="Own CPUMAP ID only; totals span generator startup, warmup, sample and shutdown.",
                    pacing="XDPerf finite replay uses bursts with a nominal 100 ms interval; requested PPS is not a smooth arrival rate.")
    (args.output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    results = []
    try:
        for index, case in enumerate(cases(args.phase)):
            directory = args.output / f"run-{index:03d}"
            directory.mkdir()
            settings = copy.copy(args)
            settings.forward_cpus = case["forward_cpus"]
            trial = (ProfileTrial if args.profile else compare.Trial)(settings, case, directory)
            print(f"[{index + 1}/{len(cases(args.phase))}] {case}", flush=True)
            try:
                result = trial.run()
                (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
                results.append(result)
                (args.output / "runs.json").write_text(json.dumps(results, indent=2) + "\n")
                print(f"offered={result['offered_pps']:.0f} received={result['delivered_pps']:.0f} deficit={result['loss_fraction']:+.5%}", flush=True)
            finally:
                trial.close()
    finally:
        if "SUDO_UID" in os.environ:
            for path in [args.output, *args.output.rglob("*")]:
                os.chown(path, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    main()
