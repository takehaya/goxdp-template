#!/usr/bin/env python3
"""Compare XDP and XDP+TC over isolated multiqueue veth links using XDPerf."""
import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import random
import select
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]


def command(*args, namespace=None, check=True):
    argv = (["ip", "netns", "exec", namespace] if namespace else []) + list(map(str, args))
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if check and result.returncode:
        raise RuntimeError(f"{argv}: {result.stderr.strip()} {result.stdout.strip()}")
    return result.stdout


def json_command(*args, **kwargs):
    return json.loads(command(*args, **kwargs))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def maps_by_name(name):
    return {m["id"] for m in json_command("bpftool", "-j", "map", "show") if m.get("name") == name}


def process_map(process, name):
    owned = set()
    for info in Path(f"/proc/{process.pid}/fdinfo").iterdir():
        try:
            for line in info.read_text().splitlines():
                if line.startswith("map_id:"):
                    owned.add(int(line.split()[1]))
        except FileNotFoundError:
            continue
    candidates = owned & maps_by_name(name)
    if len(candidates) != 1:
        raise RuntimeError(f"PID {process.pid}: expected one owned {name}, got {candidates}")
    return candidates.pop()


def attached_program(namespace, device):
    info = json_command("ip", "-n", namespace, "-j", "-d", "link", "show", "dev", device)[0]
    return info.get("xdp", {}).get("prog", {}).get("id", 0)


def program_map(program, name):
    info = json_command("bpftool", "-j", "prog", "show", "id", program)
    if isinstance(info, list):
        info = info[0]
    for map_id in info.get("map_ids", []):
        m = json_command("bpftool", "-j", "map", "show", "id", map_id)
        if isinstance(m, list):
            m = m[0]
        if m.get("name") == name:
            return map_id
    raise RuntimeError(f"program {program} has no map {name}")


def cpu_times():
    result = {}
    for line in Path("/proc/stat").read_text().splitlines():
        key, *values = line.split()
        if key == "cpu" or (key.startswith("cpu") and key[3:].isdigit()):
            result[key] = list(map(int, values[:8]))
    return result


def cpu_delta(before, after):
    hz = os.sysconf("SC_CLK_TCK")
    result = {}
    for cpu, values in after.items():
        delta = [v - old for v, old in zip(values, before[cpu])]
        result[cpu] = {"busy_seconds": (sum(delta) - delta[3] - delta[4] - delta[7]) / hz,
                       "softirq_seconds": delta[6] / hz, "steal_seconds": delta[7] / hz}
    return result


def sender_command(args, case, config):
    cpus = args.cpus[:case["workers"]]
    argv = [args.xdperf, "run", "--device", "eth0", "--send", "--plugin", "simpleudp.go",
            "--plugin-path", args.plugins, "--cfgpath", config,
            "--parallelism", str(case["workers"]), "--cpu-mode", ",".join(map(str, cpus)),
            "--batch-size", str(args.batch_size), "--xdp-mode", "native", "--show-nic-stats"]
    if getattr(args, "pps", 0):
        # Keep a finite paced sender alive through warmup and counter sampling.
        argv += ["--duration", f"{args.warmup + args.seconds + 30}s", "--pps", str(args.pps)]
    else:
        argv += ["--count", "4096", "--infinite"]
    return argv


def generator_config(args, case):
    return {"src_ip": "198.18.0.1", "dst_ip": "198.18.0.2",
            "dst_mac": "02:ff:ff:ff:ff:01", "dst_port": 40001,
            "payload_size": case["frame_size"] - 42, "is_arp_resolve": False,
            "src_port_sweep_start": 10000, "src_port_sweep_end": 9999 + getattr(args, "flows", 64)}


class Trial:
    def __init__(self, args, case, directory):
        self.args, self.case, self.directory = args, case, directory
        self.prefix = f"gxbench-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self.namespaces, self.processes, self.logs = [], [], []
        self.dut, self.source = self.prefix + "-dut", self.prefix + "-source"
        self.rx_maps = {}
        self.topology = {}

    def namespace(self, name):
        command("ip", "netns", "add", name)
        self.namespaces.append(name)
        command("sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1", namespace=name)
        command("sysctl", "-qw", "net.ipv6.conf.default.disable_ipv6=1", namespace=name)

    def pair(self, dut_port, peer_ns, mac):
        queues = self.case["queues"]
        command("ip", "-n", self.dut, "link", "add", dut_port, "numtxqueues", queues,
                "numrxqueues", queues, "type", "veth", "peer", "name", "eth0",
                "numtxqueues", queues, "numrxqueues", queues, "netns", peer_ns)
        for namespace, dev, address in [(self.dut, dut_port, mac), (peer_ns, "eth0", mac[:-2] + "fe")]:
            command("ip", "-n", namespace, "link", "set", dev, "address", address, "mtu", "1600", "up")
            command("ethtool", "-K", dev, "gro", "off", "lro", "off", "gso", "off", "tso", "off",
                    "rx", "off", "tx", "off", namespace=namespace)
            channels = command("ethtool", "-l", dev, namespace=namespace)
            features = command("ethtool", "-k", dev, namespace=namespace)
            current = channels.split("Current hardware settings:")[-1]
            import re
            for direction in ("RX", "TX"):
                match = re.search(rf"^{direction}:\s*(\d+)", current, re.M)
                if not match or int(match.group(1)) != queues:
                    raise RuntimeError(f"{namespace}/{dev}: unexpected effective {direction} queues: {channels}")
            for feature in ("generic-receive-offload", "generic-segmentation-offload", "tcp-segmentation-offload", "large-receive-offload", "rx-checksumming", "tx-checksumming"):
                if re.search(rf"^{feature}: on", features, re.M):
                    raise RuntimeError(f"{namespace}/{dev}: {feature} is still enabled")
            self.topology[namespace + "/" + dev] = {"channels": channels, "features": features}

    def spawn(self, name, argv, namespace=None):
        log = (self.directory / (name + ".log")).open("w")
        self.logs.append(log)
        process = subprocess.Popen((["ip", "netns", "exec", namespace] if namespace else []) + list(map(str, argv)),
                                   stdout=log, stderr=subprocess.STDOUT)
        self.processes.append(process)
        return process

    def wait_attached(self, process, namespace, device, log_name):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError((self.directory / (log_name + ".log")).read_text())
            if attached_program(namespace, device):
                return
            time.sleep(0.05)
        raise RuntimeError(f"attachment timed out: {namespace}/{device}")

    def setup(self):
        self.namespace(self.dut)
        self.namespace(self.source)
        self.pair("p0", self.source, "02:00:00:00:00:01")
        ports = [{"device": "p0", "vni": 100}]
        group = {"vni": 100, "devices": ["p0"], "unicast_peers": []}
        for number in range(self.case["fanout"]):
            name, port = self.prefix + f"-rx{number}", f"p{number+1}"
            self.namespace(name)
            mac = f"02:00:00:00:{number+1:02x}:01"
            self.pair(port, name, mac)
            receiver = self.spawn(f"rx{number}", [self.args.xdperf, "run", "--device", "eth0", "--send=false",
                                                   "--recv", "--xdp-mode", "native"], namespace=name)
            self.wait_attached(receiver, name, "eth0", f"rx{number}")
            self.rx_maps[f"rx{number}"] = program_map(attached_program(name, "eth0"), "rx_stats_map")
            if self.case["mode"] == "vxlan":
                ports.append({"device": port, "local_ip": f"192.0.{number+2}.1"})
                group["unicast_peers"].append({"device": port, "remote_ip": f"192.0.{number+2}.2",
                                               "remote_mac": mac[:-2] + "fe"})
            group["devices"].append(port)
        argv = [self.args.binary, "--backend", self.case["backend"], "--mode", self.case["mode"], "--device", "p0"]
        if self.case["mode"] == "vxlan":
            config = self.directory / "vxlan.json"
            config.write_text(json.dumps({"ports": ports, "groups": [group]}, indent=2) + "\n")
            argv += ["--config", config]
            if self.case["cpu_redirect"]:
                argv += ["--cpu-redirect"]
                for cpu in self.args.forward_cpus:
                    argv += ["--cpu", str(cpu)]
        else:
            for port in group["devices"]:
                argv += ["--egress", port]
        forwarder = self.spawn("goxdp", argv, namespace=self.dut)
        self.wait_attached(forwarder, self.dut, "p0", "goxdp")
        self.offloads = json_command("ip", "-n", self.dut, "-j", "-d", "link", "show")
        self.link_before = json_command("ip", "-n", self.dut, "-j", "-s", "link", "show", "dev", "p0")[0]
        self.queue_before = command("ethtool", "-S", "p0", namespace=self.dut)

    def snapshot(self, sampler):
        sampler.stdin.write("sample\n")
        sampler.stdin.flush()
        if not select.select([sampler.stdout], [], [], 15)[0]:
            raise RuntimeError("counter sampler timed out")
        line = sampler.stdout.readline()
        if not line:
            raise RuntimeError("counter sampler exited")
        return json.loads(line)

    def run(self):
        self.setup()
        config = self.directory / "generator.json"
        config.write_text(json.dumps(generator_config(self.args, self.case), indent=2) + "\n")
        cpus = self.args.cpus[:self.case["workers"]]
        argv = sender_command(self.args, self.case, config)
        sender = self.spawn("tx", argv, namespace=self.source)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if sender.poll() is not None:
                raise RuntimeError((self.directory / "tx.log").read_text())
            if "TX packet processing started" in (self.directory / "tx.log").read_text():
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("XDPerf sender startup timed out")
        mapping = {"tx": process_map(sender, "tx_stats_map"), **self.rx_maps}
        sampler = subprocess.Popen([str(self.args.counters), *[f"{name}={number}" for name, number in mapping.items()]],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.processes.append(sampler)
        time.sleep(self.args.warmup)
        cpu_before = cpu_times()
        before = self.snapshot(sampler)
        profile = getattr(self.args, "profile", False)
        perf_file = self.directory / ("perf.data" if profile else "perf.csv")
        if profile:
            scope = sorted(set(cpus + self.case["forward_cpus"]))
            perf_argv = ["perf", "record", "-a", "-C", ",".join(map(str, scope)), "-e", "cycles",
                         "-F", "199", "-g", "--call-graph", "fp", "-o", str(perf_file),
                         "--", "sleep", str(self.args.seconds)]
        else:
            perf_argv = ["perf", "stat", "-a", "-x,", "-e", "cycles,instructions,duration_time,context-switches,cpu-migrations",
                         "-o", str(perf_file), "--", "sleep", str(self.args.seconds)]
        perf_start = time.monotonic_ns()
        perf = subprocess.run(perf_argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                              timeout=self.args.seconds + 30)
        perf_end = time.monotonic_ns()
        if perf.returncode:
            raise RuntimeError(f"perf measurement: {perf.stderr}")
        (self.directory / "perf-stderr.log").write_text(perf.stderr)
        after = self.snapshot(sampler)
        cpu_after = cpu_times()
        if sender.poll() is not None:
            raise RuntimeError("sender stopped during measurement")
        duration = (after["at_ns"] - before["at_ns"]) / 1e9
        deltas = {}
        for name in mapping:
            deltas[name] = {key: value - before["maps"][name][key] for key, value in after["maps"][name].items()}
        offered = deltas["tx"]["packets"]
        if offered <= 0:
            raise RuntimeError("no offered traffic")
        if deltas["tx"]["diff_errors"] or deltas["tx"]["checksum_errors"]:
            raise RuntimeError("XDPerf reported packet generation errors")
        windows = {name: (after["map_at_ns"][name] - before["map_at_ns"][name]) / 1e9 for name in mapping}
        rates = {name: deltas[name]["packets"] / windows[name] for name in mapping}
        received_rate = sum(rates[name] for name in mapping if name != "tx")
        perf_counters = {}
        perf_raw = "" if profile else perf_file.read_text()
        for line in perf_raw.splitlines():
            if not line or line.startswith("#"):
                continue
            fields = line.split(",")
            if len(fields) >= 3:
                try:
                    perf_counters[fields[2]] = float(fields[0])
                except ValueError:
                    perf_counters[fields[2]] = fields[0]
        return {**self.case, "seconds": duration, "map_seconds": windows, "offered_pps": rates["tx"],
                "delivered_pps": received_rate, "delivered_bytes_per_second": sum(deltas[n]["bytes"] / windows[n] for n in self.rx_maps),
                "loss_fraction": 1 - received_rate / (rates["tx"] * self.case["fanout"]),
                "per_receiver_pps": {n: rates[n] for n in self.rx_maps},
                "before": before, "after": after, "deltas": deltas, "cpu": cpu_delta(cpu_before, cpu_after),
                "perf": perf_counters, "perf_raw": perf_raw, "perf_command_seconds": (perf_end - perf_start) / 1e9,
                "perf_command": perf_argv, "profile": profile, "target_pps": getattr(self.args, "pps", 0),
                "flows": getattr(self.args, "flows", 64),
                "link_before_generator": self.link_before, "queue_before_generator": self.queue_before, "topology": self.topology,
                "generator_cpus": cpus, "command": list(map(str, argv))}

    def close(self):
        failures = []
        for process in reversed(self.processes):
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    try:
                        process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        failures.append(f"owned PID {process.pid} did not exit after SIGKILL")
        for log in self.logs:
            log.close()
        for namespace in reversed(self.namespaces):
            try:
                command("ip", "netns", "del", namespace)
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                failures.append(str(error))
        if failures:
            (self.directory / "cleanup-errors.json").write_text(json.dumps(failures, indent=2) + "\n")
            raise RuntimeError("benchmark cleanup failed: " + "; ".join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "bin/goxdp")
    parser.add_argument("--xdperf", type=Path, required=True)
    parser.add_argument("--plugins", type=Path, required=True)
    parser.add_argument("--counters", type=Path, default=ROOT / "bin/goxdp-perf-counters")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--frames", default="64,512,1514")
    parser.add_argument("--fanouts", default="1,2,4")
    parser.add_argument("--modes", default="broadcast,vxlan")
    parser.add_argument("--backends", default="xdp,tc")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--queues", type=int, default=4)
    parser.add_argument("--cpus", default="0,1,2,3")
    parser.add_argument("--cpu-redirect", action="store_true")
    forward = parser.add_mutually_exclusive_group()
    forward.add_argument("--forward-cpu", type=int, help="one forwarding CPU (default: 8)")
    forward.add_argument("--forward-cpus", type=lambda value: list(map(int, value.split(","))),
                         help="comma-separated forwarding CPUs")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=float, default=5)
    parser.add_argument("--warmup", type=float, default=2)
    parser.add_argument("--idle-seconds", type=float, default=2)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--pps", type=int, default=0, help="paced total input rate; 0 sends at saturation")
    parser.add_argument("--flows", type=int, default=64, help="number of UDP source ports, starting at 10000")
    parser.add_argument("--profile", action="store_true", help="sample stacks instead of perf stat; use a separate output directory")
    parser.add_argument("--seed", type=int, default=20261022)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run with sudo; the benchmark creates isolated namespaces")
    args.cpus = list(map(int, args.cpus.split(",")))
    if args.forward_cpus is None:
        args.forward_cpus = [8 if args.forward_cpu is None else args.forward_cpu]
    if not 0 < args.workers <= args.queues or len(args.cpus) < args.workers:
        parser.error("need 1 <= workers <= queues and enough CPU IDs")
    if not set(args.cpus).issubset(os.sched_getaffinity(0)):
        parser.error("generator CPUs must be available")
    if len(set(args.cpus)) != len(args.cpus):
        parser.error("generator CPU IDs must be unique")
    if args.cpu_redirect:
        if not args.forward_cpus or len(set(args.forward_cpus)) != len(args.forward_cpus):
            parser.error("forward CPU IDs must be nonempty and unique")
        if not set(args.forward_cpus).issubset(os.sched_getaffinity(0)) or set(args.forward_cpus) & set(args.cpus[:args.workers]):
            parser.error("forward CPUs must be available and separate from generator CPUs")
    if args.seconds <= 0 or args.warmup < 0 or args.idle_seconds < 0 or args.repeats < 1 or args.pps < 0:
        parser.error("invalid duration or repeat count")
    if not 1 <= args.flows <= 55536:
        parser.error("flows must be 1..55536 to fit UDP source ports starting at 10000")
    frames, fanouts = list(map(int, args.frames.split(","))), list(map(int, args.fanouts.split(",")))
    if any(not 64 <= n <= 1514 for n in frames) or any(not 1 <= n <= 63 for n in fanouts):
        parser.error("frames must be 64..1514 bytes; fanouts must be 1..63")
    if not set(args.modes.split(",")).issubset({"broadcast", "vxlan"}) or not set(args.backends.split(",")).issubset({"xdp", "tc"}):
        parser.error("invalid mode or backend")
    if args.cpu_redirect and args.modes != "vxlan":
        parser.error("CPU redirect comparison requires --modes vxlan")
    args.output.mkdir(parents=True, exist_ok=False)
    metadata = {"time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kernel": platform.uname()._asdict(),
                "lscpu": json_command("lscpu", "-J"), "args": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
                "binary_sha256": digest(args.binary), "xdperf_sha256": digest(args.xdperf),
                "counters_sha256": digest(args.counters), "runner_sha256": digest(Path(__file__)),
                "plugin_sha256": digest(args.plugins / "simpleudp.go.wasm"),
                "xdperf_build_info": command("env", "-u", "GOROOT", "go", "version", "-m", args.xdperf),
                "available_cpus": sorted(os.sched_getaffinity(0)),
                "goxdp_revision": command("git", "-C", ROOT, "rev-parse", "HEAD").strip(),
                "goxdp_status": command("git", "-C", ROOT, "status", "--short"),
                "measurement": "XDPerf TX processed counts are offered frames, not proof of DUT acceptance; receiver XDP maps count actual arrivals. CPU/perf are system-wide and include generator, forwarding, sinks, and unrelated activity."}
    if args.idle_seconds:
        idle_start, idle_cpu = time.monotonic(), cpu_times()
        time.sleep(args.idle_seconds)
        metadata["idle_baseline"] = {"seconds": time.monotonic() - idle_start,
                                     "cpu": cpu_delta(idle_cpu, cpu_times())}
    (args.output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    cases = []
    rng = random.Random(args.seed)
    for mode, size, fanout, repeat in itertools.product(args.modes.split(","), frames, fanouts, range(args.repeats)):
        backends = args.backends.split(",")
        rng.shuffle(backends)
        for backend in backends:
            cases.append({"mode": mode, "frame_size": size, "fanout": fanout, "repeat": repeat,
                          "backend": backend, "workers": args.workers, "queues": args.queues,
                          "cpu_redirect": args.cpu_redirect,
                          "forward_cpus": args.forward_cpus if args.cpu_redirect else []})
    results = []
    for index, case in enumerate(cases):
        directory = args.output / f"run-{index:03d}"
        directory.mkdir()
        trial = Trial(args, case, directory)
        print(f"[{index+1}/{len(cases)}] {case}", flush=True)
        try:
            result = trial.run()
            results.append(result)
            (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
            (args.output / "runs.json").write_text(json.dumps(results, indent=2) + "\n")
            print(f"offered={result['offered_pps']:.0f} pps delivered={result['delivered_pps']:.0f} pps sampled_deficit={result['loss_fraction']:+.5%}", flush=True)
        finally:
            trial.close()
    if "SUDO_UID" in os.environ:
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
        for path in [args.output, *args.output.rglob("*")]:
            os.chown(path, uid, gid)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    main()
