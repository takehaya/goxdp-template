#!/usr/bin/env python3
"""Summarize compare.py output and plot measured whole-pipeline throughput."""
import argparse
from collections import Counter
import csv
import itertools
import json
import math
import os
from pathlib import Path
from statistics import median

GROUP = ("mode", "frame_size", "fanout", "workers", "queues", "cpu_redirect", "backend")


def summarize(runs):
    if not runs:
        raise ValueError("runs.json contains no completed trials")
    if any(run.get("profile") for run in runs):
        raise ValueError("sampled profiles must stay separate from throughput summaries")
    if len({run.get("flows", 64) for run in runs}) != 1 or len({run.get("target_pps", 0) for run in runs}) != 1:
        raise ValueError("different flow counts or requested rates must be reported separately")
    cpu_sets = {tuple(run.get("forward_cpus", [])) for run in runs if run["cpu_redirect"]}
    if len(cpu_sets) > 1:
        raise ValueError("different forwarding CPU sets must be reported separately")
    forward_cpus = next(iter(cpu_sets), ())
    groups, seen = {}, set()
    for run in runs:
        key = tuple(run[field] for field in GROUP)
        trial = (*key, run["repeat"])
        if trial in seen:
            raise ValueError(f"duplicate trial: {trial}")
        seen.add(trial)
        if run["backend"] not in ("xdp", "tc"):
            raise ValueError(f"unknown backend: {run['backend']}")
        receivers = run["per_receiver_pps"]
        if set(receivers) != {f"rx{i}" for i in range(run["fanout"])}:
            raise ValueError(f"receiver count does not match fanout: {trial}")
        metrics = {"offered_pps": run["offered_pps"], "delivered_pps": run["delivered_pps"],
                   "signed_deficit_fraction": run["loss_fraction"],
                   **{f"{name}_pps": value for name, value in receivers.items()}}
        if "cpu" in run:
            host = run["cpu"]["cpu"]
            for metric in ("busy", "softirq", "steal"):
                metrics[f"host_{metric}_cores"] = host[f"{metric}_seconds"] / run["seconds"]
        if any(not math.isfinite(value) for value in metrics.values()):
            raise ValueError(f"non-finite measurement: {trial}")
        if metrics["offered_pps"] <= 0 or any(value < 0 for name, value in metrics.items()
                                             if name != "signed_deficit_fraction"):
            raise ValueError(f"invalid packet rate: {trial}")
        if not math.isclose(sum(receivers.values()), run["delivered_pps"], rel_tol=1e-9, abs_tol=1e-6):
            raise ValueError(f"receiver rates do not sum to delivered rate: {trial}")
        groups.setdefault(key, []).append(metrics)
    summaries = []
    for key, trials in sorted(groups.items()):
        row = dict(zip(GROUP, key))
        row["flows"] = runs[0].get("flows", 64)
        row["target_pps"] = runs[0].get("target_pps", 0)
        row["forward_cpus"] = ",".join(map(str, forward_cpus)) if row["cpu_redirect"] else ""
        row["repetitions"] = len(trials)
        for metric in trials[0]:
            values = [trial[metric] for trial in trials]
            row.update({f"{metric}_median": median(values), f"{metric}_min": min(values),
                        f"{metric}_max": max(values)})
        summaries.append(row)
    return summaries


def comparisons(summaries):
    paired = {}
    for row in summaries:
        key = tuple(row[field] for field in GROUP[:-1])
        paired.setdefault(key, {})[row["backend"]] = row
    for key, pair in sorted(paired.items()):
        if set(pair) == {"xdp", "tc"}:
            xdp, tc = pair["xdp"], pair["tc"]
            denominator = tc["delivered_pps_median"]
            yield key, xdp, tc, xdp["delivered_pps_median"] / denominator if denominator else None


def write_csv(directory, summaries):
    fields = list(dict.fromkeys(field for row in summaries for field in row))
    with (directory / "summary.csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(summaries)


def plot(directory, summaries):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    configurations = sorted({(row["mode"], row["workers"], row["queues"], row["cpu_redirect"])
                             for row in summaries})
    frames = sorted({row["frame_size"] for row in summaries})
    fig, axes = plt.subplots(len(configurations), len(frames), squeeze=False,
                             sharey="row", figsize=(4 * len(frames), 3.3 * len(configurations)), constrained_layout=True)
    for row_number, configuration in enumerate(configurations):
        mode, workers, queues, cpu_redirect = configuration
        for column, frame in enumerate(frames):
            ax = axes[row_number][column]
            for backend, color, marker in [("xdp", "#2166ac", "o"), ("tc", "#b35806", "s")]:
                rows = sorted((row for row in summaries if row["backend"] == backend and
                               row["frame_size"] == frame and
                               (row["mode"], row["workers"], row["queues"], row["cpu_redirect"]) == configuration),
                              key=lambda row: row["fanout"])
                if not rows:
                    continue
                values = [row["delivered_pps_median"] / 1e6 for row in rows]
                errors = [[(row["delivered_pps_median"] - row["delivered_pps_min"]) / 1e6 for row in rows],
                          [(row["delivered_pps_max"] - row["delivered_pps_median"]) / 1e6 for row in rows]]
                ax.errorbar([row["fanout"] for row in rows], values, yerr=errors, marker=marker,
                            color=color, capsize=4, label="XDP" if backend == "xdp" else "XDP + TC")
            targets = next((row["forward_cpus"] for row in summaries if row["cpu_redirect"]), "")
            placement = f"CPUMAP CPUs {targets}" if cpu_redirect and targets else f"CPUMAP {'on' if cpu_redirect else 'off'}"
            ax.set_title(f"{mode}, {frame}-byte input\n{workers} workers, {queues} queues\n{placement}")
            ax.set_xlabel("Fanout (receivers)")
            ax.set_ylabel("Aggregate received (Mpps)")
            ax.set_xticks(sorted({row["fanout"] for row in summaries}))
            ax.set_ylim(bottom=0)
            ax.grid(axis="y", alpha=0.25)
            if ax.lines:
                ax.legend()
    counts = sorted({row["repetitions"] for row in summaries})
    load = f"requested {summaries[0]['target_pps']} input pps" if summaries[0]["target_pps"] else "saturation"
    fig.suptitle(f"Whole-pipeline throughput, {load}, {summaries[0]['flows']} flows\nMedian [min, max]; repetitions: {', '.join(map(str, counts))}",
                 fontsize=12 if len(frames) == 1 else 15)
    fig.savefig(directory / "throughput.svg", bbox_inches="tight")
    fig.savefig(directory / "throughput.png", dpi=180, bbox_inches="tight")
    plt.close(fig)


def write_markdown(directory, environment, runs, summaries):
    args = environment["args"]
    targets = args.get("forward_cpus") or [args.get("forward_cpu", 8)]
    expected = int(args["repeats"])
    expected_keys = set(itertools.product(args["modes"].split(","), map(int, args["frames"].split(",")),
                                        map(int, args["fanouts"].split(",")), [args["workers"]], [args["queues"]],
                                        [args["cpu_redirect"]], args["backends"].split(",")))
    expected_trials = {(*key, repeat) for key in expected_keys for repeat in range(expected)}
    actual_trials = {(*(run[field] for field in GROUP), run["repeat"]) for run in runs}
    complete = actual_trials == expected_trials
    lscpu = {entry["field"].rstrip(":"): entry["data"] for entry in environment["lscpu"]["lscpu"]}
    methodology = os.path.relpath(Path(__file__).resolve().parents[2] / "docs/benchmarks.md", directory.resolve())
    lines = ["# XDP and TC benchmark results", "",
             "These measurements cover the generator, veth forwarding, and receiver XDP programs on one host.",
             "The XDP/TC ratio compares median aggregate received throughput for that whole pipeline; it does not isolate DUT cost.",
             "These sampled rates do not establish maximum loss-free capacity.", "",
             f"Recorded: {environment['time_utc']}.",
             f"Kernel: `{environment['kernel']['release']}`; CPU: {lscpu.get('Model name', 'unknown')}; "
             f"hypervisor: {lscpu.get('Hypervisor vendor', 'not reported')}.",
             f"Completed trials: {len(runs)}; expected repetitions per point: {expected}.",
             f"CPUMAP targets: {', '.join(map(str, targets)) if args['cpu_redirect'] else 'disabled'}.",
             f"UDP flows: {args.get('flows', 64)}; requested input PPS: {args.get('pps', 0)} (0 means unpaced).",
             f"Matrix status: {'complete' if complete else 'INCOMPLETE; missing or unexpected groups/repetitions must be resolved before comparison'}.",
             "Raw inputs and executable hashes are in [environment.json](environment.json) and [runs.json](runs.json).", "",
             f"See the [benchmark methodology]({methodology}) for the workload and interpretation of these measurements.", "",
             "![Median aggregate receiver throughput with observed minimum and maximum](throughput.svg)", "",
             "[PNG](throughput.png) | [CSV with all receiver rates](summary.csv)", "",
             "## Whole-pipeline comparison", "",
             "The ratio divides the XDP median by the TC median for the same configuration.",
             "Error bars show observed minimum and maximum, not confidence intervals.", "",
             "| Mode | Input bytes | Fanout | Workers/queues | CPUMAP | XDP Mpps | TC Mpps | XDP/TC | Repeats XDP/TC |",
             "| --- | ---: | ---: | --- | --- | ---: | ---: | ---: | --- |"]
    for key, xdp, tc, ratio in comparisons(summaries):
        mode, size, fanout, workers, queues, cpu_redirect = key
        ratio_text = f"{ratio:.3f}" if ratio is not None else "undefined"
        lines.append(f"| {mode} | {size} | {fanout} | {workers}/{queues} | {'on' if cpu_redirect else 'off'} | "
                     f"{xdp['delivered_pps_median']/1e6:.3f} | {tc['delivered_pps_median']/1e6:.3f} | {ratio_text} | "
                     f"{xdp['repetitions']}/{tc['repetitions']} |")
    lines += ["", "## Offered and received traffic", "",
              "Offered traffic is XDPerf's processed TX count; each receiver counts actual arrivals in its XDP map.",
              "The signed deficit is `1 - aggregate_received_pps / (offered_pps * fanout)`.",
              "Counter lookups are sequential and each rate uses its own sampling interval.",
              "Small positive or negative deficits can result from sampling skew and packets in flight; these values alone do not establish loss or duplication.",
              "Large positive deficits show a delivery shortfall at the observed offered load and must be reported alongside throughput.",
              "Exact frame copies and local UDP delivery are checked separately by the integration and scenario tests.", "",
              "| Mode | Bytes | Fanout | Workers/queues | CPUMAP | Backend | Offered Mpps median | Received Mpps median [min, max] | Signed deficit % median [min, max] |",
              "| --- | ---: | ---: | --- | --- | --- | ---: | --- | --- |"]
    for row in summaries:
        delivered = [row[f"delivered_pps_{stat}"] / 1e6 for stat in ("median", "min", "max")]
        deficit = [100 * row[f"signed_deficit_fraction_{stat}"] for stat in ("median", "min", "max")]
        lines.append(f"| {row['mode']} | {row['frame_size']} | {row['fanout']} | {row['workers']}/{row['queues']} | "
                     f"{'on' if row['cpu_redirect'] else 'off'} | {row['backend']} | {row['offered_pps_median']/1e6:.3f} | "
                     f"{delivered[0]:.3f} [{delivered[1]:.3f}, {delivered[2]:.3f}] | "
                     f"{deficit[0]:+.5f} [{deficit[1]:+.5f}, {deficit[2]:+.5f}] |")
    lines += ["", "## Receiver CPU placement", "",
              "Each CPU set contains the CPUs with positive packet deltas across the receivers in one trial.",
              "The count in parentheses is the number of trials with that set; only receiver counters contribute, and sender counters are excluded.",
              "These counters record receiver execution and do not by themselves identify forwarding CPU placement.", "",
              "| Mode | Bytes | Fanout | Backend | Active receiver CPU sets (trials) |",
              "| --- | ---: | ---: | --- | --- |"]
    for row in summaries:
        sets = Counter()
        for run in runs:
            if any(run[field] != row[field] for field in GROUP):
                continue
            active = {cpu for name in run["per_receiver_pps"]
                      for cpu, (after, before) in enumerate(zip(run["after"]["per_cpu_packets"][name],
                                                               run["before"]["per_cpu_packets"][name])) if after > before}
            sets[tuple(sorted(active))] += 1
        placement = "; ".join(f"`{','.join(map(str, cpus)) or 'none'}` ({count})" for cpus, count in sorted(sets.items()))
        lines.append(f"| {row['mode']} | {row['frame_size']} | {row['fanout']} | {row['backend']} | {placement} |")
    if all("host_busy_cores_median" in row for row in summaries):
        lines += ["", "## Whole-host CPU activity", "",
                  "Equivalent busy cores are CPU execution seconds divided by the counter-window duration.",
                  "One fully busy core corresponds to 1.0; idle, I/O wait, and steal time are excluded from execution time.",
                  "These system-wide observations include generation, forwarding, receivers, and unrelated activity; they do not isolate DUT CPU usage.",
                  "Softirq and steal columns use the same core-seconds-per-second scale.", "",
                  "| Mode | Bytes | Fanout | Backend | Busy cores median [min, max] | Softirq cores median | Steal cores median |",
                  "| --- | ---: | ---: | --- | --- | ---: | ---: |"]
        for row in summaries:
            busy = [row[f"host_busy_cores_{stat}"] for stat in ("median", "min", "max")]
            lines.append(f"| {row['mode']} | {row['frame_size']} | {row['fanout']} | {row['backend']} | "
                         f"{busy[0]:.3f} [{busy[1]:.3f}, {busy[2]:.3f}] | "
                         f"{row['host_softirq_cores_median']:.3f} | {row['host_steal_cores_median']:.3f} |")
        baseline = environment.get("idle_baseline")
        if baseline:
            busy = baseline["cpu"]["cpu"]["busy_seconds"] / baseline["seconds"]
            lines += ["", f"Before the matrix, the {baseline['seconds']:.3f}-second idle baseline averaged {busy:.3f} busy cores across the host.",
                      "This baseline is recorded for context and is not subtracted from trial measurements."]
    windows = [value for run in runs for value in run["map_seconds"].values()]
    spans = [(run[point]["end_ns"] - run[point]["at_ns"]) / 1e6
             for run in runs for point in ("before", "after")]
    perf_windows = [run["perf"]["duration_time"] / 1e9 for run in runs
                    if isinstance(run["perf"].get("duration_time"), (int, float))]
    lines += ["", "## Sampling and host activity", "",
              f"Per-map measurement intervals range from {min(windows):.6f} to {max(windows):.6f} seconds.",
              f"Reading all maps takes {min(spans):.3f} to {max(spans):.3f} ms per snapshot."]
    if perf_windows:
        lines.append(f"The perf event duration ranges from {min(perf_windows):.6f} to {max(perf_windows):.6f} seconds.")
    lines += ["Perf and map measurement windows differ; raw records preserve both intervals.",
              "System-wide perf and /proc/stat include generator, forwarding, receivers, and unrelated host activity.",
              "These counters cannot establish isolated forwarding cycles per packet on a shared host.",
              "Before/after per-CPU packet counters in runs.json show where the source and receivers processed packets.",
              "Veth results do not establish physical NIC throughput, latency, or maximum loss-free capacity.", ""]
    (directory / "report.md").write_text("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="compare.py output directory")
    args = parser.parse_args()
    environment = json.loads((args.directory / "environment.json").read_text())
    runs = json.loads((args.directory / "runs.json").read_text())
    summaries = summarize(runs)
    plot(args.directory, summaries)
    write_csv(args.directory, summaries)
    write_markdown(args.directory, environment, runs, summaries)
    print(args.directory / "report.md")


if __name__ == "__main__":
    main()
