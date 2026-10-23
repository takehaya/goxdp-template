#!/usr/bin/env python3
"""Summarize stage trials and plot throughput, CPU use, and flow-count controls."""
import argparse
import csv
import itertools
import json
from pathlib import Path
import statistics

import report


def summarize(runs):
    def key(run):
        return (*(run[field] for field in report.GROUP), tuple(run["forward_cpus"]))

    rows = []
    for _, group in itertools.groupby(sorted(runs, key=key), key=key):
        group = list(group)
        assert not any(run.get("profile") for run in group), "profiles must stay separate"
        assert len({run.get("flows", 64) for run in group}) == 1
        assert len({run.get("target_pps", 0) for run in group}) == 1
        row = report.summarize(group)[0]
        row["flows"] = group[0].get("flows", 64)
        row["target_pps"] = group[0].get("target_pps", 0)
        row["cpu_budget"] = len(set(group[0]["generator_cpus"] + group[0]["forward_cpus"]))
        for label, cpu_key in (("source", "generator_cpus"), ("forward", "forward_cpus")):
            busy = [sum(run["cpu"][f"cpu{cpu}"]["busy_seconds"] for cpu in run[cpu_key]) / run["seconds"]
                    for run in group]
            row[f"{label}_busy_cores_median"] = statistics.median(busy)
        efficiency = []
        for run in group:
            cpus = set(run["generator_cpus"] + run["forward_cpus"])
            busy = sum(run["cpu"][f"cpu{cpu}"]["busy_seconds"] for cpu in cpus) / run["seconds"]
            efficiency.append(busy * 1e6 / run["delivered_pps"])
        row["assigned_core_seconds_per_million_outputs_median"] = statistics.median(efficiency)
        rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    rows = []
    for phase in ("saturation", "paced", "flows-4096-direct", "flows-4096-four"):
        runs = json.loads((args.directory / phase / "runs.json").read_text())
        rows.extend({"phase": phase, **row} for row in summarize(runs))
    with (args.directory / "summary.csv").open("w") as output:
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"font.size": 10, "svg.fonttype": "none"})
    fig, axes = plt.subplots(2, 2, figsize=(12, 8.5))
    colors = ["#6b8eaa", "#177c78", "#d19535", "#7160a8"]
    stages = [("broadcast", ""), ("vxlan", ""), ("vxlan", "8"), ("vxlan", "8,9,10,11")]
    labels = ["Devmap\n4 CPUs", "VXLAN direct\n4 CPUs", "CPUMAP 1\n5 CPUs", "CPUMAP 4\n8 CPUs"]

    def select(phase, size):
        candidates = [row for row in rows if row["phase"] == phase and row["frame_size"] == size]
        return [next(row for row in candidates if (row["mode"], row["forward_cpus"]) == stage) for stage in stages]

    def throughput(ax, selected, names, palette):
        values = [row["delivered_pps_median"] / 1e6 for row in selected]
        errors = [[(row["delivered_pps_median"] - row["delivered_pps_min"]) / 1e6 for row in selected],
                  [(row["delivered_pps_max"] - row["delivered_pps_median"]) / 1e6 for row in selected]]
        ax.bar(range(len(values)), values, color=palette, yerr=errors, capsize=4, width=.65)
        for x, (value, row) in enumerate(zip(values, selected)):
            ax.text(x, max(value, row["delivered_pps_max"] / 1e6) + .09,
                    f"{value:.2f}\n{row['signed_deficit_fraction_median'] * 100:.1f}% deficit", ha="center", fontsize=9)
        ax.set_xticks(range(len(names)), names)
        ax.set_ylabel("Aggregate received Mpps (two outputs)")
        ax.set_ylim(0, max(row["delivered_pps_max"] / 1e6 for row in selected) * 1.32)
        ax.grid(axis="y", alpha=.2)
        ax.set_axisbelow(True)

    for ax, size in zip(axes[0], (64, 1514)):
        throughput(ax, select("saturation", size), labels, colors)
        ax.set_title(f"Unpaced input, {size}-byte frames, 64 flows")

    paced = select("paced", 64)
    ax = axes[1, 0]
    source = [row["source_busy_cores_median"] for row in paced]
    forward = [row["forward_busy_cores_median"] for row in paced]
    ax.bar(range(4), source, color="#438eaa", label="CPUs 0-3 (includes generator)")
    ax.bar(range(4), forward, bottom=source, color="#b294c2", label="Configured CPUMAP CPUs")
    for x, row in enumerate(paced):
        ax.text(x, source[x] + forward[x] + .08,
                f"{row['delivered_pps_median'] / 1e6:.2f} Mpps\n{row['signed_deficit_fraction_median'] * 100:.1f}% deficit",
                ha="center", fontsize=9)
    ax.set_xticks(range(4), labels)
    ax.set_ylim(0, max(a + b for a, b in zip(source, forward)) * 1.5)
    ax.set_ylabel("Busy CPU seconds / second on assigned CPUs")
    ax.set_title("Requested input 0.4 Mpps, 64-byte frames")
    ax.legend(loc="upper left", fontsize=8)

    control = [select("saturation", 64)[1], select("saturation", 64)[3]]
    for phase in ("flows-4096-direct", "flows-4096-four"):
        control.append(next(row for row in rows if row["phase"] == phase))
    throughput(axes[1, 1], control, ["Direct\n64 flows", "CPUMAP 4\n64 flows", "Direct\n4096 flows", "CPUMAP 4\n4096 flows"],
               [colors[1], colors[3], colors[1], colors[3]])
    axes[1, 1].set_title("Flow-count control, 64-byte frames")
    fig.suptitle("XDP replication stages on four-queue veth links", fontsize=15)
    fig.text(.5, .015, "Medians and observed min-max of 3 trials. Shared KVM host; generator and receivers included.\n"
             "Paced replay arrives in nominal 100 ms bursts. Profiles are excluded from these plots.", ha="center", fontsize=9)
    fig.tight_layout(rect=[0, .065, 1, .95], h_pad=2)
    for suffix in ("svg", "png"):
        fig.savefig(args.directory / f"stages.{suffix}", dpi=170)


if __name__ == "__main__":
    main()
