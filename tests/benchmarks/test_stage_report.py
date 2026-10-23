import copy
import unittest

import stage_report


class StageReportTest(unittest.TestCase):
    def setUp(self):
        self.runs = [dict(mode="vxlan", frame_size=64, backend="xdp", forward_cpus=[],
                          cpu_redirect=False, workers=1, queues=1, fanout=2, repeat=repeat,
                          generator_cpus=[0], seconds=5, offered_pps=200, delivered_pps=400,
                          loss_fraction=0, per_receiver_pps={"rx0": 200, "rx1": 200},
                          cpu={"cpu": {"busy_seconds": 60, "softirq_seconds": 0, "steal_seconds": 0},
                               "cpu0": {"busy_seconds": 5}, "cpu8": {"busy_seconds": 5},
                               "cpu31": {"busy_seconds": 50}})
                     for repeat in range(3)]

    def test_counts_only_assigned_cpus_and_separates_cpu_budgets(self):
        remote = copy.deepcopy(self.runs)
        for run in remote:
            run.update(cpu_redirect=True, forward_cpus=[8])
        rows = stage_report.summarize(self.runs + remote)
        self.assertEqual([row["cpu_budget"] for row in rows], [1, 2])
        self.assertEqual([row["source_busy_cores_median"] for row in rows], [1, 1])
        self.assertEqual([row["forward_busy_cores_median"] for row in rows], [0, 1])
        self.assertEqual([row["assigned_core_seconds_per_million_outputs_median"] for row in rows], [2500, 5000])

    def test_profiles_cannot_enter_throughput_summary(self):
        self.runs[0]["profile"] = True
        with self.assertRaisesRegex(AssertionError, "profiles must stay separate"):
            stage_report.summarize(self.runs)


if __name__ == "__main__":
    unittest.main()
