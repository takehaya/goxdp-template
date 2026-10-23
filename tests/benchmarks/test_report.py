"""Run with: python3 -m unittest discover -s tests/benchmarks -p 'test_*.py'."""
import copy
import unittest

import report


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.runs = []
        for backend, scale in [("xdp", 2), ("tc", 1)]:
            for repeat, value in enumerate([90, 110, 100]):
                self.runs.append({"mode": "vxlan", "frame_size": 64, "fanout": 2,
                                  "workers": 4, "queues": 4, "cpu_redirect": False,
                                  "backend": backend, "repeat": repeat,
                                  "offered_pps": value * scale, "delivered_pps": 2 * value * scale,
                                  "loss_fraction": (repeat - 1) * 0.001,
                                  "per_receiver_pps": {"rx0": value * scale, "rx1": value * scale}})

    def test_medians_receivers_signed_deficits_and_ratio(self):
        rows = report.summarize(self.runs)
        xdp = next(row for row in rows if row["backend"] == "xdp")
        self.assertEqual(xdp["repetitions"], 3)
        self.assertEqual(xdp["delivered_pps_median"], 400)
        self.assertEqual(xdp["rx0_pps_min"], 180)
        self.assertEqual(xdp["rx1_pps_max"], 220)
        self.assertEqual(xdp["signed_deficit_fraction_min"], -0.001)
        self.assertEqual(list(report.comparisons(rows))[0][3], 2)

    def test_separate_queue_and_cpu_configurations(self):
        other = copy.deepcopy(self.runs)
        for run in other:
            run["queues"] = 8
            run["cpu_redirect"] = True
        rows = report.summarize(self.runs + other)
        self.assertEqual(len(rows), 4)
        self.assertEqual(len(list(report.comparisons(rows))), 2)

    def test_rejects_duplicate_trials_and_inconsistent_receivers(self):
        with self.assertRaisesRegex(ValueError, "duplicate trial"):
            report.summarize(self.runs + [self.runs[0]])
        self.runs[0]["per_receiver_pps"]["rx0"] += 1
        with self.assertRaisesRegex(ValueError, "do not sum"):
            report.summarize(self.runs)

    def test_zero_delivery_ratio_is_undefined(self):
        for run in self.runs:
            if run["backend"] == "tc":
                run["delivered_pps"] = 0
                run["per_receiver_pps"] = {"rx0": 0, "rx1": 0}
        self.assertIsNone(list(report.comparisons(report.summarize(self.runs)))[0][3])

    def test_forwarding_cpu_sets_are_recorded_and_not_merged(self):
        for run in self.runs:
            run["cpu_redirect"] = True
            run["forward_cpus"] = [8, 9, 10, 11]
        rows = report.summarize(self.runs)
        self.assertTrue(all(row["forward_cpus"] == "8,9,10,11" for row in rows))
        self.runs[0]["forward_cpus"] = [8]
        with self.assertRaisesRegex(ValueError, "different forwarding CPU sets"):
            report.summarize(self.runs)

    def test_profiles_and_mixed_workloads_cannot_enter_summary(self):
        self.runs[0]["profile"] = True
        with self.assertRaisesRegex(ValueError, "sampled profiles"):
            report.summarize(self.runs)
        self.runs[0]["profile"] = False
        self.runs[0]["target_pps"] = 400000
        with self.assertRaisesRegex(ValueError, "different flow counts or requested rates"):
            report.summarize(self.runs)
        self.runs[0]["target_pps"] = 0
        self.runs[0]["flows"] = 4096
        with self.assertRaisesRegex(ValueError, "different flow counts or requested rates"):
            report.summarize(self.runs)


if __name__ == "__main__":
    unittest.main()
