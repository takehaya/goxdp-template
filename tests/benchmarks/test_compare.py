import unittest
from types import SimpleNamespace
from unittest.mock import patch

from compare import cpu_delta, generator_config, sender_command
from stages import cases


class CPUAccountingTest(unittest.TestCase):
    def test_steal_and_wait_are_not_cpu_execution(self):
        with patch("compare.os.sysconf", return_value=100):
            activity = cpu_delta({"cpu": [100] * 8},
                                 {"cpu": [110, 105, 120, 140, 107, 103, 104, 111]})["cpu"]
        self.assertAlmostEqual(activity["busy_seconds"], 0.42)
        self.assertAlmostEqual(activity["softirq_seconds"], 0.04)
        self.assertAlmostEqual(activity["steal_seconds"], 0.11)

    def test_paced_sender_has_finite_budget_and_no_infinite_flag(self):
        args = SimpleNamespace(xdperf="xdperf", plugins="plugins", cpus=[0, 1, 2, 3],
                               batch_size=1, warmup=2, seconds=5, pps=400000)
        command = sender_command(args, {"workers": 4}, "generator.json")
        self.assertNotIn("--infinite", command)
        self.assertNotIn("--count", command)
        self.assertEqual(command[command.index("--pps") + 1], "400000")
        self.assertEqual(command[command.index("--duration") + 1], "37s")
        args.pps = 0
        self.assertIn("--infinite", sender_command(args, {"workers": 4}, "generator.json"))

    def test_stage_matrix_keeps_profiles_separate_and_cpu_budgets_explicit(self):
        self.assertEqual(len(cases("saturation")), 24)
        self.assertEqual(len(cases("paced")), 12)
        self.assertEqual(len(cases("profile")), 6)
        for phase in ("saturation", "paced", "profile"):
            for case in cases(phase):
                self.assertEqual(case["cpu_redirect"], bool(case["forward_cpus"]))
                self.assertFalse(set(case["forward_cpus"]) & {0, 1, 2, 3})
                if case["mode"] == "broadcast":
                    self.assertFalse(case["cpu_redirect"])

    def test_flow_sweep_uses_inclusive_upper_port(self):
        args = SimpleNamespace(flows=4096)
        config = generator_config(args, {"frame_size": 64})
        self.assertEqual(config["src_port_sweep_start"], 10000)
        self.assertEqual(config["src_port_sweep_end"], 14095)
        self.assertEqual(config["payload_size"], 22)


if __name__ == "__main__":
    unittest.main()
