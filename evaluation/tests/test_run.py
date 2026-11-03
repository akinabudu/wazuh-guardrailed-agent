"""The harness runs each scenario step on the host the committed corpus names."""

import sys
import unittest
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

import run  # noqa: E402


class StepHostTest(unittest.TestCase):
    def test_on_key_parsed_as_yaml_boolean_still_selects_the_attacker(self):
        step = yaml.safe_load("on: attacker\ncmd: true\n")
        self.assertIn(True, step)          # what PyYAML actually returns
        self.assertEqual(run.step_host(step), "attacker")

    def test_default_is_the_endpoint(self):
        self.assertEqual(run.step_host({"cmd": "true"}), "endpoint")

    def test_unknown_host_is_refused(self):
        with self.assertRaises(ValueError):
            run.step_host({True: "elsewhere", "cmd": "true"})

    def test_committed_corpus_attacker_steps(self):
        corpus = yaml.safe_load((HERE / "scenarios.yaml").read_text(encoding="utf8"))
        on_attacker = sorted(
            sc["id"].split("-")[0] for sc in corpus["scenarios"]
            if any(run.step_host(st) == "attacker"
                   for st in sc.get("steps", []) if "atomic" not in st))
        self.assertEqual(on_attacker, ["A01", "A02", "A03", "A04", "A05", "B03", "B04"])


if __name__ == "__main__":
    unittest.main()
