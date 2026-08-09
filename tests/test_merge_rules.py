import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "merge_rules.py"
SPEC = importlib.util.spec_from_file_location("merge_rules", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ParseRuleTests(unittest.TestCase):
    def test_parses_supported_domain_formats(self):
        cases = {
            "||Ads.Example.COM^": ("domain", "ads.example.com"),
            "0.0.0.0 tracker.example.com": ("domain", "tracker.example.com"),
            "127.0.0.1 metric.example.com # comment": ("domain", "metric.example.com"),
            "address=/pixel.example.com/": ("domain", "pixel.example.com"),
            "plain.example.com": ("domain", "plain.example.com"),
        }
        for rule, expected in cases.items():
            with self.subTest(rule=rule):
                self.assertEqual(MODULE.parse_rule(rule), expected)

    def test_ignores_comments_allowlists_ips_and_local_domains(self):
        for rule in [
            "! comment",
            "# comment",
            "@@||allowed.example.com^",
            "127.0.0.1",
            "localhost",
            "printer.local",
        ]:
            with self.subTest(rule=rule):
                self.assertIsNone(MODULE.parse_rule(rule))

    def test_keeps_advanced_rules_without_lossy_rewrite(self):
        rule = "||example.com/path$important"
        self.assertEqual(MODULE.parse_rule(rule), ("raw", rule))


class CollapseTests(unittest.TestCase):
    def test_parent_rule_removes_subdomains(self):
        result = MODULE.collapse_domains(
            {"example.com", "ads.example.com", "deep.ads.example.com", "other.net"}
        )
        self.assertEqual(result, ["example.com", "other.net"])

    def test_sibling_domains_are_preserved_without_parent(self):
        result = MODULE.collapse_domains({"ads.example.com", "track.example.com"})
        self.assertEqual(result, ["ads.example.com", "track.example.com"])


class SafetyTests(unittest.TestCase):
    def test_rejects_abnormally_small_output(self):
        source = MODULE.Source("fixture", "https://example.invalid/list")
        with mock.patch.object(MODULE, "MIN_RULES", 2):
            with self.assertRaisesRegex(RuntimeError, "refusing to publish"):
                MODULE.merge([(source, b"||only.example.com^\n")])

    def test_rejects_source_without_usable_rules(self):
        source = MODULE.Source("fixture", "https://example.invalid/list")
        with self.assertRaisesRegex(RuntimeError, "no usable rules"):
            MODULE.merge([(source, b"! comments only\n# nothing\n")])


if __name__ == "__main__":
    unittest.main()
