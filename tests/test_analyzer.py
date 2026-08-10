from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc_lab.analyzer import analyze, load_events, render_markdown
from soc_lab.detections import run_detections


class AnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.events_path = ROOT / "data" / "sample_events.jsonl"
        cls.events = load_events(cls.events_path)
        cls.findings = run_detections(cls.events)

    def test_sample_produces_expected_detection_chain(self) -> None:
        rule_ids = {finding.rule_id for finding in self.findings}
        self.assertEqual(
            rule_ids,
            {"SOC-AUTH-001", "SOC-EXEC-001", "SOC-NET-001", "SOC-DATA-001"},
        )

    def test_brute_force_is_correlated_to_same_source_user_and_host(self) -> None:
        finding = next(item for item in self.findings if item.rule_id == "SOC-AUTH-001")
        self.assertEqual(finding.severity, "critical")
        self.assertIn("6 failed logons", finding.description)
        self.assertTrue(any("203.0.113.77" in item for item in finding.evidence))

    def test_benign_process_does_not_trigger(self) -> None:
        titles = " ".join(finding.title for finding in self.findings).lower()
        self.assertNotIn("notepad", titles)

    def test_result_is_serializable_and_documented(self) -> None:
        result = analyze(self.events_path)
        serialized = json.dumps(result)
        markdown = render_markdown(result)
        self.assertIn("true_positive", serialized)
        self.assertIn("# Automated SOC Findings", markdown)
        self.assertEqual(result["finding_count"], 4)

    def test_invalid_event_reports_line_number(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            bad_path = Path(temp_dir) / "bad.jsonl"
            bad_path.write_text('{"event_id": 4625}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 1"):
                load_events(bad_path)


if __name__ == "__main__":
    unittest.main()

