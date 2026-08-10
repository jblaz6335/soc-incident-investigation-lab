from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc_lab.analyzer import analyze, build_result, load_events, render_markdown
from soc_lab.detections import detect_suspicious_outbound, run_detections
from soc_lab.evtx_loader import parse_event_xml
from soc_lab.models import SecurityEvent
from soc_lab.reporting import render_html


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
            {"SOC-AUTH-001", "SOC-EXEC-001", "SOC-NET-001", "SOC-DATA-001", "SOC-DATA-002"},
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
        self.assertEqual(result["finding_count"], 5)
        self.assertEqual(result["risk_score"], 100)
        self.assertTrue(result["attack_chain_complete"])
        self.assertEqual(result["confidence"], "high")
        self.assertGreaterEqual(len(result["mitre_attack"]), 7)

    def test_invalid_event_reports_line_number(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            bad_path = Path(temp_dir) / "bad.jsonl"
            bad_path.write_text('{"event_id": 4625}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 1"):
                load_events(bad_path)

    def test_unsupported_input_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unsupported input format"):
            load_events(ROOT / "data" / "sample.txt")

    def test_internal_powershell_connection_is_not_flagged(self) -> None:
        event = SecurityEvent.from_mapping(
            {
                "timestamp": "2026-07-15T09:10:00Z",
                "event_id": 3,
                "channel": "Sysmon",
                "host": "WS-FIN-07",
                "image": "powershell.exe",
                "destination_ip": "10.20.30.9",
                "destination_port": 443,
            }
        )
        self.assertEqual(detect_suspicious_outbound([event]), [])

    def test_evtx_xml_normalization(self) -> None:
        xml_text = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID>
          <TimeCreated SystemTime="2026-07-15T09:00:11.0000000Z"/><EventRecordID>42</EventRecordID>
          <Channel>Security</Channel><Computer>WS-FIN-07</Computer></System>
          <EventData><Data Name="TargetUserName">j.smith</Data><Data Name="IpAddress">203.0.113.77</Data></EventData>
        </Event>"""
        event = parse_event_xml(xml_text)
        self.assertEqual(event.event_id, "4625")
        self.assertEqual(event.outcome, "failure")
        self.assertEqual(event.username, "j.smith")
        self.assertEqual(event.source_ip, "203.0.113.77")

    def test_html_dashboard_contains_case_and_filter_controls(self) -> None:
        dashboard = render_html(analyze(self.events_path))
        self.assertIn("Windows Account Compromise Investigation", dashboard)
        self.assertIn('data-filter="critical"', dashboard)
        self.assertIn("SOC-DATA-002", dashboard)
        self.assertIn("window.socCase", dashboard)
        match = re.search(
            r'<script id="case-data" type="application/json">(.*?)</script>',
            dashboard,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        embedded_case = json.loads(match.group(1))
        self.assertEqual(embedded_case["case_id"], "SOC-LAB-2026-001")

    def test_single_signal_requires_review_instead_of_auto_confirmation(self) -> None:
        one_event = [
            SecurityEvent.from_mapping(
                {
                    "timestamp": "2026-07-15T09:00:00Z",
                    "event_id": 4104,
                    "channel": "PowerShell",
                    "host": "WS-TEST-01",
                    "username": "analyst",
                    "image": "powershell.exe",
                    "command_line": "powershell.exe -EncodedCommand ZABlAG0AbwA=",
                }
            )
        ]
        partial = build_result(one_event, run_detections(one_event))
        self.assertEqual(partial["classification"], "requires_review")
        self.assertFalse(partial["attack_chain_complete"])

    def test_archive_staging_is_detected(self) -> None:
        finding = next(item for item in self.findings if item.rule_id == "SOC-DATA-002")
        self.assertIn("client_list_Q3.zip", " ".join(finding.evidence))
        self.assertIn("T1560.001", finding.mitre_attack[0])

    def test_sigma_rules_have_required_structure(self) -> None:
        rule_paths = sorted((ROOT / "detections" / "sigma").glob("*.yml"))
        self.assertEqual(len(rule_paths), 4)
        for rule_path in rule_paths:
            rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
            with self.subTest(rule=rule_path.name):
                for key in ("title", "id", "status", "description", "logsource", "detection", "level", "tags"):
                    self.assertIn(key, rule)
                self.assertIn("condition", rule["detection"])


if __name__ == "__main__":
    unittest.main()
