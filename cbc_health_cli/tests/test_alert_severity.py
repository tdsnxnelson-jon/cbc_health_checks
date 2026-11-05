import json
import tempfile
import unittest
from pathlib import Path

from pptx import Presentation

from cbc_health_cli.checks import summarize_alerts
from cbc_health_cli.reporting import write_technical_pptx


class AlertSeverityTests(unittest.TestCase):
    def alert_summary(self):
        alerts = [
            {"type": "CB_ANALYTICS", "device_policy": policy, "reason_code": "category:rule", "severity": severity}
            for policy, severity in (("Policy A", 3), ("Policy A", 10), ("Policy B", 5))
        ]
        alerts += [
            {"type": "WATCHLIST", "reason": 'Matched report "Report A"', "severity": severity}
            for severity in (9, 1, None)
        ]
        alerts += [
            {"type": "WATCHLIST", "report_name": "Report B", "severity": "unknown"},
            {"type": "WATCHLIST", "report_name": "Report C", "severity": 7},
        ]
        return summarize_alerts(
            alerts,
            policy_rule_config_names={
                ("1", "rule", "category"): "Block execution",
                ("2", "rule", "category"): "Block execution",
            },
            policy_ids_by_name={"policy a": "1", "policy b": "2"},
        )

    def test_ranges_are_numeric_grouped_and_do_not_change_counts(self):
        summary = self.alert_summary()
        self.assertEqual(summary["top_cb_analytics_policy_rule_blocks"], [
            {"policy": "Policy A", "rule_block": "Block execution", "severity_range": "3-10", "count": 2},
            {"policy": "Policy B", "rule_block": "Block execution", "severity_range": "5", "count": 1},
        ])
        self.assertEqual(summary["top_watchlist_reports"], {"Report A": 3, "Report B": 1, "Report C": 1})
        self.assertEqual(summary["top_watchlist_report_severity_ranges"], {
            "Report A": "1-9", "Report B": "n/a", "Report C": "7",
        })

    def test_repeated_single_severity_is_not_a_range(self):
        alerts = [
            {"type": alert_type, "device_policy": "Policy A", "reason_code": "category:rule",
             "report_name": "Report A", "severity": severity}
            for alert_type in ("CB_ANALYTICS", "WATCHLIST")
            for severity in (8, "8", 8)
        ]
        summary = summarize_alerts(alerts)
        self.assertEqual(summary["top_cb_analytics_policy_rule_blocks"][0]["severity_range"], "8")
        self.assertEqual(summary["top_watchlist_report_severity_ranges"]["Report A"], "8")

    def test_deck_columns_ranges_and_legacy_summaries(self):
        alerts = self.alert_summary()
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            for legacy in (False, True):
                if legacy:
                    del alerts["top_watchlist_report_severity_ranges"]
                    for row in alerts["top_cb_analytics_policy_rule_blocks"]:
                        del row["severity_range"]
                (run_dir / "summary.json").write_text(json.dumps({
                    "checks": {"alerts": {"status": "ok", "summary": alerts}},
                }), encoding="utf-8")
                deck = Presentation(str(write_technical_pptx(run_dir)))
                matching = []
                for slide in deck.slides:
                    for shape in slide.shapes:
                        if not shape.has_table:
                            continue
                        table = shape.table
                        headers = [cell.text for cell in table.rows[0].cells]
                        if "Severity" not in headers:
                            continue
                        matching.append(headers)
                        severity_column = headers.index("Severity")
                        expected = "n/a" if legacy else ("3-10" if "Policy" in headers else "1-9")
                        self.assertEqual(table.cell(1, severity_column).text, expected)
                        if not legacy:
                            if "Policy" in headers:
                                self.assertEqual(table.cell(2, severity_column).text, "5")
                            else:
                                self.assertEqual(table.cell(3, severity_column).text, "7")
                        self.assertLessEqual(shape.left + shape.width, deck.slide_width)
                        self.assertLessEqual(shape.top + shape.height, deck.slide_height)
                self.assertEqual(matching, [
                    ["Policy", "Rule Block", "Severity", "Count"],
                    ["Alert / Report", "Severity", "Count"],
                ])


if __name__ == "__main__":
    unittest.main()
