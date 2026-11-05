import copy
import json
import tempfile
import unittest
from pathlib import Path

from pptx import Presentation
from pptx.util import Inches

from cbc_health_cli.checks import (
    prioritized_recommendations,
    summarize_core_prevention_settings,
    summarize_policy_efficacy,
    summarize_policy_posture,
    summarize_policy_tuning_analysis,
)
from cbc_health_cli.reporting import _paginate_table_to_slides, write_executive_pptx, write_technical_pptx


def policy_data(policy_id="1", paths=5, assigned=10):
    policies = [{"id": policy_id, "name": f"Policy {policy_id}", "num_devices": assigned}]
    core = [{
        "policy_id": policy_id, "policy_name": f"Policy {policy_id}", "name": "Prevention",
        "category": "core_prevention",
        "parameters": {
            "WindowsAssignmentMode": "BLOCK",
            "LinuxAssignmentMode": "BLOCK",
            "MacAssignmentMode": "BLOCK",
        },
    }]
    rules = []
    for reputation in (
        "KNOWN_MALWARE", "COMPANY_BLACK_LIST", "RESOLVING", "PUP", "SUSPECT_MALWARE", "ADAPTIVE_WHITE_LIST",
    ):
        for operation in ("RUN", "RANSOM", "MEMORY_SCRAPE", "EXECUTE_CODE_FROM_MEMORY", "NETWORK", "UNTRUSTED_PROCESS"):
            rules.append({
                "policy_id": policy_id, "policy_name": f"Policy {policy_id}", "action": "TERMINATE",
                "operation": operation, "application": {"type": "REPUTATION", "value": reputation},
            })
    rules.extend({
        "policy_id": policy_id, "action": "DENY", "operation": "RUN",
        "application": {"type": "NAME_PATH", "value": f"c:\\example\\app{index}.exe"},
    } for index in range(paths))
    return policies, core, rules


def assessment(policies, core, rules, ngav=True):
    summary = {"customer_name": "Synthetic Test", "tenant_key": "test", "checks": {}, "errors": []}
    for name, result in (
        ("policy_posture", summarize_policy_posture(policies, rules, ngav_enabled=ngav)),
        ("core_prevention_settings", summarize_core_prevention_settings(core, rules, policies)),
        ("policy_efficacy", summarize_policy_efficacy(policies, rules, core, [])),
    ):
        summary["checks"][name] = {"status": "ok", "summary": result}
    tuning = summarize_policy_tuning_analysis(summary, policies)
    summary["checks"]["policy_tuning_analysis"] = {"status": "ok", "summary": tuning}
    summary["recommendations"] = prioritized_recommendations(summary)
    return summary, tuning


class PolicyEnforcementTests(unittest.TestCase):
    def test_recommendation_appendix_paginates_wrapped_text_without_loss(self):
        deck = Presentation()
        deck.slide_width = Inches(13.333)
        deck.slide_height = Inches(7.5)
        rows = [
            ["P1", "Policy coverage", "Preserve every recommendation word. " * 90,
             "Evidence with explicit lines.\n" * 50],
            ["P2", "Alerts", "Review alert volume. " * 30, "All evidence is retained."],
        ]
        pages = _paginate_table_to_slides(
            deck, rows, ["Priority", "Area", "Recommendation", "Evidence"], "Complete Recommendations",
        )
        self.assertGreater(pages, 1)
        actual = ["", "", "", ""]
        for index, slide in enumerate(deck.slides, start=1):
            self.assertTrue(any(
                shape.has_text_frame and shape.text == f"Complete Recommendations (Page {index}/{pages})"
                for shape in slide.shapes
            ))
            for shape in slide.shapes:
                if not shape.has_table:
                    continue
                self.assertLessEqual(shape.top + shape.height, Inches(7.1))
                self.assertLessEqual(shape.left + shape.width, deck.slide_width)
                for row in list(shape.table.rows)[1:]:
                    for column, cell in enumerate(row.cells):
                        actual[column] += cell.text
        self.assertEqual(actual, ["".join(row[column] for row in rows) for column in range(4)])

    def test_complete_policy_is_best(self):
        _, tuning = assessment(*policy_data())
        self.assertEqual(tuning["current_tier"], "best")
        self.assertEqual(tuning["score_0_100"], 100)
        row = tuning["policy_maturity_action_plan_all"][0]
        self.assertEqual(row["core_prevention_alert_and_block"], 3)
        self.assertEqual(len(row["blocking_isolation_rule_counts"]), 5)
        self.assertEqual(row["file_path_rules"], 5)

    def test_each_required_category_needs_an_active_enforcing_rule(self):
        for reputation in ("KNOWN_MALWARE", "COMPANY_BLACK_LIST", "RESOLVING", "PUP", "SUSPECT_MALWARE"):
            for modification in ({"enabled": False}, {"test": True}, {"action": "ALLOW"}, {"action": "ALERT"}):
                with self.subTest(reputation=reputation, modification=modification):
                    policies, core, rules = policy_data()
                    for rule in rules:
                        if rule["application"]["value"] == reputation:
                            rule.update(modification)
                    summary, tuning = assessment(policies, core, rules)
                    row = tuning["policy_maturity_action_plan_all"][0]
                    self.assertEqual(row["current_tier"], "weak")
                    self.assertEqual(len(row["missing_required_controls"]), 1)
                    if reputation in {"KNOWN_MALWARE", "COMPANY_BLACK_LIST"}:
                        self.assertEqual(row["severity"], "critical")
                        self.assertLessEqual(row["enforcement_score_0_100"], 39)
                        self.assertLessEqual(tuning["score_0_100"], 39)
                        self.assertTrue(any(
                            rec["priority"] == "P1" and "CRITICAL" in rec["recommendation"]
                            for rec in summary["recommendations"]
                        ))
                    else:
                        self.assertGreaterEqual(row["enforcement_score_0_100"], 80)

    def test_platform_modes_are_separate_and_standard_rules_do_not_mask_alert(self):
        policies, core, rules = policy_data()
        core[0]["action"] = "BLOCK"
        core[0]["parameters"].update({
            "WindowsAssignmentMode": "Alert and Block", "LinuxAssignmentMode": "Alert", "MacAssignmentMode": "REPORT",
        })
        _, tuning = assessment(policies, core, rules)
        row = tuning["policy_maturity_action_plan_all"][0]
        self.assertEqual(row["core_prevention_alert"], 2)
        self.assertEqual(row["core_prevention_alert_and_block"], 1)
        self.assertEqual(row["current_tier"], "weak")
        self.assertLess(row["enforcement_score_0_100"], 100)
        self.assertTrue(all(count > 0 for count in row["blocking_isolation_rule_counts"].values()))

    def test_disabled_or_missing_core_is_not_inferred_from_standard_rules(self):
        policies, core, rules = policy_data()
        for configs in ([], [dict(core[0], enabled=False)]):
            with self.subTest(configs=configs):
                _, tuning = assessment(policies, configs, rules)
                self.assertEqual(tuning["current_tier"], "weak")
                row = tuning["policy_maturity_action_plan_all"][0]
                self.assertEqual(row["core_prevention_alert_and_block"], 0)
                self.assertEqual(row["enforcement_score_0_100"], 80)

    def test_core_named_known_malware_cannot_satisfy_blocking_isolation(self):
        policies, core, _ = policy_data()
        core[0]["name"] = "Known malware"
        result = summarize_core_prevention_settings(core, [], policies)
        self.assertEqual(result["policy_mode_breakdown"][0]["blocking_isolation_rule_counts"]["known_malware"], 0)

    def test_exactly_one_enforcing_rule_satisfies_each_category(self):
        policies, core, rules = policy_data()
        rules = [rule for rule in rules if rule["operation"] == "RUN"]
        result = summarize_core_prevention_settings(core, rules, policies)
        row = result["policy_mode_breakdown"][0]
        self.assertEqual(list(row["blocking_isolation_rule_counts"].values()), [1, 1, 1, 1, 1])
        self.assertEqual(row["missing_required_controls"], [])
        self.assertEqual(row["missing_critical_controls"], [])

    def test_path_rules_are_per_policy_and_zero_is_weak(self):
        first = policy_data("1", paths=0)
        second = policy_data("2", paths=10)
        policies, core, rules = [first[index] + second[index] for index in range(3)]
        _, tuning = assessment(policies, core, rules)
        rows = {row["policy_id"]: row for row in tuning["policy_maturity_action_plan_all"]}
        self.assertEqual(rows["1"]["current_tier"], "weak")
        self.assertLessEqual(rows["1"]["enforcement_score_0_100"], 59)
        self.assertEqual(rows["1"]["file_path_rules"], 0)
        self.assertEqual(rows["2"]["current_tier"], "best")
        self.assertEqual(tuning["current_tier"], "weak")
        self.assertFalse(tuning["gates"]["good"]["pass"])

    def test_disabled_paths_do_not_satisfy_gate(self):
        policies, core, rules = policy_data()
        for rule in rules:
            if rule["application"]["type"] == "NAME_PATH":
                rule["enabled"] = False
        _, tuning = assessment(policies, core, rules)
        self.assertEqual(tuning["policy_maturity_action_plan_all"][0]["file_path_rules"], 0)
        self.assertEqual(tuning["current_tier"], "weak")

    def test_one_path_is_not_best(self):
        _, tuning = assessment(*policy_data(paths=1))
        self.assertEqual(tuning["current_tier"], "better")

    def test_unassigned_weak_policy_is_visible_but_does_not_reduce_score(self):
        first = policy_data()
        second = policy_data("2", paths=0, assigned=0)
        policies, core, rules = [first[index] + second[index] for index in range(3)]
        _, tuning = assessment(policies, core, rules)
        self.assertEqual(tuning["current_tier"], "best")
        self.assertEqual(tuning["score_0_100"], 100)
        self.assertEqual(len(tuning["policy_maturity_action_plan_all"]), 2)
        self.assertEqual(tuning["metrics"]["total_policies_scored"], 1)

    def test_empty_policy_is_critical_and_has_all_five_gaps(self):
        policies, _, _ = policy_data()
        _, tuning = assessment(policies, [], [])
        row = tuning["policy_maturity_action_plan_all"][0]
        self.assertEqual(len(row["missing_required_controls"]), 5)
        self.assertEqual(len(row["missing_critical_controls"]), 2)
        self.assertEqual(row["enforcement_score_0_100"], 0)

    def test_eedr_is_not_applicable(self):
        _, tuning = assessment(*policy_data(), ngav=False)
        self.assertFalse(tuning["framework_applicable"])
        self.assertEqual(tuning["current_tier"], "not_applicable")

    def test_no_assigned_policies_cannot_receive_a_healthy_score(self):
        _, tuning = assessment(*policy_data(assigned=0))
        self.assertEqual(tuning["metrics"]["total_policies_scored"], 0)
        self.assertEqual(tuning["score_0_100"], 0)
        self.assertFalse(tuning["gates"]["good"]["pass"])

    def test_old_summaries_require_reassessment_instead_of_showing_zero_coverage_as_best(self):
        summary, tuning = assessment(*policy_data())
        for row in tuning["policy_maturity_action_plan_all"]:
            del row["enforcement_score_0_100"]
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            deck = Presentation(str(write_technical_pptx(run_dir)))
            slide = next(slide for slide in deck.slides if any(
                shape.has_text_frame and shape.text == "Detailed Breakdown" for shape in slide.shapes
            ))
            tables = [shape.table for shape in slide.shapes if shape.has_table]
            self.assertTrue(all("rerun checks" in table.cell(1, 0).text for table in tables))

    def test_decks_contain_section_specific_tables_and_full_appendices(self):
        policies, core, rules = [], [], []
        for index in range(14):
            data = policy_data(str(index), paths=0 if index == 0 else 5, assigned=index * 10)
            policies.extend(data[0])
            core.extend(data[1])
            rules.extend(data[2])
        summary, tuning = assessment(policies, core, rules)
        original_policy_order = [row["policy_id"] for row in tuning["policy_maturity_action_plan_all"]]
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            deck = Presentation(str(write_technical_pptx(run_dir)))
            slide = next(slide for slide in deck.slides if any(
                shape.has_text_frame and shape.text == "Detailed Breakdown" for shape in slide.shapes
            ))
            tables = [shape for shape in slide.shapes if shape.has_table]
            self.assertEqual(len(tables), 2)
            self.assertEqual([cell.text for cell in tables[0].table.rows[0].cells],
                             ["Policy", "Endpoints", "Alert", "Alert and Block", "Unknown"])
            self.assertEqual(tables[1].table.cell(0, 1).text, "Endpoints")
            for table in tables:
                counts = [int(row.cells[1].text) for row in list(table.table.rows)[1:]]
                self.assertEqual(counts, sorted(counts, reverse=True))
                self.assertEqual(table.table.cell(1, 0).text, "Policy 13")
                self.assertEqual(table.table.cell(1, 1).text, "130")
            self.assertEqual(tables[1].table.cell(1, 7).text, "5")
            self.assertIn("BEST", tables[1].table.cell(1, 8).text)
            self.assertEqual(len(tables[1].table.rows), 6)
            for table in tables:
                self.assertLessEqual(table.top + table.height, deck.slide_height)
            appendix_rows = {
                "Core Prevention by Policy": [],
                "Core Prevention Settings": [],
                "Blocking and Isolation by Policy": [],
            }
            for page in deck.slides:
                for title, rows in appendix_rows.items():
                    if any(shape.has_text_frame and shape.text.startswith(title + " (Page")
                           for shape in page.shapes):
                        for shape in page.shapes:
                            if shape.has_table:
                                self.assertEqual(shape.table.cell(0, 1).text, "Endpoints")
                                rows.extend([cell.text for cell in row.cells]
                                            for row in list(shape.table.rows)[1:])
                if any(shape.has_text_frame and shape.text.startswith((
                    "Core Prevention Settings (Page", "Blocking and Isolation by Policy (Page",
                )) for shape in page.shapes):
                    for shape in page.shapes:
                        if shape.has_table:
                            self.assertLessEqual(shape.top + shape.height, deck.slide_height)
            for title, rows in appendix_rows.items():
                with self.subTest(appendix=title):
                    counts = [int(row[1]) for row in rows]
                    self.assertTrue(counts)
                    self.assertEqual(counts, sorted(counts, reverse=True))
                    self.assertEqual(rows[0][:2], ["Policy 13", "130"])
                    self.assertEqual(rows[-1][:2], ["Policy 0", "0"])
            self.assertEqual(len(appendix_rows["Core Prevention by Policy"]), 14)
            self.assertEqual(len(appendix_rows["Blocking and Isolation by Policy"]), 14)
            weakest_row = appendix_rows["Blocking and Isolation by Policy"][-1]
            self.assertEqual(weakest_row[7], "0")
            self.assertIn("WEAK", weakest_row[8])
            self.assertEqual(
                [row["policy_id"] for row in tuning["policy_maturity_action_plan_all"]], original_policy_order,
            )
            all_text = "\n".join(shape.text for page in deck.slides for shape in page.shapes if shape.has_text_frame)
            self.assertIn("Core Prevention Settings (Page", all_text)
            self.assertIn("Blocking and Isolation by Policy (Page 2/", all_text)
            self.assertNotIn("Policies with Highest Blocking Rules", all_text)
            self.assertTrue(write_executive_pptx(run_dir).is_file())
            eedr = copy.deepcopy(summary)
            eedr["checks"]["org"] = {
                "status": "ok", "organization": {"changeTimestamps": {"timestampMap": {"ORG_DISABLE_DEFENSE_RULES": 1}}},
            }
            eedr["checks"]["policy_posture"]["summary"]["ngav_enabled"] = False
            (run_dir / "summary.json").write_text(json.dumps(eedr), encoding="utf-8")
            eedr_deck = Presentation(str(write_technical_pptx(run_dir)))
            eedr_slide = next(slide for slide in eedr_deck.slides if any(
                shape.has_text_frame and shape.text == "Detailed Breakdown" for shape in slide.shapes
            ))
            self.assertFalse(any(shape.has_table for shape in eedr_slide.shapes))
            eedr_text = "\n".join(
                shape.text for page in eedr_deck.slides for shape in page.shapes if shape.has_text_frame
            )
            self.assertNotIn("Blocking and Isolation by Policy (Page", eedr_text)


if __name__ == "__main__":
    unittest.main()
