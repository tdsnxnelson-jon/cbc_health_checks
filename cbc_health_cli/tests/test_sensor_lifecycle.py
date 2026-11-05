import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from pptx import Presentation

from cbc_health_cli.checks import (
    SensorLifecycleLookupError,
    fetch_sensor_lifecycle,
    summarize_sensor_coverage_quality,
)
from cbc_health_cli.reporting import write_technical_pptx


class SensorLifecycleTests(unittest.TestCase):
    def lifecycle_page(self, os_label, latest_release, eos_releases):
        rows = [f"<tr><td>{latest_release}</td><td>June 2026</td><td></td><td></td></tr>"]
        rows.extend(
            f"<tr><td>{release}</td><td>January 2020</td><td>February 2020</td><td>March 2020</td></tr>"
            for release in eos_releases
        )
        return (
            f"<table><caption>{os_label} Sensors in Status: Standard Support</caption>"
            "<tr><th>Release</th><th>Enter Standard</th><th>Enter Extended</th>"
            "<th>Enter End of Support</th></tr>"
            f"{''.join(rows)}</table>"
        )

    def sensor_devices(self):
        return [
            {"status": "ACTIVE", "os": "WINDOWS", "sensor_version": "4.0.2.1540"},
            {"status": "ACTIVE", "os": "WINDOWS", "sensor_version": "4.1.0.5463"},
            {"status": "ACTIVE", "os": "WINDOWS", "sensor_version": "4.2.0.3361"},
            {"status": "ACTIVE", "os": "WINDOWS", "sensor_version": "4.3.0.1000"},
            {"status": "ACTIVE", "os": "LINUX", "sensor_version": "2.15.0.1"},
            {"status": "ACTIVE", "os": "LINUX", "sensor_version": "2.16.3.7863591"},
            {"status": "ACTIVE", "os": "MAC", "sensor_version": "3.7.4.1"},
            {"status": "ACTIVE", "os": "MAC", "sensor_version": "3.8.2.53"},
            {"status": "ACTIVE", "os": "WINDOWS", "sensor_version": "unknown"},
        ]

    def fetch_lifecycle(self, windows_latest="4.2"):
        pages = [
            self.lifecycle_page("Windows", windows_latest, ["4.0", "3.9"]),
            self.lifecycle_page("Linux", "2.16.0", ["2.15.x"]),
            self.lifecycle_page("macOS", "3.8", ["3.7.4"]),
        ]
        responses = []
        for page in pages:
            response = MagicMock()
            response.read.return_value = page.encode("utf-8")
            response.headers.get_content_charset.return_value = "utf-8"
            response.__enter__.return_value = response
            response.__exit__.return_value = None
            responses.append(response)
        with patch("cbc_health_cli.checks.urlopen", side_effect=responses) as get:
            lifecycle = fetch_sensor_lifecycle()
        return lifecycle, get

    def test_summary_flags_only_eos_release_trains(self):
        lifecycle, _ = self.fetch_lifecycle()
        summary = summarize_sensor_coverage_quality(self.sensor_devices(), lifecycle)

        self.assertEqual(summary["latest_vendor_release_train_by_os"], {
            "WINDOWS": "4.2",
            "LINUX": "2.16.0",
            "MACOS": "3.8",
        })
        self.assertEqual(summary["eos_sensor_version_breakdown_by_os"], {
            "LINUX": {"2.15.0.1": 1},
            "MACOS": {"3.7.4.1": 1},
            "WINDOWS": {"4.0.2.1540": 1},
        })
        self.assertEqual(summary["eos_sensor_release_train_breakdown_by_os"], {
            "LINUX": {"2.15": 1},
            "MACOS": {"3.7": 1},
            "WINDOWS": {"4.0": 1},
        })
        self.assertEqual(summary["sensor_lifecycle_status"], "available")
        self.assertTrue(summary["sensor_lifecycle_retrieved_at"])

    def test_vendor_lifecycle_is_fetched_again_each_invocation(self):
        first, first_requests = self.fetch_lifecycle("4.2")
        second, second_requests = self.fetch_lifecycle("4.3")

        self.assertEqual(first["latest_release_train_by_os"]["WINDOWS"], "4.2")
        self.assertEqual(second["latest_release_train_by_os"]["WINDOWS"], "4.3")
        self.assertEqual(first_requests.call_count, 3)
        self.assertEqual(second_requests.call_count, 3)

    def test_failed_vendor_fetch_does_not_fall_back_to_a_snapshot(self):
        with patch(
            "cbc_health_cli.checks.urlopen",
            side_effect=URLError("offline"),
        ):
            with self.assertRaises(SensorLifecycleLookupError):
                fetch_sensor_lifecycle()

        summary = summarize_sensor_coverage_quality(self.sensor_devices())
        self.assertEqual(summary["sensor_lifecycle_status"], "unavailable")
        self.assertEqual(summary["latest_vendor_release_train_by_os"], {})
        self.assertEqual(summary["eos_sensor_release_train_breakdown_by_os"], {})

    def test_endpoint_health_slide_shows_vendor_releases_and_eos(self):
        lifecycle, _ = self.fetch_lifecycle()
        sensor_quality = summarize_sensor_coverage_quality(self.sensor_devices(), lifecycle)
        summary = {
            "checks": {
                "devices": {"status": "ok", "summary": {
                    "total_devices": 9,
                    "active_last_7d": 9,
                    "active_ratio_last_7d": 1,
                    "os_breakdown": {"WINDOWS": 5, "LINUX": 2, "MAC": 2},
                }},
                "sensor_coverage_quality": {"status": "ok", "summary": sensor_quality},
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            deck = Presentation(str(write_technical_pptx(run_dir)))

        slide = next(
            slide for slide in deck.slides
            if any(shape.has_text_frame and shape.text == "Endpoint Platform and Sensor Health" for shape in slide.shapes)
        )
        slide_text = "\n".join(
            shape.text for shape in slide.shapes if shape.has_text_frame
        )
        self.assertIn("Latest vendor release train: Windows 4.2 | Linux 2.16.0 | macOS 3.8", slide_text)
        self.assertIn(
            "End-of-support (EOS/EOL) release trains detected: Windows: 4.0.x (1) | Linux: 2.15.x (1) | macOS: 3.7.x (1)",
            slide_text,
        )
        self.assertIn("Broadcom lifecycle reference fetched ", slide_text)
        source = next(
            shape for shape in slide.shapes
            if shape.has_text_frame and shape.text.startswith("Broadcom lifecycle reference fetched ")
        )
        self.assertIn("techdocs.broadcom.com", source.text_frame.paragraphs[0].runs[0].hyperlink.address)
        for shape in slide.shapes:
            self.assertLessEqual(shape.left + shape.width, deck.slide_width)
            self.assertLessEqual(shape.top + shape.height, deck.slide_height)


if __name__ == "__main__":
    unittest.main()
