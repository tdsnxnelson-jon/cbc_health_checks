import unittest

from cbc_health_cli.checks import (
    is_api_connector_authentication_event,
    summarize_api_connector_use,
)


class ApiConnectorUseTests(unittest.TestCase):
    def test_ui_event_with_connector_text_and_email_actor_is_not_authentication(self):
        event = {
            "actor": "user@example.com",
            "description": "Tab: Settings (Policy) Action: Connector settings viewed",
        }

        self.assertFalse(is_api_connector_authentication_event(event))
        summary = summarize_api_connector_use([event])
        self.assertEqual(summary["active_connectors"], [])
        self.assertEqual(summary["connector_session_events"], 0)

    def test_connector_authentication_event_is_counted_with_access_level(self):
        event = {
            "actor": "A1B2C3D4",
            "actor_ip": "192.0.2.10",
            "description": "Connector (App) A1B2C3D4 created session successfully",
        }

        summary = summarize_api_connector_use(
            [event],
            [{"api_id": "A1B2C3D4", "access_level_type": "Health Checks"}],
        )

        self.assertEqual(summary["connector_session_events"], 1)
        self.assertEqual(summary["active_connectors"][0]["connector_id"], "A1B2C3D4")
        self.assertEqual(summary["active_connectors"][0]["api_access_level_type"], "Health Checks")

    def test_email_actor_is_ignored_in_targeted_connector_activity(self):
        summary = summarize_api_connector_use(
            [],
            connector_activity={
                "user@example.com": {"session_count": 4_202_123},
                "A1B2C3D4": {"session_count": 2},
            },
        )

        self.assertEqual(summary["connector_session_events"], 2)
        self.assertEqual(summary["active_connector_count"], 1)
        self.assertEqual(summary["active_connectors"][0]["connector_id"], "A1B2C3D4")


if __name__ == "__main__":
    unittest.main()