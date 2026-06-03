import unittest

import crevex.engine as engine


class EngineTargetHandlingTest(unittest.TestCase):
    def test_web_checks_are_skipped_when_http_probe_fails(self):
        original_probe = engine.probe_http_service
        engine.probe_http_service = lambda url: (False, "not an HTTP service")
        try:
            report = engine.run_scan(
                ["http://127.0.0.1:3306"],
                scan_type="scan",
                include={"web.security_headers"},
            )
        finally:
            engine.probe_http_service = original_probe

        self.assertEqual(report.errors, [])
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].check_id, "target.http_service")
        self.assertIn("Web-only checks were skipped", report.findings[0].impact)


if __name__ == "__main__":
    unittest.main()
