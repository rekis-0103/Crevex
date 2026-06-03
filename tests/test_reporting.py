import unittest

from crevex.models import Finding, ScanReport
from crevex.reporting import report_to_json, render_text


class ReportingTest(unittest.TestCase):
    def test_report_summary_and_json(self):
        report = ScanReport.start(version="0.1.0", scan_type="code-scan")
        report.targets = ["."]
        report.findings.append(
            Finding(
                id="x",
                check_id="test",
                title="Example",
                severity="high",
                confidence="medium",
                target=".",
                evidence="evidence",
                impact="impact",
                recommendation="fix",
            )
        )
        report.finish()

        self.assertIn('"high": 1', report_to_json(report))
        self.assertIn("[HIGH] Example", render_text(report))
        self.assertIn("Severity Summary", render_text(report))
        self.assertIn("Fix: fix", render_text(report))

    def test_quiet_report_hides_detail_fields(self):
        report = ScanReport.start(version="0.1.0", scan_type="code-scan")
        report.targets = ["."]
        report.findings.append(
            Finding(
                id="x",
                check_id="test",
                title="Example",
                severity="medium",
                confidence="medium",
                target=".",
                evidence="evidence",
                impact="impact",
                recommendation="fix",
            )
        )
        report.finish()

        rendered = render_text(report, verbosity="quiet")

        self.assertIn("[MEDIUM] Example", rendered)
        self.assertIn("Target: .", rendered)
        self.assertNotIn("Evidence:", rendered)
        self.assertNotIn("Fix:", rendered)

    def test_verbose_report_shows_metadata(self):
        report = ScanReport.start(version="0.1.0", scan_type="code-scan")
        report.targets = ["."]
        report.findings.append(
            Finding(
                id="x",
                check_id="test.check",
                title="Example",
                severity="low",
                confidence="medium",
                target=".",
                evidence="evidence",
                impact="impact",
                recommendation="fix",
                references=["https://example.com/reference"],
            )
        )
        report.finish()

        rendered = render_text(report, verbosity="verbose")

        self.assertIn("Check: test.check", rendered)
        self.assertIn("Finding ID: x", rendered)
        self.assertIn("References: https://example.com/reference", rendered)


if __name__ == "__main__":
    unittest.main()
