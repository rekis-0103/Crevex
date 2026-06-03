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


if __name__ == "__main__":
    unittest.main()
