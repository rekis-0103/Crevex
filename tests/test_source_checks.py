import tempfile
import unittest
from pathlib import Path

from crevex.checks.source import SecretPatternCheck, SourceRiskPatternCheck
from crevex.models import ScanTarget


class SourceChecksTest(unittest.TestCase):
    def test_secret_pattern_check_finds_possible_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = root / "app.py"
            secret = "abcdefghijkl" + "mnopqrstuvwxyz"
            app.write_text(f"API_KEY = '{secret}'\n", encoding="utf-8")
            target = ScanTarget(raw=str(root), kind="code", host=str(root))

            findings = list(SecretPatternCheck().run(target))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")

    def test_source_risk_pattern_check_finds_sql_string_building(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = root / "app.py"
            app.write_text("query = 'SELECT * FROM users WHERE id=' + request.args['id']\n", encoding="utf-8")
            target = ScanTarget(raw=str(root), kind="code", host=str(root))

            findings = list(SourceRiskPatternCheck().run(target))

        self.assertTrue(any("SQL injection" in finding.title for finding in findings))


if __name__ == "__main__":
    unittest.main()
