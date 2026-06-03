import unittest

from crevex.checks import build_checks
from crevex.checks.host import TcpPortCheck
from crevex.checks.web import SensitivePathCheck
from crevex.targets import parse_target


class ProfileBehaviorTest(unittest.TestCase):
    def test_quick_dast_profile_uses_smaller_check_set(self):
        check_ids = {check.id for check in build_checks("scan", profile="quick")}

        self.assertIn("host.dns_resolution", check_ids)
        self.assertIn("host.tcp_ports", check_ids)
        self.assertIn("web.security_headers", check_ids)
        self.assertNotIn("web.sensitive_paths", check_ids)
        self.assertNotIn("web.tls_certificate", check_ids)

    def test_quick_code_profile_skips_source_risk_patterns(self):
        check_ids = {check.id for check in build_checks("code-scan", profile="quick")}

        self.assertIn("code.dependency_manifests", check_ids)
        self.assertIn("code.secret_patterns", check_ids)
        self.assertNotIn("code.risk_patterns", check_ids)

    def test_tcp_profile_ports_keep_explicit_target_port(self):
        target = parse_target("http://127.0.0.1:3306")
        ports = TcpPortCheck(profile="quick").ports_for_target(target)

        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertIn(3306, ports)

    def test_deep_sensitive_paths_include_extended_candidates(self):
        paths = SensitivePathCheck(profile="deep").paths_for_profile()

        self.assertIn(".env.production", paths)
        self.assertIn("phpinfo.php", paths)
        self.assertGreater(len(paths), len(SensitivePathCheck(profile="standard").paths_for_profile()))


if __name__ == "__main__":
    unittest.main()
