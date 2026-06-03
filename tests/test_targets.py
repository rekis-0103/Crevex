import unittest

from crevex.targets import parse_target


class TargetParsingTest(unittest.TestCase):
    def test_parse_https_url(self):
        target = parse_target("https://example.com/app")

        self.assertEqual(target.kind, "web")
        self.assertEqual(target.scheme, "https")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.path, "/app")

    def test_parse_ip_as_host(self):
        target = parse_target("127.0.0.1")

        self.assertEqual(target.kind, "host")
        self.assertEqual(target.host, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
