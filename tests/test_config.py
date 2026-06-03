import tempfile
import unittest
from pathlib import Path

from crevex.config import list_to_csv, load_config


class ConfigTest(unittest.TestCase):
    def test_load_config_supports_scalars_and_lists(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "crevex.yml"
            path.write_text(
                "\n".join(
                    [
                        "profile: quick",
                        "format: table",
                        "no_color: true",
                        "include_check:",
                        "  - web.security_headers",
                        "  - host.tcp_ports",
                    ]
                ),
                encoding="utf-8",
            )

            config = load_config(str(path))

        self.assertEqual(config["profile"], "quick")
        self.assertEqual(config["format"], "table")
        self.assertTrue(config["no_color"])
        self.assertEqual(config["include_check"], ["web.security_headers", "host.tcp_ports"])

    def test_list_to_csv_normalizes_config_lists(self):
        self.assertEqual(list_to_csv(["a", "b"]), "a,b")
        self.assertEqual(list_to_csv("a,b"), "a,b")
        self.assertIsNone(list_to_csv(None))

    def test_missing_default_config_returns_empty_dict(self):
        self.assertEqual(load_config(), {})


if __name__ == "__main__":
    unittest.main()
