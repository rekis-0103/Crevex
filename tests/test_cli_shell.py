import contextlib
import io
import argparse
import tempfile
import unittest
from pathlib import Path

from crevex.cli import apply_config_defaults, run_shell_command


class CliShellTest(unittest.TestCase):
    def test_shell_help_command(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = run_shell_command("help")

        self.assertEqual(status, 0)
        self.assertIn("Available commands", output.getvalue())

    def test_shell_version_command(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = run_shell_command("version")

        self.assertEqual(status, 0)
        self.assertIn("crevex 0.1.0", output.getvalue())

    def test_shell_exit_command(self):
        self.assertEqual(run_shell_command("exit"), -1)

    def test_apply_config_defaults_keeps_authorization_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "crevex.yml"
            path.write_text(
                "\n".join(
                    [
                        "profile: deep",
                        "format: table",
                        "quiet: true",
                    ]
                ),
                encoding="utf-8",
            )

            args = argparse.Namespace(
                config=str(path),
                targets=[],
                targets_file=None,
                code_path=None,
                profile=None,
                format=None,
                output=None,
                include_check=None,
                exclude_check=None,
                no_color=False,
                no_spinner=False,
                quiet=False,
                verbose=False,
                confirm_authorized=False,
            )

            resolved = apply_config_defaults(args)

        self.assertEqual(resolved.profile, "deep")
        self.assertEqual(resolved.format, "table")
        self.assertTrue(resolved.quiet)
        self.assertFalse(resolved.confirm_authorized)


if __name__ == "__main__":
    unittest.main()
