import contextlib
import io
import unittest

from crevex.cli import run_shell_command


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


if __name__ == "__main__":
    unittest.main()
