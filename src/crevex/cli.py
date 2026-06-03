from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path

from . import __version__
from .checks import list_checks
from .engine import run_scan
from .reporting import render_html, render_text, report_from_json, report_to_json


class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    MAGENTA = "\033[35m"


def comma_set(value: str | None) -> set[str] | None:
    if not value:
        return None
    return {item.strip() for item in value.split(",") if item.strip()}


def write_or_print(content: str, output: str | None) -> None:
    if output:
        Path(output).write_text(content, encoding="utf-8")
        print(f"Wrote {output}")
    else:
        print(content)


def add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("targets", nargs="*", help="URL, host, IP, or code path depending on command.")
    parser.add_argument("--targets-file", help="File containing one target per line.")
    parser.add_argument("--code-path", help="Source-code path for audit mode.")
    parser.add_argument("--profile", choices=["quick", "standard", "deep"], default="standard")
    parser.add_argument("--format", choices=["table", "json", "html"], default="table")
    parser.add_argument("--output", help="Write report to this path.")
    parser.add_argument("--include-check", help="Comma-separated check IDs to include.")
    parser.add_argument("--exclude-check", help="Comma-separated check IDs to exclude.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output.")
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("--quiet", action="store_true", help="Show a compact terminal report.")
    verbosity.add_argument("--verbose", action="store_true", help="Show extra finding metadata in terminal reports.")
    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Confirm that you own or are authorized to scan the target.",
    )


def render_scan_output(
    report,
    output_format: str,
    color: bool = False,
    verbosity: str = "normal",
) -> str:
    if output_format == "json":
        return report_to_json(report)
    if output_format == "html":
        return render_html(report.to_dict())
    return render_text(report, color=color, verbosity=verbosity)


def run_scan_command(args: argparse.Namespace, scan_type: str) -> int:
    if scan_type in {"scan", "audit"} and not args.confirm_authorized:
        print("Refusing active scan without --confirm-authorized.", file=sys.stderr)
        return 2

    try:
        report = run_scan(
            targets=args.targets,
            target_file=args.targets_file,
            code_path=args.code_path,
            scan_type=scan_type,
            profile=args.profile,
            include=comma_set(args.include_check),
            exclude=comma_set(args.exclude_check),
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    use_color = (
        args.output is None
        and args.format == "table"
        and not args.no_color
        and sys.stdout.isatty()
    )
    verbosity = "verbose" if args.verbose else "quiet" if args.quiet else "normal"
    write_or_print(
        render_scan_output(report, args.format, color=use_color, verbosity=verbosity),
        args.output,
    )
    return 1 if any(finding.severity in {"high", "critical"} for finding in report.findings) else 0


def build_parser(require_command: bool = True) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crevex",
        description="Safe CLI vulnerability scanner for authorized targets.",
    )
    parser.add_argument("--version", action="version", version=f"crevex {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=require_command)

    scan = subparsers.add_parser("scan", help="Run safe DAST checks against URL/host targets.")
    add_scan_options(scan)

    code_scan = subparsers.add_parser("code-scan", help="Run source-code checks against a project path.")
    add_scan_options(code_scan)

    audit = subparsers.add_parser("audit", help="Run DAST checks plus source-code checks.")
    add_scan_options(audit)

    subparsers.add_parser("checks", help="List available checks.")

    report = subparsers.add_parser("report", help="Render a saved JSON report.")
    report.add_argument("input", help="Path to a Crevex JSON report.")
    report.add_argument("--format", choices=["html", "json"], default="html")
    report.add_argument("--output", help="Write rendered report to this path.")

    subparsers.add_parser("version", help="Print version.")
    return parser


def dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.command in {"scan", "code-scan", "audit"}:
        return run_scan_command(args, args.command)

    if args.command == "checks":
        for check in list_checks():
            kinds = ",".join(sorted(check.target_kinds))
            print(f"{check.id}\t{kinds}\t{check.name}")
        return 0

    if args.command == "report":
        data = report_from_json(args.input)
        content = render_html(data) if args.format == "html" else Path(args.input).read_text(encoding="utf-8")
        write_or_print(content, args.output)
        return 0

    if args.command == "version":
        print(f"crevex {__version__}")
        return 0

    parser.print_help()
    return 2


def print_banner() -> None:
    print(
        f"""{Style.CYAN}{Style.BOLD}
   ______
  / ____/_______ _   _____  _  __
 / /   / ___/ _ \\ | / / _ \\| |/_/
/ /___/ /  /  __/ |/ /  __/>  <
\\____/_/   \\___/|___/\\___/_/|_|
{Style.RESET}{Style.DIM}Safe vulnerability scanner for authorized targets{Style.RESET}
"""
    )
    print(f"{Style.GREEN}crevex {__version__}{Style.RESET} interactive shell")
    print("Type 'help' for commands, 'exit' to quit.\n")


def print_shell_help() -> None:
    print(f"{Style.BOLD}Available commands{Style.RESET}")
    print("  scan <url|host> --confirm-authorized")
    print("  code-scan <path>")
    print("  audit <url|host> --code-path <path> --confirm-authorized")
    print("  checks")
    print("  report <report.json> --format html --output report.html")
    print("  version")
    print("  clear")
    print("  exit")
    print("")
    print(f"{Style.BOLD}Examples{Style.RESET}")
    print("  scan http://127.0.0.1:3000 --confirm-authorized")
    print("  scan http://127.0.0.1:3000 --confirm-authorized --quiet")
    print("  scan http://127.0.0.1:3000 --confirm-authorized --verbose --no-color")
    print("  code-scan <project-path>")
    print("  audit http://127.0.0.1:3000 --code-path <project-path> --confirm-authorized")


def run_shell_command(line: str) -> int:
    command = line.strip()
    if not command:
        return 0
    if command in {"exit", "quit", ":q"}:
        return -1
    if command in {"help", "?"}:
        print_shell_help()
        return 0
    if command == "clear":
        print("\033[2J\033[H", end="")
        return 0

    try:
        argv = shlex.split(command, posix=False)
    except ValueError as exc:
        print(f"{Style.RED}Parse error:{Style.RESET} {exc}")
        return 2

    parser = build_parser(require_command=True)
    try:
        args = parser.parse_args(argv)
        status = dispatch(args, parser)
    except SystemExit as exc:
        status = int(exc.code) if isinstance(exc.code, int) else 2

    if status == 0:
        print(f"{Style.GREEN}done{Style.RESET}")
    elif status == 1:
        print(f"{Style.YELLOW}completed with findings{Style.RESET}")
    elif status > 1:
        print(f"{Style.RED}command failed with exit code {status}{Style.RESET}")
    return status


def interactive_shell() -> int:
    print_banner()
    while True:
        try:
            line = input(f"{Style.MAGENTA}crevex{Style.RESET} {Style.DIM}>{Style.RESET} ")
        except (EOFError, KeyboardInterrupt):
            print("\nbye")
            return 0
        status = run_shell_command(line)
        if status == -1:
            print("bye")
            return 0


def main(argv: list[str] | None = None) -> int:
    actual_argv = sys.argv[1:] if argv is None else argv
    if not actual_argv:
        return interactive_shell()

    parser = build_parser(require_command=True)
    args = parser.parse_args(actual_argv)
    return dispatch(args, parser)


if __name__ == "__main__":
    raise SystemExit(main())
