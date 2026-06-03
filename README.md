# Crevex

Crevex is a safe CLI vulnerability scanner for authorized targets. It supports:

- DAST-style web and host checks for running applications.
- Source-code checks for common project risks.
- JSON and HTML reports with actionable remediation guidance.

Crevex is intended only for systems you own or are explicitly authorized to test.

## Quick Start

```powershell
$env:PYTHONPATH="src"
python -m crevex
python -m crevex scan https://example.com --confirm-authorized
python -m crevex code-scan .
python -m crevex audit https://example.com --code-path . --confirm-authorized --format json --output report.json
python -m crevex report report.json --format html --output report.html
```

Or install it locally:

```powershell
python -m pip install -e .
crevex
crevex checks
```

## Interactive Shell

Run Crevex without arguments to open the interactive terminal shell:

```powershell
crevex
```

Or from source:

```powershell
$env:PYTHONPATH="src"
python -m crevex
```

Inside the shell, run commands without typing `crevex` again:

```text
crevex > checks
crevex > scan http://127.0.0.1:3000 --confirm-authorized
crevex > code-scan <project-path>
crevex > audit http://127.0.0.1:3000 --code-path <project-path> --confirm-authorized
crevex > exit
```

## Current Checks

DAST checks:

- DNS resolution summary.
- Safe TCP port exposure check on a small default port list.
- HTTP security headers.
- Cookie security flags.
- Common sensitive path exposure using safe GET requests.
- TLS certificate expiration.

Source-code checks:

- Dependency manifest discovery for JavaScript, Python, and PHP projects.
- Possible hardcoded secrets.
- Risky source patterns for SQL string building, debug mode, unsafe redirects, and command execution from input.

Every finding includes evidence, impact, severity, confidence, and an actionable recommendation.

## Safety

The default scanner performs low-risk checks only. It does not exploit targets, brute-force credentials, or run destructive payloads.
