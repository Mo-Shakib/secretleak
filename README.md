# secret-scanner

A production-quality CLI tool to detect leaked secrets (API keys, tokens, private keys) in Git repositories.

## Features

- **Regex rules** — 30+ built-in patterns covering AWS, GitHub, Stripe, Google, Slack, Twilio, SendGrid, npm, PyPI, private keys, connection strings, and more
- **Shannon entropy heuristic** — catches high-entropy strings that don't match a known pattern
- **Three scan modes** — working tree, staged diff (`git diff --staged`), commit range
- **Three output formats** — Rich console table, JSON report, SARIF 2.1.0 (GitHub Code Scanning compatible)
- **False-positive suppression** — allowlist patterns, ignore paths, baseline file
- **Git hook** — auto-generates a `pre-commit` hook that blocks commits on findings
- **Secret masking** — secrets are never printed or stored in full (prefix/suffix only)

## Installation

### From PyPI

```bash
pip install secret-scanner
```

### From source (development)

```bash
git clone https://github.com/your-org/secret-scanner.git
cd secret-scanner
pip install -e ".[dev]"
```

---

## Using secret-scanner in Another Project

### Option 1 — Install globally and scan manually

Install once, then point it at any repo:

```bash
pip install secret-scanner
secret-scanner scan /path/to/your-project
```

### Option 2 — Add as a dev dependency

In your project's `pyproject.toml`:

```toml
[project.optional-dependencies]
dev = [
    "secret-scanner",
]
```

Then install and scan:

```bash
pip install -e ".[dev]"
secret-scanner scan .
```

Or reference a local checkout before it is published to PyPI:

```toml
dev = [
    "secret-scanner @ file:///path/to/secret-scanner",
]
```

### Option 3 — Pre-commit hook (recommended for teams)

Run once inside the target repo. Every developer on the team is protected automatically — no changes to their workflow required.

```bash
cd /path/to/your-project
secret-scanner install-hook .
```

From that point on, every `git commit` scans the staged files and blocks if secrets are found:

```
[secret-scanner] Scanning staged files for secrets...
🔴 CRITICAL  AWS Access Key ID — config.py:12 — AKIA****MPLE

[secret-scanner] !! Commit BLOCKED: secrets detected in staged files.
```

Remove the hook at any time:

```bash
secret-scanner uninstall-hook .
```

### Option 4 — GitHub Actions (CI/CD)

Create `.github/workflows/secret-scan.yml` in your project:

```yaml
name: Secret Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Scan for secrets
        run: |
          pip install secret-scanner
          secret-scanner scan . --format sarif --output results.sarif --no-fail

      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Findings appear in your repo's **Security → Code Scanning** tab with file locations and line numbers.

### Option 5 — Suppress false positives in your project

```bash
cd /path/to/your-project

# 1. Generate a baseline to silence already-known findings
secret-scanner generate-baseline .
git add .secret-scanner-baseline.json
git commit -m "chore: add secret-scanner baseline"

# 2. Add project-specific config
cat > .secret-scanner.yaml << 'EOF'
allowlist:
  patterns:
    - '^EXAMPLE_'        # placeholder values in docs
    - 'your-key-here'    # obvious dummy values
  paths:
    - tests/fixtures/**  # test data with fake secrets
    - docs/**
baseline_file: .secret-scanner-baseline.json
EOF
```

Future scans will skip anything in the baseline and anything matching the allowlist.

---

### Quick reference

| Goal | Command |
|------|---------|
| Scan a project | `secret-scanner scan /path/to/project` |
| Scan staged files only | `secret-scanner scan --staged` |
| Scan a commit range | `secret-scanner scan --commit-range HEAD~10..HEAD` |
| Block commits automatically | `secret-scanner install-hook .` (run once) |
| CI pipeline (SARIF) | `secret-scanner scan . --format sarif --no-fail` |
| JSON report | `secret-scanner scan . --format json -o report.json` |
| Suppress known findings | `secret-scanner generate-baseline .` |
| List active rules | `secret-scanner rules` |

---

## Quick Start

```bash
# Scan current directory
secret-scanner scan .

# Scan only staged files (before committing)
secret-scanner scan --staged

# Scan a commit range
secret-scanner scan --commit-range HEAD~10..HEAD

# JSON output
secret-scanner scan . --format json --output report.json

# SARIF output (GitHub Code Scanning)
secret-scanner scan . --format sarif --output results.sarif

# Install pre-commit hook
secret-scanner install-hook .

# Generate baseline to suppress existing findings
secret-scanner generate-baseline .

# List active rules
secret-scanner rules
```

## Configuration

Create `.secret-scanner.yaml` in your repo root:

```yaml
# Override entropy settings
entropy:
  enabled: true
  threshold: 4.5
  min_length: 20

# Add custom rules
rules:
  - id: my-internal-token
    name: Internal Service Token
    pattern: 'myapp_[a-z0-9]{32}'
    severity: high
    description: Internal service authentication token

# Allowlist – suppress known false positives
allowlist:
  patterns:
    - '^EXAMPLE'          # example values in docs
    - 'placeholder'        # obvious placeholders
  paths:
    - tests/fixtures/**   # test data
    - '**/*.md'           # documentation

# Additional paths to skip
ignore_paths:
  - vendor/**
  - node_modules/**

# Point at a baseline file
baseline_file: .secret-scanner-baseline.json
```

## False Positive Handling

### Allowlist patterns

```yaml
allowlist:
  patterns:
    - '^fake_'
    - 'example\.com'
```

### Baseline suppression

Generate a baseline from the current state of your repo, commit it, and future scans will ignore already-known findings:

```bash
secret-scanner generate-baseline .
git add .secret-scanner-baseline.json
git commit -m "chore: add secret-scanner baseline"
```

### Ignore paths

```yaml
ignore_paths:
  - docs/**
  - tests/fixtures/**
  - '**/*.lock'
```

## CI Integration

```yaml
# .github/workflows/secret-scan.yml
- name: Scan for secrets
  run: |
    pip install secret-scanner
    secret-scanner scan . --format sarif --output results.sarif --no-fail

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Git Hook

```bash
# Install
secret-scanner install-hook .

# Force-overwrite an existing hook
secret-scanner install-hook . --force

# Uninstall
secret-scanner uninstall-hook .
```

The hook runs `secret-scanner scan --staged` and blocks the commit if any secrets are found.

## Output Formats

### Console (default)

Rich table with severity icons, file paths, line numbers, and masked secrets.

### JSON

```json
{
  "version": "0.1.0",
  "generated_at": "2026-03-09T12:00:00Z",
  "scan_mode": "working_tree",
  "summary": { "total": 2, "critical": 1, "high": 1 },
  "findings": [
    {
      "fingerprint": "a3b4c5d6e7f8a1b2",
      "rule_id": "aws-access-key-id",
      "severity": "critical",
      "file_path": "config.py",
      "line_number": 12,
      "secret_masked": "AKIA****MPLE",
      ...
    }
  ]
}
```

### SARIF 2.1.0

Compatible with GitHub Code Scanning. Upload via `github/codeql-action/upload-sarif`.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | No findings |
| `1`  | Findings detected (`--no-fail` to suppress) |
| `2`  | Error (bad args, git failure, config error) |

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=secret_scanner --cov-report=term-missing

# Lint
ruff check src/ tests/
ruff format src/ tests/

# Type check
mypy src/
```

## Security Notes

- Secrets are **never** stored or logged in full. Only a masked form (`prefix****suffix`) appears in output.
- The JSON and SARIF outputs are safe to store and share — they contain only masked values.
- The baseline file contains only fingerprints (SHA-256 hashes), not secret values.
