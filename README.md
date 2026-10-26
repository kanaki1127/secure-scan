# \# secure-scan

# 

# A corporate \*\*Secure Coding Analysis Tool\*\* that scans source code for security vulnerabilities, maps findings to \*\*OWASP Top 10 2021\*\* and \*\*PCI DSS v4.0\*\*, and delivers results through a CLI, a web dashboard, and \*\*SARIF 2.1.0\*\* reports compatible with GitHub Code Scanning.

# 

# Built to satisfy the objectives of automated code review, secure coding enforcement, compliance reporting, and CI/CD integration in corporate development workflows.

# 

# \---

# 

# \## Features

# 

# \- \*\*Multi-language static analysis\*\* via Semgrep — covers Python, JavaScript, TypeScript, Go, Java, Ruby, PHP, C/C++, and 20+ more

# \- \*\*Compliance mapping\*\* — every finding tagged with CWE ID, OWASP Top 10 2021 category, and PCI DSS v4.0 requirement

# \- \*\*Developer-friendly output\*\* — color-coded console report, GitHub-flavored PR comment formatter, and SARIF 2.1.0

# \- \*\*Baseline diffing\*\* — suppress known findings and surface only new issues introduced in a pull request

# \- \*\*Quality gates\*\* — `--fail-on` flag exits with code 1 on critical/high findings, blocking vulnerable merges

# \- \*\*Web dashboard\*\* — FastAPI UI with SQLite scan history, live findings table, and one-click scanning

# \- \*\*CI/CD integration\*\* — GitHub Actions workflow included; SARIF uploads to the repository's Security tab

# 

# \---

# 

# \## Installation

# 

# Requires Python 3.10+ and Semgrep.

# 

# ```bash

# pip install -e .

# pip install semgrep

# ```

# 

# Verify the install:

# 

# ```bash

# secure-scan --help

# ```

# 

# \---

# 

# \## Quick start

# 

# \### Scan a project

# 

# ```bash

# secure-scan scan ./src --format console

# ```

# 

# Output:

# 

# ```

# === secure-scan report ===

# Total findings: 3

# Critical: 0  High: 1  Medium: 2  Low: 0

# 

# src/auth.py:42

# &#x20; \[HIGH] python.lang.security.audit.sqli.string-concat

# &#x20; SQL query built from untrusted input.

# &#x20; Fix: Use parameterized queries or prepared statements.

# ```

# 

# \### Generate SARIF for GitHub Code Scanning

# 

# ```bash

# secure-scan scan ./src --format sarif --output report.sarif

# ```

# 

# \### Enforce a quality gate in CI

# 

# ```bash

# secure-scan scan ./src --fail-on high

# \# exits with code 1 if any high/critical finding is present

# ```

# 

# \### Use a baseline to ignore known findings

# 

# ```bash

# \# Save the current state as a baseline

# secure-scan baseline-save ./src --output baseline.sarif

# 

# \# Later scans will only show NEW findings

# secure-scan scan ./src --baseline baseline.sarif --format console

# ```

# 

# \### Launch the web dashboard

# 

# ```bash

# secure-scan serve

# \# open http://127.0.0.1:8000

# ```

# 

# The dashboard persists scan history in SQLite and lets you re-scan any target with a single click.

# 

# \---

# 

# \## Configuration

# 

# Create `secure-scan.yml` in your project root. All fields are optional; defaults apply.

# 

# ```yaml

# \# Minimum severity that causes a non-zero exit code (critical | high | medium | low)

# fail\_on\_severity: high

# 

# \# Glob patterns or paths to skip during scanning

# ignore\_paths: \[]

# 

# \# Semgrep rule sets to enable ("auto" uses the community registry)

# enabled\_rules:

# &#x20; - auto

# 

# \# Optional baseline file for diffing findings

# baseline\_path: null

# 

# \# Output format: sarif | console | json

# output\_format: sarif

# ```

# 

# \---

# 

# \## Supported CWEs

# 

# | CWE | Name | OWASP 2021 | PCI DSS v4.0 |

# |-----|------|------------|--------------|

# | CWE-89 | SQL Injection | A03:2021 - Injection | 6.2.4 |

# | CWE-79 | Cross-site Scripting | A03:2021 - Injection | 6.2.4 |

# | CWE-78 | OS Command Injection | A03:2021 - Injection | 6.2.4 |

# | CWE-22 | Path Traversal | A01:2021 - Broken Access Control | 6.2.4 |

# | CWE-798 | Hardcoded Credentials | A07:2021 - Auth Failures | 8.3.1 |

# | CWE-327 | Broken Cryptography | A02:2021 - Crypto Failures | 4.2.1 |

# | CWE-502 | Insecure Deserialization | A08:2021 - Integrity Failures | 6.2.4 |

# | CWE-611 | XML External Entity | A05:2021 - Misconfiguration | 6.2.4 |

# | CWE-918 | Server-Side Request Forgery | A10:2021 - SSRF | 6.2.4 |

# | CWE-352 | Cross-Site Request Forgery | A01:2021 - Broken Access Control | 6.2.4 |

# | CWE-284 | Improper Access Control | A01:2021 - Broken Access Control | 7.1 |

# | CWE-20 | Improper Input Validation | A03:2021 - Injection | 6.2.4 |

# 

# \---

# 

# \## Architecture

# 

# ```

# Target code

# &#x20;   │

# &#x20;   ▼

# analyzers.semgrep\_runner  ──►  Semgrep CLI

# &#x20;   │                              │

# &#x20;   ▼                              ▼

# analyzers.dispatcher ─────►  SARIF 2.1.0

# &#x20;   │

# &#x20;   ▼

# output.enricher  (adds CWE / OWASP / PCI DSS tags)

# &#x20;   │

# &#x20;   ▼

# output.baseline  (optional diff against previous scan)

# &#x20;   │

# &#x20;   ├──►  output.console\_formatter  ──►  CLI output

# &#x20;   ├──►  output.pr\_formatter       ──►  GitHub PR comment

# &#x20;   ├──►  output.sarif\_merger       ──►  report.sarif

# &#x20;   └──►  storage.db                ──►  SQLite

# &#x20;                                         │

# &#x20;                                         ▼

# &#x20;                                   web.app (FastAPI dashboard)

# ```

# 

# \### Project layout

# 

# ```

# secure-scan/

# ├── analyzers/     Semgrep integration and analyzer dispatch

# ├── compliance/    CWE → OWASP / PCI DSS lookup table

# ├── config/        YAML config loader

# ├── output/        SARIF builder, console/PR formatters, baseline diff

# ├── storage/       SQLAlchemy models and SQLite persistence

# ├── cli/           argparse entry point (scan / baseline-save / serve)

# ├── web/           FastAPI dashboard + Jinja2 template

# ├── tests/         pytest suite (6 tests)

# └── .github/       CI workflow that uploads SARIF on every PR

# ```

# 

# \---

# 

# \## Testing

# 

# ```bash

# python -m pytest tests/test\_scanner.py -v

# ```

# 

# Expected output: \*\*6 passed\*\*.

# 

# \---

# 

# \## CI/CD integration

# 

# The repository ships with `.github/workflows/secure-scan.yml`, which runs on every push to `main` and every pull request. It:

# 

# 1\. Installs `secure-scan` and Semgrep

# 2\. Runs the scanner against the workspace

# 3\. Uploads the resulting SARIF to the \*\*GitHub Security tab\*\* via `github/codeql-action/upload-sarif`

# 

# This makes secure coding review part of the standard PR workflow without additional tooling.

# 

# \---

# 

# \## License

# 

# Internal corporate use.

