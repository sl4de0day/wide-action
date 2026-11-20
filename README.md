<p align="center">
  <img src="assets/wide-logo.png" alt="Wide Action" width="128">
  <h1 align="center">Wide Action</h1>
  <p align="center">Wide's security rules as a pull request gate in GitHub CI, with AI-suggested fixes</p>
</p>

<p align="center">
  <a href="https://github.com/sl4de0day/wide-action/releases/latest">Release</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#building-from-source">Build</a> ·
  <a href="https://github.com/sl4de0day/wide-action/releases">Changelog</a> ·
  <a href="https://github.com/sl4de0day/wide-ide">Wide IDE</a> ·
  <a href="https://github.com/sl4de0day/wide-cli">Wide CLI</a> ·
  <a href="https://github.com/sl4de0day/wide-app">Wide App</a> ·
  <a href="https://github.com/sl4de0day/wide-sdk">Wide SDK</a> ·
  <a href="https://github.com/sl4de0day/wide-rules">Wide Rules</a> ·
  <a href="LICENSE">License</a>
</p>

---

> **Wide blends web development and web security into one AI-powered workflow.** Write the code, catch the vulnerability, and test the fix in the same place.

**Wide Action is the official GitHub Action for the Wide ecosystem that brings static application security testing (SAST), software composition analysis (SCA), differential pull request auditing, and autonomous AI-assisted vulnerability remediation directly into CI/CD pipelines. Running with zero external runtime dependencies on Node 24, it enforces security gates, writes GitHub Step Summaries, and posts contextual inline code review comments with automated fix suggestions.**

Wide Action is designed for rapid execution and seamless pull request integration:
- **Zero-Dependency Runner:** Pre-compiled Node 24 bundle executing directly inside the GitHub Actions runner without npm install overhead, embedding the full Wide Rules catalog (750+ rules) and OSV advisory bundle (800+ advisories).
- **Differential Scanning:** Analyzes only modified files and git diff hunks to keep pull request checks fast and developer-friendly.
- **Ecosystem Integration:** Shares AST/regex security patterns, AI agent guardrails, OSV/KEV/EPSS feeds, and SARIF reporting across Wide IDE, Wide CLI, and Wide SDK.

## Features

- **Differential Code Inspection.** Scans only added or modified lines in pull requests (covering JS/TS, Vue, Svelte, Python, PHP, Go, Java, Kotlin, Scala, C/C++, C#, Rust, Ruby, SQL, YAML, JSON, and Dockerfile) to eliminate legacy codebase noise.
- **Built-In OSV SCA Scanning.** Audits `package.json`, `package-lock.json`, `requirements.txt`, `go.mod`, `Cargo.toml`, and `pom.xml` against embedded or remote OSV/KEV/EPSS advisories.
- **CI/CD Security Gate & Step Summary.** Enforces configurable failure thresholds (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NEVER`), publishes GitHub Job Summaries, and creates optional Check Runs when `checks: write` is granted.
- **Inline Review Comments & Deduplication.** Publishes actionable security findings strictly on PR diff lines via the GitHub Pull Request Review API and tracks markers to prevent spam across subsequent commits.
- **Autonomous AI Remediation.** Employs AI models (Gemini, Claude, DeepSeek, OpenAI) with bounded concurrency, candidate quality scoring, and `wide-rules` agent guardrails to generate one-click GitHub suggested change blocks.
- **SARIF 2.1.0 Export.** Generates OASIS SARIF reports with sensitive credential masking for native integration with GitHub Advanced Security and Code Scanning dashboards.
- **Verified Dynamic Rules & Feeds.** Loads updated remote rules and OSV bundles from `wide-rules` with mandatory upstream `SHA256SUMS` verification and automatic fallback to embedded artifacts.
- **Retry Resilience.** Native HTTP exponential backoff and rate-limit retry handling for robust CI/CD execution.

## Quick Start

### 1. Basic Pull Request Audit

Add Wide Action to `.github/workflows/security.yml`:

```yaml
name: Security Audit

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Wide Security Action
        uses: sl4de0day/wide-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: HIGH
          only-diff: true
          sca: true
          sarif: true
```

### 2. With Autonomous AI Remediation

```yaml
      - name: Run Wide Security Action with AI Remediation
        uses: sl4de0day/wide-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: HIGH
          only-diff: true
          ai-remediation: true
          provider: gemini
          api-key: ${{ secrets.GEMINI_API_KEY }}
```

## Inputs

| Input | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `github-token` | Yes | `${{ github.token }}` | GitHub token for posting review comments, optional check runs, and summary reports |
| `fail-on` | No | `HIGH` | Vulnerability severity threshold to fail CI (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NEVER`) |
| `only-diff` | No | `true` | Scan only modified files and changed line hunks in pull requests |
| `ai-remediation` | No | `false` | Generate automated AI code fixes and review suggestions |
| `provider` | No | `gemini` | AI model provider for remediation (`gemini`, `claude`, `deepseek`, `openai`) |
| `model` | No | `""` | Optional AI model override for the selected provider |
| `api-key` | No | `""` | API key for the selected AI provider |
| `sarif` | No | `true` | Generate SARIF 2.1.0 report for GitHub Advanced Security |
| `output-path` | No | `wide-results.sarif` | File path to write the SARIF report |
| `rules` | No | `embedded` | Rule source to load (`embedded`, `latest`, or path to `rules.json`) |
| `sca` | No | `true` | Scan dependency manifests against embedded or fetched OSV advisories |
| `check-run` | No | `true` | Publish an optional GitHub Check Run when `checks: write` permission is granted |

## Outputs

| Output | Description |
| :--- | :--- |
| `findings-count` | Total number of detected vulnerabilities |
| `critical-count` | Number of critical severity vulnerabilities |
| `high-count` | Number of high severity vulnerabilities |
| `medium-count` | Number of medium severity vulnerabilities |
| `low-count` | Number of low severity vulnerabilities |
| `sca-count` | Number of vulnerable dependencies detected by OSV SCA scan |
| `sarif-path` | File path to the generated SARIF report |

## Building from source

Requirements:
- Node.js 20 or newer
- npm

```bash
git clone https://github.com/sl4de0day/wide-action.git
cd wide-action
npm install
npm test
npm run build
```

## The Wide Ecosystem

Wide blends web development and web security into one AI-powered workflow. Every product runs on the same security rules, so a vulnerability caught in one place is caught everywhere.

| Product | Who it is for |
| :--- | :--- |
| [Wide IDE](https://github.com/sl4de0day/wide-ide) | **The flagship.** A full IDE for web developers and pentesters: write code, see vulnerabilities as you type, and test them with built-in pentest tools and AI agents. |
| [Wide App](https://github.com/sl4de0day/wide-app) | A prompt-only AI workspace for people who do not need a full IDE. Describe the task; Wide's agents build, fix, and audit the project. |
| [Wide CLI](https://github.com/sl4de0day/wide-cli) | The same AI agents and security scanner in your terminal. |
| [Wide Action](https://github.com/sl4de0day/wide-action) | The same rules as a pull request security gate in GitHub CI. |
| [Wide SDK](https://github.com/sl4de0day/wide-sdk) | A Python library for building your own agents on Wide's security tooling. |
| [Wide Rules](https://github.com/sl4de0day/wide-rules) | The shared rule and advisory database behind every Wide product. |

## License

Wide Action is free software licensed under the [MIT License](LICENSE).

Copyright (c) 2026 sl4de0day.
