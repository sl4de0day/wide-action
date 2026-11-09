<p align="center">
  <img src="assets/wide-logo.png" alt="Wide Action" width="128">
  <h1 align="center">Wide Action</h1>
  <p align="center">CI/CD-first autonomous security gate and pull request auditor for the Wide ecosystem</p>
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
  <a href="LICENSE">License</a>
</p>

---

**Wide Action is the official GitHub Action for the Wide ecosystem that brings static application security testing (SAST), differential pull request auditing, and autonomous AI-assisted vulnerability remediation directly into CI/CD pipelines. Running with zero external runtime dependencies on Node 20, it enforces security gates and posts contextual inline code review comments with automated fix suggestions.**

Wide Action is designed for rapid execution and seamless pull request integration:
- **Zero-Dependency Runner:** Pre-compiled Node 20 bundle executing directly inside the GitHub Actions runner without npm install overhead.
- **Differential Scanning:** Analyzes only modified files and git diff hunks to keep pull request checks fast and developer-friendly.
- **Ecosystem Integration:** Shares AST inspection patterns, security rules, and taint flow definitions across Wide IDE, Wide CLI, and Wide Action.

## Features

- **Differential Code Inspection.** Scans only added or modified lines in pull requests to eliminate legacy codebase noise and focus strictly on newly introduced changes.
- **CI/CD Security Gate.** Enforces configurable failure thresholds (CRITICAL, HIGH, MEDIUM, LOW) to block vulnerable code before merge.
- **Inline Review Comments.** Publishes actionable security findings directly on affected lines via the GitHub Pull Request Review API.
- **Autonomous AI Remediation.** Employs AI models (Gemini, Claude, DeepSeek, OpenAI) to generate one-click GitHub suggested change blocks for automated developer patching.
- **SARIF 2.1.0 Export.** Generates OASIS SARIF reports for native integration with GitHub Advanced Security and Code Scanning dashboards.
- **Anti-Spam Deduplication.** Updates existing summary comments and tracks posted review items to prevent pull request noise across subsequent commits.

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
        uses: sl4de0day/wide-action@v0.191126
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: HIGH
          only-diff: true
          sarif: true
```

### 2. With Autonomous AI Remediation

```yaml
      - name: Run Wide Security Action with AI Remediation
        uses: sl4de0day/wide-action@v0.191126
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
| `github-token` | Yes | `${{ github.token }}` | GitHub token for posting review comments and summary reports |
| `fail-on` | No | `HIGH` | Vulnerability severity threshold to fail CI (CRITICAL, HIGH, MEDIUM, LOW, NEVER) |
| `only-diff` | No | `true` | Scan only modified files and changed line hunks in pull requests |
| `ai-remediation` | No | `false` | Generate automated AI code fixes and review suggestions |
| `provider` | No | `gemini` | AI model provider for remediation (gemini, claude, deepseek, openai) |
| `api-key` | No | `""` | API key for the selected AI provider |
| `sarif` | No | `true` | Generate SARIF 2.1.0 report for GitHub Advanced Security |
| `output-path` | No | `wide-results.sarif` | File path to write the SARIF report |

## Outputs

| Output | Description |
| :--- | :--- |
| `findings-count` | Total number of detected vulnerabilities |
| `critical-count` | Number of critical severity vulnerabilities |
| `high-count` | Number of high severity vulnerabilities |
| `medium-count` | Number of medium severity vulnerabilities |
| `low-count` | Number of low severity vulnerabilities |
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

## License

Wide Action is free software licensed under the [MIT License](LICENSE).

Copyright (c) 2026 sl4de0day.
