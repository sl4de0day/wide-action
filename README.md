# Wide Action

Wide Action is the official GitHub Action for the Wide ecosystem, providing automated Static Application Security Testing (SAST), pull request diff analysis, and autonomous AI-assisted vulnerability remediation directly within CI/CD pipelines.

## Overview

Wide Action inspects pull requests and commits for security vulnerabilities, secrets, and code quality issues. It features differential scanning to analyze only modified lines, generates SARIF reports for GitHub Advanced Security, and posts contextual inline review comments with automated fix suggestions.

## Features

- Differential Analysis: Scans only modified files and changed line hunks to keep PR checks fast and lightweight.
- CI/CD Security Gate: Enforces configurable failure thresholds (CRITICAL, HIGH, MEDIUM, LOW) to block vulnerable code from merging.
- Inline Review Comments: Publishes actionable security findings directly on affected lines in GitHub Pull Requests.
- Autonomous Remediation: Generates GitHub suggested change blocks using AI models (Gemini, Claude, DeepSeek, OpenAI) for one-click developer patching.
- SARIF 2.1.0 Support: Seamless integration with GitHub Code Scanning and Security tabs.
- Zero-Dependency Runner: Pre-bundled with Node 20 runtime for instant execution without npm install overhead.

## Usage

### Quick Start

Add Wide Action to your repository workflow:

```yaml
name: Wide Security Audit

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
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Wide Security Audit
        uses: sl4de0day/wide-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: HIGH
          only-diff: true
          sarif: true
```

### With Autonomous AI Remediation

```yaml
      - name: Run Wide Security Audit with AI Remediation
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
| `github-token` | Yes | `${{ github.token }}` | GitHub token for posting comments, check runs, and reviews |
| `fail-on` | No | `HIGH` | Vulnerability severity threshold to fail CI (CRITICAL, HIGH, MEDIUM, LOW, NEVER) |
| `only-diff` | No | `true` | Scan only modified files and changed line hunks in the pull request |
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

## Ecosystem

Wide Action is part of the Wide security and development ecosystem:

- wide-ide: Full-featured desktop IDE for security auditing and development.
- wide-app: Lightweight desktop interface for AI security operations.
- wide-cli: Command-line scanner and security agent for terminals and scripts.
- wide-sdk: Core SDK and common runtime for the Wide ecosystem.
- wide-rules: Vulnerability patterns, AST rules, and detection queries.
- wide-action: Automated CI/CD PR reviewer and security gate.

## License

MIT
