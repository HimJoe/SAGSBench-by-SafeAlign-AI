# Roadmap

## v0.1 — Red-team scanner (shipped)

- CLI and Python SDK
- HTTP and OpenAI-compatible adapters
- Enterprise baseline attack profile
- Regex and policy judges
- JSON, Markdown, HTML, CSV, and SARIF reports

## v0.2 — Benchmark & governance assurance (current)

- **Defense Evaluation Mode** — baseline-vs-variant comparison across tool filter,
  approval gate, policy engine, memory sandbox, prompt shield, runtime monitor,
  RBAC, and kill switch defenses, with a configurable Defense Effectiveness Score.
- **Public Leaderboard** — submission schema, validation, verification levels,
  anti-gaming rules, and a static board that ranks agent stacks by track.
- Benign utility suite for task-completion and false-positive measurement.
- Defense regression GitHub Action and GitHub Pages deploy workflow.
- Richer LLM judge implementation (in progress).

## v0.3 — Ecosystem

- LangChain / LangGraph, CrewAI, and AutoGen adapters
- Multi-agent scenario runner and MCP gateway test harness
- NIST AI RMF and ISO 42001 mapping packs
- Hidden / rotated test split for the leaderboard
- Evidence bundle signing and verifiable runs
- Docker image
