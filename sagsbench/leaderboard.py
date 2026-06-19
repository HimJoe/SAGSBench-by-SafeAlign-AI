"""SAGSBench Public Leaderboard tooling.

The leaderboard ranks *agent stacks and governance architectures* — model +
framework + tools + memory + approval flow + policy layer + monitoring — not
just foundation models. This module validates community submissions produced by
the SAGSBench CLI and builds the static, dependency-free leaderboard page that
ships under ``frontend/leaderboard.html``.

See ``docs/LEADERBOARD.md`` for the submission and verification workflow.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"

TRACKS = {
    "customer-support": "Customer Support",
    "finance-procurement": "Finance / Procurement",
    "hr": "HR Agent",
    "devops-sre": "DevOps / SRE",
    "multi-agent-governance": "Multi-agent Governance",
}

REPRODUCIBILITY_LEVELS = {
    "self-reported": "Self-reported",
    "reproducible": "Reproducible",
    "community-reproduced": "Community verified",
    "maintainer-verified": "Verified",
    "enterprise-private": "Private",
}

REQUIRED_SCORES = (
    "overall_sags",
    "security",
    "governance",
    "utility",
    "auditability",
    "defense_effectiveness",
)


def validate_submission(data: dict[str, Any]) -> list[str]:
    """Return a list of human-readable validation errors (empty == valid)."""

    errors: list[str] = []

    if not isinstance(data, dict):
        return ["Submission must be a JSON object."]

    stack = data.get("agent_stack")
    if not isinstance(stack, dict):
        errors.append("Missing 'agent_stack' object.")
    else:
        for key in ("name", "architecture", "framework", "model"):
            if not stack.get(key):
                errors.append(f"agent_stack.{key} is required.")
        if "defenses" in stack and not isinstance(stack["defenses"], list):
            errors.append("agent_stack.defenses must be a list.")

    benchmark = data.get("benchmark")
    if not isinstance(benchmark, dict):
        errors.append("Missing 'benchmark' object.")
    else:
        for key in ("version", "suite_version", "policy_version"):
            if not benchmark.get(key):
                errors.append(f"benchmark.{key} is required (anti-gaming: versions must be declared).")

    scores = data.get("scores")
    if not isinstance(scores, dict):
        errors.append("Missing 'scores' object.")
    else:
        for key in REQUIRED_SCORES:
            value = scores.get(key)
            if value is None:
                errors.append(f"scores.{key} is required.")
            elif not isinstance(value, (int, float)) or not (0 <= value <= 100):
                errors.append(f"scores.{key} must be a number between 0 and 100.")

    track = data.get("track")
    if track not in TRACKS:
        errors.append(f"track must be one of: {', '.join(TRACKS)}.")

    level = data.get("reproducibility")
    if level not in REPRODUCIBILITY_LEVELS:
        errors.append(f"reproducibility must be one of: {', '.join(REPRODUCIBILITY_LEVELS)}.")

    # Anti-gaming: a high score must be backed by completed legitimate tasks.
    if isinstance(scores, dict):
        utility = scores.get("utility", 0)
        overall = scores.get("overall_sags", 0)
        if isinstance(utility, (int, float)) and isinstance(overall, (int, float)):
            if overall >= 70 and utility < 40:
                errors.append(
                    "Anti-gaming: a high Overall SAGS score requires real task utility "
                    "(utility >= 40). Agents cannot rank highly by refusing everything."
                )

    return errors


def load_submissions(directory: str | Path) -> list[dict[str, Any]]:
    """Load and validate every submission JSON file under ``directory``.

    Invalid or private submissions are skipped (private ones never appear on the
    public board). Each returned record is annotated with its source filename.
    """

    directory = Path(directory)
    submissions: list[dict[str, Any]] = []
    for file in sorted(directory.glob("*.json")):
        data = json.loads(file.read_text(encoding="utf-8"))
        errors = validate_submission(data)
        if errors:
            continue
        if data.get("reproducibility") == "enterprise-private":
            continue
        data.setdefault("_source", file.name)
        submissions.append(data)
    return submissions


def rank_submissions(submissions: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group submissions by track and sort by Overall SAGS score descending."""

    by_track: dict[str, list[dict[str, Any]]] = {key: [] for key in TRACKS}
    for sub in submissions:
        by_track.setdefault(sub["track"], []).append(sub)
    for track in by_track:
        by_track[track].sort(key=lambda s: s["scores"]["overall_sags"], reverse=True)
    return by_track


def _esc(value: Any) -> str:
    return html.escape(str(value))


def _rows(subs: list[dict[str, Any]]) -> str:
    rows = []
    for rank, sub in enumerate(subs, start=1):
        stack = sub["agent_stack"]
        scores = sub["scores"]
        level = sub.get("reproducibility", "self-reported")
        badge = REPRODUCIBILITY_LEVELS.get(level, level)
        defenses = ", ".join(stack.get("defenses", [])) or "none"
        rows.append(
            "<tr>"
            f"<td class='rank'>{rank}</td>"
            f"<td><b>{_esc(stack['name'])}</b><br><small>{_esc(stack['model'])} &middot; "
            f"{_esc(stack['framework'])}</small></td>"
            f"<td>{_esc(stack['architecture'])}</td>"
            f"<td><small>{_esc(defenses)}</small></td>"
            f"<td class='score'>{_esc(scores['overall_sags'])}</td>"
            f"<td>{_esc(scores['security'])}</td>"
            f"<td>{_esc(scores['governance'])}</td>"
            f"<td>{_esc(scores['utility'])}</td>"
            f"<td><span class='lb-badge lb-{_esc(level)}'>{_esc(badge)}</span></td>"
            "</tr>"
        )
    if not rows:
        return "<tr><td colspan='9' class='empty'>No public submissions yet — be the first.</td></tr>"
    return "\n".join(rows)


def build_leaderboard_html(submissions: list[dict[str, Any]]) -> str:
    """Render the full static leaderboard page (no scripts, CSP-safe)."""

    by_track = rank_submissions(submissions)
    sections = []
    for key, label in TRACKS.items():
        subs = by_track.get(key, [])
        sections.append(
            f"""
      <section class="lb-track section-pad" id="track-{key}">
        <div class="section-heading"><div class="eyebrow">Track</div><h2>{_esc(label)}</h2></div>
        <div class="lb-table-wrap">
          <table class="lb-table">
            <thead>
              <tr><th>#</th><th>Agent stack</th><th>Architecture</th><th>Defense stack</th>
              <th>SAGS</th><th>Sec.</th><th>Gov.</th><th>Utility</th><th>Status</th></tr>
            </thead>
            <tbody>
              {_rows(subs)}
            </tbody>
          </table>
        </div>
      </section>"""
        )
    track_nav = "\n".join(
        f'<a href="#track-{key}">{_esc(label)}</a>' for key, label in TRACKS.items()
    )

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests" />
    <meta name="referrer" content="strict-origin-when-cross-origin" />
    <meta http-equiv="X-Content-Type-Options" content="nosniff" />
    <title>SAGSBench Public Leaderboard | SafeAlign AI</title>
    <meta name="description" content="The SAGSBench public leaderboard ranks agent stacks and governance architectures by Safety, Alignment, Governance, and Security." />
    <link rel="icon" href="assets/favicon-64.png" type="image/png" />
    <link rel="stylesheet" href="assets/styles.css" />
  </head>
  <body>
    <a class="skip-link" href="#main">Skip to content</a>
    <header class="site-header" id="top">
      <a class="brand" href="index.html" aria-label="SAGSBench home">
        <img src="assets/safealign-ai-logo.png" alt="SafeAlign AI" class="brand-logo" />
        <span class="brand-copy"><strong>SAGSBench</strong><em>by SafeAlign AI</em></span>
      </a>
      <nav class="nav" id="site-nav" aria-label="Leaderboard tracks">
        {track_nav}
      </nav>
      <div class="header-actions">
        <a class="ghost" href="index.html">Home</a>
        <a class="button small" href="https://github.com/CoHumAInLabs/SAGSBench-by-SafeAlign-AI" rel="noopener noreferrer">GitHub</a>
      </div>
    </header>

    <main id="main">
      <section class="hero hero-solo section-pad">
        <div class="hero-copy reveal">
          <div class="eyebrow"><span class="status-dot"></span> community benchmark</div>
          <h1>SAGSBench <span>PUBLIC LEADERBOARD</span></h1>
          <p class="lead">Ranking agent stacks and governance architectures — not just models — by Safety, Alignment, Governance, and Security. Submit a SAGSBench report to compare your stack.</p>
          <div class="hero-actions">
            <a class="button" href="https://github.com/CoHumAInLabs/SAGSBench-by-SafeAlign-AI/blob/main/docs/LEADERBOARD.md" rel="noopener noreferrer">How to submit</a>
            <a class="ghost strong" href="index.html#defense">Defense Evaluation Mode</a>
          </div>
        </div>
      </section>
      {''.join(sections)}
    </main>

    <footer class="footer">
      <span>&copy; 2026 SafeAlign AI / COHUMAIN Labs</span>
      <a href="index.html">Home</a>
      <a href="https://safealignai.io/" rel="noopener noreferrer">safealignai.io</a>
      <a href="https://github.com/CoHumAInLabs/SAGSBench-by-SafeAlign-AI" rel="noopener noreferrer">GitHub</a>
    </footer>
  </body>
</html>
"""


__all__ = [
    "REPRODUCIBILITY_LEVELS",
    "SCHEMA_VERSION",
    "TRACKS",
    "build_leaderboard_html",
    "load_submissions",
    "rank_submissions",
    "validate_submission",
]
