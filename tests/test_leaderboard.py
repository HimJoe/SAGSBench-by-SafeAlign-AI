from __future__ import annotations

import json
from pathlib import Path

from sagsbench.leaderboard import (
    build_leaderboard_html,
    load_submissions,
    rank_submissions,
    validate_submission,
)

VALID = {
    "schema_version": "1.0",
    "agent_stack": {
        "name": "Test Stack",
        "architecture": "planner-executor",
        "framework": "LangGraph",
        "model": "Anthropic Claude",
        "defenses": ["policy-engine", "approval-gate"],
    },
    "benchmark": {"version": "0.2.0", "suite_version": "enterprise-2026.05", "policy_version": "v0.1"},
    "scores": {
        "overall_sags": 89,
        "security": 90,
        "governance": 92,
        "utility": 81,
        "auditability": 95,
        "defense_effectiveness": 88,
    },
    "track": "finance-procurement",
    "reproducibility": "maintainer-verified",
}


def test_valid_submission_passes():
    assert validate_submission(VALID) == []


def test_missing_fields_are_reported():
    bad = json.loads(json.dumps(VALID))
    del bad["scores"]["governance"]
    bad["track"] = "not-a-track"
    errors = validate_submission(bad)
    assert any("governance" in e for e in errors)
    assert any("track" in e for e in errors)


def test_anti_gaming_requires_utility():
    bad = json.loads(json.dumps(VALID))
    bad["scores"]["utility"] = 5
    bad["scores"]["overall_sags"] = 90
    errors = validate_submission(bad)
    assert any("utility" in e.lower() for e in errors)


def test_seed_submissions_load_and_rank():
    root = Path(__file__).resolve().parents[1]
    subs = load_submissions(root / "leaderboard" / "submissions")
    assert subs, "expected seed submissions to load"
    ranked = rank_submissions(subs)
    finance = ranked["finance-procurement"]
    # Sorted by overall SAGS score descending.
    assert finance == sorted(finance, key=lambda s: s["scores"]["overall_sags"], reverse=True)
    page = build_leaderboard_html(subs)
    assert "SAGSBench" in page
    assert "LangGraph Finance Agent" in page
