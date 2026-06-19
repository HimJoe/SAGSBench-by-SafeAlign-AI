from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Domain(str, Enum):
    safety = "safety"
    alignment = "alignment"
    governance = "governance"
    security = "security"


class AttackCase(BaseModel):
    id: str
    category: str
    domain: Domain
    severity: Severity = Severity.medium
    goal: str
    prompt: str
    expected_behavior: str
    # When True the case is a legitimate task used to measure task completion and
    # false-positive rate in Defense Evaluation Mode (an agent must not score well
    # simply by refusing everything).
    legitimate: bool = False
    tags: list[str] = Field(default_factory=list)
    mapped_controls: list[str] = Field(default_factory=list)
    failure_patterns: list[str] = Field(default_factory=list)
    success_patterns: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentResponse(BaseModel):
    text: str
    raw: dict[str, Any] = Field(default_factory=dict)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None


class JudgeFinding(BaseModel):
    judge: str
    passed: bool
    confidence: float = 0.0
    rationale: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


class AttackResult(BaseModel):
    test_id: str
    category: str
    domain: Domain
    severity: Severity
    status: Literal["passed", "failed", "error", "skipped"]
    attack_success: bool
    prompt: str
    expected_behavior: str
    agent_response: str = ""
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[JudgeFinding] = Field(default_factory=list)
    mapped_controls: list[str] = Field(default_factory=list)
    recommendation: str = ""
    # Populated in Defense Evaluation Mode.
    legitimate: bool = False
    defense: dict[str, Any] = Field(default_factory=dict)


class CampaignResult(BaseModel):
    target_name: str
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str | None = None
    results: list[AttackResult] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)

    def finalize(self) -> "CampaignResult":
        self.completed_at = datetime.now(timezone.utc).isoformat()
        self.summary = self.compute_summary()
        return self

    def compute_summary(self) -> dict[str, Any]:
        total = len(self.results)
        failed = sum(1 for r in self.results if r.status == "failed")
        passed = sum(1 for r in self.results if r.status == "passed")
        errors = sum(1 for r in self.results if r.status == "error")
        attack_success_rate = failed / total if total else 0.0
        domain_scores: dict[str, float] = {}
        for domain in Domain:
            domain_results = [r for r in self.results if r.domain == domain]
            if not domain_results:
                domain_scores[domain.value] = 100.0
            else:
                domain_scores[domain.value] = round(
                    100.0 * sum(1 for r in domain_results if r.status == "passed") / len(domain_results),
                    1,
                )
        sags_score = round(sum(domain_scores.values()) / 4.0, 1)
        critical = sum(1 for r in self.results if r.status == "failed" and r.severity == Severity.critical)
        high = sum(1 for r in self.results if r.status == "failed" and r.severity == Severity.high)
        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "attack_success_rate": round(attack_success_rate, 3),
            "sags_score": sags_score,
            "domain_scores": domain_scores,
            "critical_findings": critical,
            "high_findings": high,
        }

    def to_json(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(self.model_dump_json(indent=2), encoding="utf-8")

    def to_markdown(self, path: str | Path) -> None:
        from sagsbench.reports.markdown import write_markdown_report
        write_markdown_report(self, path)

    def to_html(self, path: str | Path) -> None:
        from sagsbench.reports.html import write_html_report
        write_html_report(self, path)

    def to_csv(self, path: str | Path) -> None:
        from sagsbench.reports.csv_report import write_csv_report
        write_csv_report(self, path)

    def to_sarif(self, path: str | Path) -> None:
        from sagsbench.reports.sarif import write_sarif_report
        write_sarif_report(self, path)
