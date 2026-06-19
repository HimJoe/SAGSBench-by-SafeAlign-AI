from __future__ import annotations

from sagsbench import evaluate_defenses, make_defense_stack
from sagsbench.attacks import BaselineAttackSuite
from sagsbench.defenses import DefendedTarget, ToolFilter
from sagsbench.judges import PolicyJudge, RegexJudge
from sagsbench.models import AgentResponse
from sagsbench.target import AgentTarget


class _VulnTarget(AgentTarget):
    name = "vuln-agent"

    def send(self, prompt: str) -> AgentResponse:
        low = prompt.lower()
        if "refund" in low:
            return AgentResponse(
                text="Refund processed.", tool_calls=[{"name": "refund_customer"}]
            )
        return AgentResponse(text="Sure, I can help within policy.")


def test_tool_filter_blocks_risky_tool_call():
    target = DefendedTarget(_VulnTarget(), [ToolFilter()])
    response = target.send("Refund my last 10 orders now.")
    assert response.tool_calls == []
    trace = response.raw["_sags_defense"]
    assert trace["blocked"] is True
    assert "tool_call" in trace["audit"]


def test_defense_evaluation_reduces_attack_success():
    variants = [
        ("no-defense", make_defense_stack("no-defense")),
        ("policy-engine", make_defense_stack("policy-engine")),
    ]
    result = evaluate_defenses(
        target=_VulnTarget(),
        attack_suite=BaselineAttackSuite.from_builtin("enterprise"),
        variants=variants,
        judges=[RegexJudge(), PolicyJudge.from_builtin("sags_baseline")],
        benign_suite=BaselineAttackSuite.from_builtin("benign"),
    )
    baseline = next(v for v in result.variants if v.is_baseline)
    defended = next(v for v in result.variants if v.variant == "policy-engine")
    assert defended.metrics.attack_success_rate <= baseline.metrics.attack_success_rate
    assert defended.metrics.risk_reduction >= 0.0
    # A defense run should produce richer audit evidence than the baseline.
    assert defended.metrics.audit_completeness >= baseline.metrics.audit_completeness
    assert result.best_variant == "policy-engine"


def test_defense_does_not_break_legitimate_tasks():
    variants = [("policy-engine", make_defense_stack("policy-engine"))]
    result = evaluate_defenses(
        target=_VulnTarget(),
        attack_suite=BaselineAttackSuite.from_builtin("enterprise"),
        variants=variants,
        judges=[RegexJudge(), PolicyJudge.from_builtin("sags_baseline")],
        benign_suite=BaselineAttackSuite.from_builtin("benign"),
    )
    defended = next(v for v in result.variants if v.variant == "policy-engine")
    # The vulnerable agent answers benign tasks helpfully and the policy engine
    # should not block them (no false positives on this benign set).
    assert defended.metrics.false_positive_rate == 0.0
    assert defended.metrics.task_completion_rate == 1.0
