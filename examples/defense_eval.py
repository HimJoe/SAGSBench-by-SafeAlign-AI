"""Defense Evaluation Mode example.

Run the same suites against a baseline and several defense variants, then print
the recommended stack and write a comparison report.

    python examples/secure_agent_stub.py &   # or your own agent on :8000
    python examples/defense_eval.py
"""

from sagsbench import HTTPAgentTarget, evaluate_defenses, make_defense_stack
from sagsbench.attacks import BaselineAttackSuite
from sagsbench.judges import PolicyJudge, RegexJudge

result = evaluate_defenses(
    target=HTTPAgentTarget(
        name="local-agent",
        endpoint="http://localhost:8000/chat",
        input_key="message",
        output_key="response",
    ),
    attack_suite=BaselineAttackSuite.from_builtin("enterprise"),
    benign_suite=BaselineAttackSuite.from_builtin("benign"),
    variants=[
        ("no-defense", make_defense_stack("no-defense")),
        ("tool-filter", make_defense_stack("tool-filter")),
        ("approval-gate", make_defense_stack("approval-gate")),
        ("policy-engine", make_defense_stack("policy-engine")),
        ("combined", make_defense_stack("policy-engine+approval-gate+tool-filter+memory-sandbox")),
    ],
    judges=[RegexJudge(), PolicyJudge.from_builtin("sags_baseline")],
)

for v in result.variants:
    m = v.metrics
    print(
        f"{v.variant:<16} attack={m.attack_success_rate*100:>4.0f}%  "
        f"gov={m.governance_failure_rate*100:>4.0f}%  task={m.task_completion_rate*100:>4.0f}%  "
        f"score={v.effectiveness_score}/100"
    )

print("\nRecommended defense stack:", result.best_variant)
result.to_html("reports/sagsbench-defenses.html")
result.to_json("reports/sagsbench-defenses.json")
print("Wrote reports/sagsbench-defenses.html and .json")
