from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from sagsbench.adapters import HTTPAgentTarget, OpenAICompatibleTarget
from sagsbench.attacks import BaselineAttackSuite
from sagsbench.campaign import Campaign
from sagsbench.defense_eval import evaluate_defenses
from sagsbench.defenses import make_defense_stack
from sagsbench.judges import PolicyJudge, RegexJudge
from sagsbench.models import CampaignResult

console = Console()


@click.group()
def cli() -> None:
    """SAGSBench: open-source red teaming for agentic AI governance."""


@cli.command()
def init() -> None:
    """Create local reports and config folders."""
    Path("reports").mkdir(exist_ok=True)
    Path("sagsbench.yaml").write_text(
        "profile: enterprise\nreports: [html, json, markdown, sarif, csv]\n",
        encoding="utf-8",
    )
    console.print("[bold green]Initialized SAGSBench project.[/bold green]")


@cli.command("list-profiles")
def list_profiles() -> None:
    """List built-in attack profiles."""
    table = Table(title="Built-in SAGSBench profiles")
    table.add_column("Profile")
    table.add_column("Description")
    table.add_row("enterprise", "General enterprise agentic AI red-team suite")
    console.print(table)


@cli.command()
@click.option("--target", required=False, help="HTTP endpoint for the target agent.")
@click.option("--target-name", default="agent-under-test", show_default=True)
@click.option("--input-key", default="message", show_default=True)
@click.option("--output-key", default="response", show_default=True)
@click.option("--profile", default="enterprise", show_default=True)
@click.option("--report", "reports", default="html,json,markdown", show_default=True)
@click.option("--openai-model", default=None, help="Use an OpenAI-compatible model as the target.")
@click.option("--openai-base-url", default=None)
def scan(
    target: str | None,
    target_name: str,
    input_key: str,
    output_key: str,
    profile: str,
    reports: str,
    openai_model: str | None,
    openai_base_url: str | None,
) -> None:
    """Run a red-team scan against an agent target."""
    if openai_model:
        agent_target = OpenAICompatibleTarget(
            name=target_name,
            model=openai_model,
            base_url=openai_base_url,
        )
    elif target:
        agent_target = HTTPAgentTarget(
            name=target_name,
            endpoint=target,
            input_key=input_key,
            output_key=output_key,
        )
    else:
        raise click.UsageError("Provide --target for HTTP or --openai-model for OpenAI-compatible target.")

    campaign = Campaign(
        target=agent_target,
        suites=[BaselineAttackSuite.from_builtin(profile)],
        judges=[RegexJudge(), PolicyJudge.from_builtin("sags_baseline")],
    )
    result = campaign.run(show_progress=True)
    write_reports(result, reports.split(","))
    print_summary(result)


@cli.command()
@click.option("--input", "input_path", required=True, type=click.Path(exists=True))
@click.option("--format", "fmt", default="markdown", show_default=True)
def report(input_path: str, fmt: str) -> None:
    """Regenerate a report from JSON results."""
    result = CampaignResult(**json.loads(Path(input_path).read_text(encoding="utf-8")))
    write_reports(result, [fmt])
    console.print(f"[green]Wrote {fmt} report.[/green]")


@cli.command("list-defenses")
def list_defenses() -> None:
    """List built-in defenses for Defense Evaluation Mode."""
    from sagsbench.defenses import DEFENSE_REGISTRY

    table = Table(title="Built-in SAGSBench defenses")
    table.add_column("Name")
    table.add_column("Category")
    for name, cls in sorted(DEFENSE_REGISTRY.items()):
        table.add_row(name, getattr(cls, "category", ""))
    console.print(table)


@cli.command("evaluate-defenses")
@click.option("--target", required=False, help="HTTP endpoint for the target agent.")
@click.option("--target-name", default="agent-under-test", show_default=True)
@click.option("--input-key", default="message", show_default=True)
@click.option("--output-key", default="response", show_default=True)
@click.option("--openai-model", default=None, help="Use an OpenAI-compatible model as the target.")
@click.option("--openai-base-url", default=None)
@click.option("--suite", default="enterprise", show_default=True, help="Attack profile.")
@click.option("--baseline", default="no-defense", show_default=True)
@click.option(
    "--variant",
    "variants",
    multiple=True,
    help="Defense variant spec, repeatable. e.g. --variant tool-filter --variant policy-engine+approval-gate",
)
@click.option("--report", "reports", default="html,json,csv", show_default=True)
def evaluate_defenses_cmd(
    target: str | None,
    target_name: str,
    input_key: str,
    output_key: str,
    openai_model: str | None,
    openai_base_url: str | None,
    suite: str,
    baseline: str,
    variants: tuple[str, ...],
    reports: str,
) -> None:
    """Run the same suite against a baseline and one or more defense variants."""
    if openai_model:
        agent_target = OpenAICompatibleTarget(
            name=target_name, model=openai_model, base_url=openai_base_url
        )
    elif target:
        agent_target = HTTPAgentTarget(
            name=target_name, endpoint=target, input_key=input_key, output_key=output_key
        )
    else:
        raise click.UsageError("Provide --target for HTTP or --openai-model for OpenAI-compatible target.")

    if not variants:
        variants = ("tool-filter", "approval-gate", "policy-engine", "policy-engine+approval-gate")

    variant_stacks = [(baseline, make_defense_stack(baseline))]
    for spec in variants:
        variant_stacks.append((spec, make_defense_stack(spec)))

    result = evaluate_defenses(
        target=agent_target,
        attack_suite=BaselineAttackSuite.from_builtin(suite),
        variants=variant_stacks,
        judges=[RegexJudge(), PolicyJudge.from_builtin("sags_baseline")],
        benign_suite=BaselineAttackSuite.from_builtin("benign"),
    )
    write_defense_reports(result, reports.split(","))
    print_defense_summary(result)


def write_defense_reports(result, report_types: list[str]) -> None:
    out = Path("reports")
    out.mkdir(exist_ok=True)
    normalized = {item.strip().lower() for item in report_types}
    if "json" in normalized:
        result.to_json(out / "sagsbench-defenses.json")
    if "html" in normalized:
        result.to_html(out / "sagsbench-defenses.html")
    if "csv" in normalized:
        result.to_csv(out / "sagsbench-defenses.csv")
    if "markdown" in normalized or "md" in normalized:
        result.to_markdown(out / "sagsbench-defenses.md")


def print_defense_summary(result) -> None:
    table = Table(title="Defense Evaluation — comparison")
    table.add_column("Variant")
    table.add_column("Attack success")
    table.add_column("Gov. failures")
    table.add_column("Task completion")
    table.add_column("Effectiveness")
    for v in result.variants:
        m = v.metrics
        table.add_row(
            v.variant,
            f"{m.attack_success_rate * 100:.0f}%",
            f"{m.governance_failure_rate * 100:.0f}%",
            f"{m.task_completion_rate * 100:.0f}%",
            f"{v.effectiveness_score}/100",
        )
    console.print(table)
    if result.best_variant:
        console.print(f"[bold green]Recommended defense stack: {result.best_variant}[/bold green]")


@cli.group()
def leaderboard() -> None:
    """Validate and build SAGSBench public leaderboard submissions."""


@leaderboard.command("validate")
@click.argument("path", type=click.Path(exists=True))
def leaderboard_validate(path: str) -> None:
    """Validate a leaderboard submission JSON file."""
    from sagsbench.leaderboard import validate_submission

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    errors = validate_submission(data)
    if errors:
        console.print("[bold red]Submission is invalid:[/bold red]")
        for err in errors:
            console.print(f"  - {err}")
        raise SystemExit(1)
    console.print("[bold green]Submission is valid.[/bold green]")


@leaderboard.command("build")
@click.option("--submissions", default="leaderboard/submissions", show_default=True, type=click.Path())
@click.option("--output", default="frontend/leaderboard.html", show_default=True, type=click.Path())
def leaderboard_build(submissions: str, output: str) -> None:
    """Build the static leaderboard page from submission files."""
    from sagsbench.leaderboard import build_leaderboard_html, load_submissions

    subs = load_submissions(submissions)
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(build_leaderboard_html(subs), encoding="utf-8")
    console.print(f"[green]Wrote leaderboard with {len(subs)} submissions to {output}.[/green]")


def write_reports(result: CampaignResult, report_types: list[str]) -> None:
    out = Path("reports")
    out.mkdir(exist_ok=True)
    normalized = {item.strip().lower() for item in report_types}
    if "json" in normalized:
        result.to_json(out / "sagsbench-results.json")
    if "markdown" in normalized or "md" in normalized:
        result.to_markdown(out / "sagsbench-report.md")
    if "html" in normalized:
        result.to_html(out / "sagsbench-report.html")
    if "csv" in normalized:
        result.to_csv(out / "sagsbench-summary.csv")
    if "sarif" in normalized:
        result.to_sarif(out / "sagsbench.sarif")


def print_summary(result: CampaignResult) -> None:
    summary = result.summary or result.compute_summary()
    table = Table(title="SAGSBench Summary")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Target", result.target_name)
    table.add_row("SAGS Score", f"{summary['sags_score']}/100")
    table.add_row("Tests", str(summary["total"]))
    table.add_row("Passed", str(summary["passed"]))
    table.add_row("Failed", str(summary["failed"]))
    table.add_row("Attack Success Rate", f"{summary['attack_success_rate'] * 100:.1f}%")
    console.print(table)


if __name__ == "__main__":
    cli()
