# SAGSBench Leaderboard Submissions

This directory holds community submissions for the SAGSBench public leaderboard,
which ranks **agent stacks and governance architectures**, not just models.

- `schema/submission.schema.json` — JSON Schema for a submission.
- `submissions/*.json` — one file per submission (seed examples included).

## Add your stack

1. Copy any file in `submissions/` and edit the values.
2. Validate it: `sagsbench leaderboard validate submissions/your-stack.json`
3. Open a pull request. Merging rebuilds `frontend/leaderboard.html`.

See [`docs/LEADERBOARD.md`](../docs/LEADERBOARD.md) for tracks, verification
levels, and anti-gaming rules.
