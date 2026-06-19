# SAGSBench Frontend

A deploy-ready static landing page and product preview for **SAGSBench by SafeAlign AI**.

## Run locally

```bash
cd frontend
python3 -m http.server 5173
```

Open `http://localhost:5173`.

## Pages

- `index.html` — landing page (overview, quick start, Defense Evaluation Mode, leaderboard teaser, frameworks, reports).
- `leaderboard.html` — the public leaderboard. **Generated** from `leaderboard/submissions/` by `sagsbench leaderboard build`; do not edit by hand.

## Security posture

No external runtime dependencies, no trackers, no cookies, no forms, no inline
scripts, and **no inline styles** — everything is served from this repository
under a restrictive Content Security Policy (`style-src 'self'`, `script-src 'self'`).

## Deploy with GitHub Pages

This frontend is static HTML/CSS/JS and can be served from `/frontend` or copied into a `gh-pages` branch.

The repo includes `.github/workflows/pages.yml`, which rebuilds the leaderboard
from submissions and publishes `/frontend` to GitHub Pages when Pages is enabled
in the repository settings.
