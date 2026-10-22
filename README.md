# Veylith

**From external threat to customer-specific investigation.**
Veylith is an evidence-driven, third-party incident impact intelligence platform for MSPs and security teams. It maps vendors,
products, assets and clients into an exposure graph, ingests security advisories (NIST NVD, CISA KEV), matches them
deterministically against what you actually run, explains each potential impact with evidence and uncertainty, and
carries the finding through cases, tasks, evidence and PDF reports.

> A matched advisory is **potential impact**, never an automatic claim of compromise.

## Quick start

```bash
cp .env.example .env
docker compose up -d --build
# http://localhost:3000  → create a workspace, or seed a clearly-synthetic demo organization:
docker compose run --rm -e DEMO_PASSWORD='Choose-A-Password-1' api python -m scripts.seed_demo --base-url http://api:8000
```

Run the tests: `docker compose run --rm test` (backend, offline), `cd apps/web && npm test` and `cd tests/e2e && npx playwright test` (frontend/E2E).
Everything runs in containers; no Python, PostgreSQL, Redis, GTK or WeasyPrint on the host.

## Documentation

| | |
|---|---|
| [final-report.md](docs/final-report.md) | **complete build report: what it does, worked example, all test cases, results** |
| [week-2-report.md](docs/week-2-report.md) | **Week 2 report: exposure graph and intelligence engine, worked demonstration, failure matrix, tests, performance** |
| [week-3-integration.md](docs/week-3-integration.md) | interfaces the investigation/remediation phase consumes |
| [architecture.md](docs/architecture.md) | decisions (source of truth), system overview, pipeline |
| [decisions.md](docs/decisions.md) | decision log and accepted deviations |
| [database.md](docs/database.md) | entities, RLS, migrations |
| [security.md](docs/security.md) | controls, tests, checklist, accepted risks |
| [api.md](docs/api.md) | endpoint reference |
| [development.md](docs/development.md) | setup, tests, troubleshooting |
| [operations.md](docs/operations.md) | production deployment, monitoring, backup/restore |
| [performance-report.md](docs/performance-report.md) | measurements and limits |
| [limitations-and-faq.md](docs/limitations-and-faq.md) | what it does not do |
| [release-checklist.md](docs/release-checklist.md) | go/no-go checklist |
| [learning/](docs/learning/) | learning report on the build |

Product vision: [Feature.md](docs/Feature.md) · plan: [4-week-plan.md](docs/4-week-plan.md) · Week 1 spec: [week-1.md](docs/week-1.md).
