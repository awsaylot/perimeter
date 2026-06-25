# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the tool

```bash
python main.py example.com
python main.py example.com --output report.html
python main.py example.com --hibp-key <key>   # or set HIBP_API_KEY in .env
```

Install dependencies: `pip install -r requirements.txt`

## Architecture

Perimeter is built in three future-facing layers that are additive — each works without the next:

1. **CLI** — `main.py` parses args, orchestrates checks, prints/writes output
2. **Graph DB (Neo4j)** — scan results feed into a graph for historical tracking (Phase 4)
3. **MCP service** — perimeter will be wrappable as MCP tools without refactoring (Phase 5)

### Data flow

```
main.py ? checks/*.py ? CheckResult ? ScanResult ? output (terminal / HTML / JSON / Neo4j)
```

### Check module contract

Every file in `perimeter/checks/` must expose exactly one function:

```python
def run(domain: str) -> CheckResult:
```

That is the entire interface. `main.py` calls each check by importing and calling `run`. No check touches another check or any output layer.

### Models (`perimeter/models.py`)

- `Severity` — enum: `HIGH | MEDIUM | LOW | INFO | PASS`
- `Finding` — one observation: `check`, `title`, `severity`, `summary` (plain English), `fix` (one-liner), `raw` (dict, technical detail for appendix)
- `CheckResult` — output of one check: list of `Finding` objects + optional `error` string if the check itself failed
- `ScanResult` — full scan: `domain` + list of `CheckResult`. Has `.all_findings` and `.actionable_findings` (excludes PASS/INFO) properties.

**Pending (do before adding any new check):** `ScanResult`, `CheckResult`, and `Finding` need `uuid` (generated at instantiation) and `scanned_at` / `produced_at` timestamps. These are required for the Neo4j graph nodes in Phase 4.

## Hard constraints

- **Passive recon only.** Every check uses public data — DNS queries, standard HTTP requests, public APIs, CT logs. No login attempts, no port scanning beyond 80/443, no credential guessing. This is a firm boundary.
- **One target at a time.** Perimeter is a single-domain tool, not a mass scanner.

## Roadmap context

See `ROADMAP.md` for the full phase breakdown. Current state: Phase 1 in progress.

- Phase 1 (in progress): DNS, TLS, HTTP headers checks ? terminal output
- Phase 2: Admin path probe, subdomain enumeration, HIBP breach check
- Phase 3: JSON output (`--json`), HTML report, PDF export
- Phase 4: Neo4j integration (`--graph` flag), historical tracking
- Phase 5: MCP service wrapper
- Phase 6: Real-domain validation, polish, v1.0.0 release

Commit convention follows the roadmap milestone labels: `feat:`, `chore:`, `polish:`, `release:`.

## Environment

Copy `.env.example` to `.env`. The only variable currently used is `HIBP_API_KEY` (optional — breach check skips gracefully without it).
