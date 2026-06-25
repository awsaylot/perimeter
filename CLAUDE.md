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

## Hard constraints

- **Passive recon only.** Every check uses public data — DNS queries, standard HTTP requests, public APIs, CT logs. No login attempts, no port scanning beyond 80/443, no credential guessing. This is a firm boundary.
- **One target at a time.** Perimeter is a single-domain tool, not a mass scanner.

## Git commit rules

**Never commit until the milestone is working end-to-end.** Before any commit:

1. Run `python main.py <real-domain>` and verify the output looks correct.
2. Fix any import errors, runtime errors, or broken output before staging anything.
3. Only commit when the tool runs cleanly and the milestone's exit criteria are met.

Commit convention follows the roadmap milestone labels:

```
feat:    new check or feature
chore:   structure, config, dependencies
polish:  copy, formatting, UX tweaks
docs:    CLAUDE.md, ROADMAP.md, README
release: version tags
```

After each commit: `git push`.

## Testing

No test suite yet. Manual verification before each commit:

```bash
# Smoke test — should run without errors and print findings
python main.py google.com

# Test a specific check in isolation
python -c "from perimeter.checks import dns; from pprint import pprint; pprint(dns.run('google.com'))"
```

When a check is added, run it against at least one real domain and verify:
- It produces at least one `Finding`
- Severities are sensible
- No unhandled exceptions
- `CheckResult.error` is `None` on a clean run

## API keys — stop and get the key first

Some checks require an API key. **Do not stub, skip, or work around a missing key — stop and give the user the following instructions before writing any code for that check.**

### HaveIBeenPwned (breach check — Phase 2c)

Required for `perimeter/checks/breach.py`.

1. Go to https://haveibeenpwned.com/API/Key
2. Purchase an API key (one-time or subscription — the "personal" tier is sufficient)
3. Add it to `.env`: `HIBP_API_KEY=your_key_here`

Once the key is in `.env`, proceed with implementing the breach check.

## Roadmap context

See `ROADMAP.md` for the full phase breakdown. Current state: Phase 1 in progress.

- Phase 1 (in progress): DNS, TLS, HTTP headers checks ? terminal output
- Phase 2: Admin path probe, subdomain enumeration, HIBP breach check
- Phase 3: JSON output (`--json`), HTML report, PDF export
- Phase 4: Neo4j integration (`--graph` flag), historical tracking
- Phase 5: MCP service wrapper
- Phase 6: Real-domain validation, polish, v1.0.0 release

## Environment

Copy `.env.example` to `.env`. The only variable currently used is `HIBP_API_KEY` (optional — breach check skips gracefully without it).
