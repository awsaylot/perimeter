# Perimeter — Project Roadmap

## Vision

Perimeter is a passive external exposure scanner: point it at a domain, get back a
plain-English report of what's publicly visible about that business's security posture.
No login attempts, no exploitation, no gray area — only public data.

The tool is designed to work at three levels:

1. **Standalone CLI** — run it from a terminal, get an HTML/PDF report you can hand to a client.
2. **Graph database backend** — scan results are structured to feed into Neo4j, enabling
   historical tracking, cross-domain analysis, and relationship mapping over time.
3. **MCP service** — perimeter will be wrappable as an MCP tool so AI agents can invoke
   checks, query historical results, and surface findings in conversation.

These three levels are additive. The CLI works without the graph DB. The graph DB works
without the MCP. Each layer is independently useful.

---

## Architecture Principles

- **Structured output first.** Every check produces typed `Finding` objects with stable IDs.
  The HTML report, JSON export, and graph nodes all derive from the same in-memory
  `ScanResult` — there is no separate "export format."
- **Passive recon only.** Every check must be answerable from public data with no
  credentials. This is a hard boundary, not a style preference.
- **Pluggable checks.** Each check is an isolated module with a single `run(domain) ->
  CheckResult` signature. Adding or removing a check does not touch anything else.
- **Graph-ready models.** `Finding`, `CheckResult`, and `ScanResult` carry UUIDs and
  timestamps from the moment they are created, so they map directly to graph nodes
  without a transformation step.

---

## Phases & Commit Milestones

### Phase 1 — Core checks, CLI output

The goal of Phase 1 is a working tool that runs real checks against a real domain and
prints structured results to the terminal.

| Milestone | Commit message | Description |
|-----------|---------------|-------------|
| 1a ✓ | `chore: project structure + data models` | Package layout, `Finding` / `CheckResult` / `ScanResult` dataclasses, `requirements.txt` |
| 1b ✓ | `feat: dns check` | MX, SPF, DMARC, DKIM — flags missing records, weak DMARC policy |
| 1c ✓ | `feat: tls check` | Cert expiry, protocol version, chain validity |
| 1d ✓ | `feat: http headers check` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |

**Exit criteria:** `python main.py example.com` runs all three checks and prints
findings to the terminal with severity labels.

---

### Phase 2 — Complete the check suite

All checks use only public data — no paid API keys required.

| Milestone | Commit message | Description |
|-----------|---------------|-------------|
| 2a ✓ | `feat: admin path probe` | Checks common paths (`/admin`, `/wp-admin`, `/.env`, `/swagger`, etc.) for 200/403 responses — no login attempts |
| 2b ✓ | `feat: subdomain enumeration` | Enumerates subdomains via crt.sh certificate transparency logs — flags sensitive-looking names (staging, dev, jenkins, vpn, etc.) |
| 2c ✓ | `feat: dnssec check` | Checks for DS / RRSIG records — missing DNSSEC leaves DNS responses open to cache poisoning and spoofing |
| 2d ✓ | `feat: whois check` | Queries RDAP for domain expiry, registration age, and registrar privacy — flags near-expiry and suspiciously new domains |
| 2e ✓ | `feat: robots.txt audit` | Fetches and parses robots.txt; flags Disallow entries that reveal sensitive internal paths |
| 2f ✓ | `feat: cookie security` | Inspects Set-Cookie headers for missing Secure, HttpOnly, and SameSite flags |
| 2g ✓ | `feat: security.txt check` | Checks for /.well-known/security.txt (RFC 9116) — absence means no public responsible-disclosure channel |

**Exit criteria:** All checks are implemented using only free, public data sources.
The tool is feature-complete for v1.

---

### Phase 3 — Output layer

| Milestone | Commit message | Description |
|-----------|---------------|-------------|
| 3a ✓ | `feat: json output` | `--json` flag dumps `ScanResult` as structured JSON. This is the foundation for all downstream integrations. |
| 3b ✓ | `feat: html report` | Jinja2 template renders Summary / Findings / Appendix. Plain-English copy, severity badges, client-ready formatting. |

**Exit criteria:** `python main.py example.com --output report.html` produces a
client-ready report. `--json` produces clean structured output suitable for piping
or ingestion.

**Note:** PDF export was dropped — WeasyPrint requires Pango/GTK system libraries on
Windows. Users can print to PDF from the HTML report via their browser.

---

### Phase 4 — Neo4j integration

| Milestone | Commit message | Description |
|-----------|---------------|-------------|
| 4a | `feat: neo4j schema` | Define node types (`Domain`, `Scan`, `Check`, `Finding`) and relationship types (`HAS_SCAN`, `INCLUDES_CHECK`, `PRODUCED_FINDING`). Schema documented and versioned. |
| 4b | `feat: neo4j export` | `--graph` flag writes scan results into Neo4j. Idempotent: re-running a scan updates existing nodes rather than creating duplicates. |
| 4c | `feat: historical tracking` | Graph stores every scan run. Queries can show what changed between scans — new findings, resolved issues, expiry countdowns. |

**Graph schema (draft):**
```
(Domain)-[:HAS_SCAN]->(Scan)-[:INCLUDES_CHECK]->(Check)-[:PRODUCED]->(Finding)
```

- `Domain` — the target (e.g. `example.com`). One node per domain, persists across scans.
- `Scan` — one node per run, with a timestamp. Links to all checks run in that session.
- `Check` — one node per check module per scan (DNS, TLS, etc.).
- `Finding` — one node per finding, with severity, summary, fix, and raw detail.

**Exit criteria:** Running perimeter with `--graph` populates Neo4j. A second run
against the same domain creates a new `Scan` node and updates the `Domain` node
without duplication.

---

### Phase 5 — MCP service

> Architecture TBD — perimeter will be built clean so it can be wrapped as an MCP
> tool at this stage without refactoring. The check modules and JSON output are
> the natural MCP interface.

Likely shape:
- Individual tools per check (`scan_dns`, `scan_tls`, etc.) for surgical use.
- A `scan_domain` tool that runs all checks and returns structured JSON.
- A `get_scan_history` tool that queries the Neo4j graph for historical results.

---

### Phase 6 — Polish & v1 release

| Milestone | Commit message | Description |
|-----------|---------------|-------------|
| 6a | `chore: validate against real domains` | Run against 2–3 domains (owned or permissioned). Tune plain-English copy. Fix edge cases. |
| 6b | `polish: report formatting` | Final pass on report layout, typography, and summary copy. |
| 6c | `release: v1.0.0` | Tag, GitHub release, update README with usage examples and sample output. |

---

## Pre-1b: Model updates needed

Before starting 1b, `models.py` needs two additions:

1. **UUIDs** — `ScanResult`, `CheckResult`, and `Finding` should each carry a `uuid`
   field generated at instantiation. Graph nodes need stable identifiers.
2. **Timestamps** — `ScanResult` should record when a scan started. `Finding` should
   record when it was produced. This enables the historical tracking in Phase 4.

These are one-time additions that are trivial now and painful to add later.
