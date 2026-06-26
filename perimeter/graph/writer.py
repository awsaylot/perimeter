"""Writes a ScanResult into Neo4j. All operations use MERGE so re-running is safe."""

from __future__ import annotations

import json

from neo4j import Driver

from perimeter.models import ScanResult


def write_scan(result: ScanResult, driver: Driver) -> None:
    findings  = result.all_findings
    actionable = result.actionable_findings

    scan_props = {
        "uuid":          result.uuid,
        "scanned_at":    result.scanned_at,
        "domain":        result.domain,
        "finding_count": len(findings),
        "high_count":    sum(1 for f in actionable if f.severity == "high"),
        "medium_count":  sum(1 for f in actionable if f.severity == "medium"),
        "low_count":     sum(1 for f in actionable if f.severity == "low"),
    }

    with driver.session() as session:
        # Domain node — one per domain, persists across scans
        session.run(
            """
            MERGE (d:Domain {name: $name})
            ON CREATE SET d.first_seen = $scanned_at
            SET d.last_scan = $scanned_at
            """,
            name=result.domain,
            scanned_at=result.scanned_at,
        )

        # Scan node — one per run
        session.run(
            """
            MERGE (s:Scan {uuid: $uuid})
            ON CREATE SET s += $props
            MERGE (d:Domain {name: $domain})
            MERGE (d)-[:HAS_SCAN]->(s)
            """,
            uuid=result.uuid,
            props=scan_props,
            domain=result.domain,
        )

        # Check and Finding nodes
        for cr in result.check_results:
            session.run(
                """
                MERGE (c:Check {uuid: $uuid})
                ON CREATE SET c.name = $name, c.error = $error
                WITH c
                MATCH (s:Scan {uuid: $scan_uuid})
                MERGE (s)-[:INCLUDES_CHECK]->(c)
                """,
                uuid=cr.uuid,
                name=cr.check,
                error=cr.error,
                scan_uuid=result.uuid,
            )

            for f in cr.findings:
                session.run(
                    """
                    MERGE (f:Finding {uuid: $uuid})
                    ON CREATE SET
                        f.check      = $check,
                        f.title      = $title,
                        f.severity   = $severity,
                        f.summary    = $summary,
                        f.fix        = $fix,
                        f.raw        = $raw,
                        f.produced_at = $produced_at
                    WITH f
                    MATCH (c:Check {uuid: $check_uuid})
                    MERGE (c)-[:PRODUCED]->(f)
                    """,
                    uuid=f.uuid,
                    check=f.check,
                    title=f.title,
                    severity=f.severity.value,
                    summary=f.summary,
                    fix=f.fix,
                    raw=json.dumps(f.raw),
                    produced_at=f.produced_at,
                    check_uuid=cr.uuid,
                )
