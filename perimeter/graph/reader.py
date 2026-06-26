"""Read historical scan data from Neo4j for a domain."""

from __future__ import annotations

from neo4j import Driver


def get_history(domain: str, driver: Driver) -> list[dict]:
    """Return all scans for a domain, newest first."""
    with driver.session() as session:
        result = session.run(
            """
            MATCH (d:Domain {name: $domain})-[:HAS_SCAN]->(s:Scan)
            RETURN s.uuid        AS uuid,
                   s.scanned_at  AS scanned_at,
                   s.finding_count AS total,
                   s.high_count   AS high,
                   s.medium_count AS medium,
                   s.low_count    AS low
            ORDER BY s.scanned_at DESC
            """,
            domain=domain,
        )
        return [dict(r) for r in result]


def get_new_findings(domain: str, driver: Driver) -> list[dict]:
    """
    Compare the two most recent scans and return findings present in the latest
    scan that were not present in the previous one (new issues since last run).
    """
    with driver.session() as session:
        scans = session.run(
            """
            MATCH (d:Domain {name: $domain})-[:HAS_SCAN]->(s:Scan)
            RETURN s.uuid AS uuid ORDER BY s.scanned_at DESC LIMIT 2
            """,
            domain=domain,
        ).values("uuid")

        if len(scans) < 2:
            return []

        latest_uuid, prev_uuid = scans[0][0], scans[1][0]

        result = session.run(
            """
            MATCH (s_new:Scan {uuid: $latest})-[:INCLUDES_CHECK]->(:Check)-[:PRODUCED]->(f_new:Finding)
            WHERE NOT EXISTS {
                MATCH (s_old:Scan {uuid: $prev})-[:INCLUDES_CHECK]->(:Check)-[:PRODUCED]->(f_old:Finding)
                WHERE f_old.title = f_new.title AND f_old.check = f_new.check
            }
            RETURN f_new.check AS check, f_new.title AS title, f_new.severity AS severity
            ORDER BY f_new.severity, f_new.check
            """,
            latest=latest_uuid,
            prev=prev_uuid,
        )
        return [dict(r) for r in result]


def get_resolved_findings(domain: str, driver: Driver) -> list[dict]:
    """
    Return findings present in the previous scan that are gone in the latest
    (issues that have been fixed since last run).
    """
    with driver.session() as session:
        scans = session.run(
            """
            MATCH (d:Domain {name: $domain})-[:HAS_SCAN]->(s:Scan)
            RETURN s.uuid AS uuid ORDER BY s.scanned_at DESC LIMIT 2
            """,
            domain=domain,
        ).values("uuid")

        if len(scans) < 2:
            return []

        latest_uuid, prev_uuid = scans[0][0], scans[1][0]

        result = session.run(
            """
            MATCH (s_old:Scan {uuid: $prev})-[:INCLUDES_CHECK]->(:Check)-[:PRODUCED]->(f_old:Finding)
            WHERE NOT EXISTS {
                MATCH (s_new:Scan {uuid: $latest})-[:INCLUDES_CHECK]->(:Check)-[:PRODUCED]->(f_new:Finding)
                WHERE f_new.title = f_old.title AND f_new.check = f_old.check
            }
            RETURN f_old.check AS check, f_old.title AS title, f_old.severity AS severity
            ORDER BY f_old.severity, f_old.check
            """,
            latest=latest_uuid,
            prev=prev_uuid,
        )
        return [dict(r) for r in result]
