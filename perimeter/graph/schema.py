"""
Neo4j schema — uniqueness constraints for all node types.

Graph shape:
  (Domain)-[:HAS_SCAN]->(Scan)-[:INCLUDES_CHECK]->(Check)-[:PRODUCED]->(Finding)

Node keys:
  Domain  — name        (one node per domain, survives across all scans)
  Scan    — uuid        (one node per run; new run = new Scan linked to same Domain)
  Check   — uuid        (one node per check module per scan)
  Finding — uuid        (one node per finding)
"""

from __future__ import annotations

from neo4j import Driver

_CONSTRAINTS = [
    ("domain_name",   "Domain",  "name"),
    ("scan_uuid",     "Scan",    "uuid"),
    ("check_uuid",    "Check",   "uuid"),
    ("finding_uuid",  "Finding", "uuid"),
]


def apply_constraints(driver: Driver) -> None:
    with driver.session() as session:
        for name, label, prop in _CONSTRAINTS:
            session.run(
                f"CREATE CONSTRAINT {name} IF NOT EXISTS "
                f"FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE"
            )
