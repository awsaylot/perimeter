"""Neo4j driver factory — reads credentials from environment / .env file."""

from __future__ import annotations

import os

from dotenv import load_dotenv
from neo4j import GraphDatabase, Driver

load_dotenv()


def get_driver() -> Driver:
    uri      = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    username = os.getenv("NEO4J_USERNAME", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "")

    if not password:
        raise RuntimeError(
            "NEO4J_PASSWORD is not set. Add it to .env or set the environment variable."
        )

    return GraphDatabase.driver(uri, auth=(username, password))
