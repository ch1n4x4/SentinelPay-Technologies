"""Database connection helpers."""
import os
import psycopg2
import psycopg2.extras


def get_connection():
    return psycopg2.connect(
        os.environ.get("DATABASE_URL", "postgresql://sentinel:sentinel123@postgres:5432/sentinelpay"),
        cursor_factory=psycopg2.extras.RealDictCursor
    )
