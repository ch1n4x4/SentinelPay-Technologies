import os
import psycopg2
import psycopg2.extras


def get_connection():
    return psycopg2.connect(
        os.environ.get("DATABASE_URL"),
        cursor_factory=psycopg2.extras.RealDictCursor
    )
