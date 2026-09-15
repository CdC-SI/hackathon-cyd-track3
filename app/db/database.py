"""Postgres access: a lazily opened connection pool, and nothing else.

Plain SQL through psycopg, no ORM: the queries in this project are short, and
an ORM would hide the one thing worth reading closely — the siren matching
clause.
"""

from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
from psycopg_pool import ConnectionPool

from app.config import get_settings

_pool: ConnectionPool | None = None


def get_pool() -> ConnectionPool:
    """Open the pool on first use, so importing the app needs no database."""
    global _pool
    if _pool is None:
        # open=False + explicit .open(): psycopg_pool 3.2+ deprecates opening
        # implicitly in the constructor.
        _pool = ConnectionPool(get_settings().database_url, min_size=1, max_size=10, open=False)
        _pool.open()
    return _pool


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


@contextmanager
def get_conn() -> Iterator[psycopg.Connection]:
    """A pooled connection. Commits on success, rolls back on exception."""
    with get_pool().connection() as conn:
        yield conn


def get_db() -> Iterator[psycopg.Connection]:
    """FastAPI dependency wrapping get_conn(): one pooled connection per
    request, committed on success, rolled back on exception.

        conn: Connection = Depends(get_db)
    """
    with get_conn() as conn:
        yield conn
