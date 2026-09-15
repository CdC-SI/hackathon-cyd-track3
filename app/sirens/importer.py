"""Loads sirens.csv into the `sirens` table.

Always a full refresh: DELETE + INSERT in one transaction, so the API never
observes the table half-populated mid re-run. Negligible cost (~4000 rows,
no LLM call) - there is no reason to diff against what is already there.

started_at/finished_at are passed through as the raw CSV strings and cast by
Postgres on insert (standard ISO-ish timestamps parse without help). oblast/
raion/hromada go through normalize() - the same function locations.json is
loaded through - since that is what SirenRepository matches on; see
app/location/normalize.py for why.
"""

import csv
from pathlib import Path

import psycopg

from app.location.normalize import normalize

Row = tuple[str, str, str | None, str | None, str, str, str]


def _build_rows(csv_rows: list[dict[str, str]]) -> list[Row]:
    """Pure transformation, split out from the DB write so it is unit-testable
    without a running Postgres."""
    return [
        (
            row["siren_id"],
            row["level"].strip().lower(),
            normalize(row.get("hromada")),
            normalize(row.get("raion")),
            normalize(row["oblast"]),
            row["started_at"],
            row["finished_at"],
        )
        for row in csv_rows
    ]


def load_sirens(conn: psycopg.Connection, sirens_csv: Path) -> int:
    """(Re)load the sirens table from the CSV. Returns the row count."""
    with sirens_csv.open(newline="", encoding="utf-8") as f:
        rows = _build_rows(list(csv.DictReader(f)))

    with conn.cursor() as cur:
        cur.execute("DELETE FROM sirens")
        cur.executemany(
            """
            INSERT INTO sirens (
                siren_id, level, hromada_norm, raion_norm, oblast_norm, started_at, finished_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            rows,
        )

    return len(rows)
