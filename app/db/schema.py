"""DDL for the four tables. Idempotent (CREATE ... IF NOT EXISTS): no migration
framework for this v1, applied fresh by the db-init job every run.

All timestamps are TIMESTAMP (no time zone), not TIMESTAMPTZ: every datetime
in the spec is naive (`as_of`, message timestamps, presumably sirens.csv's
started_at/finished_at too) - there is no offset anywhere to convert from or
to. TIMESTAMPTZ would make every comparison depend on the Postgres session's
timezone setting, and psycopg would hand back timezone-aware datetimes that
cannot be compared to the naive `as_of` the rest of the app uses.
"""

import psycopg

DDL = """
CREATE TABLE IF NOT EXISTS locations (
    -- Assigned deterministically by app/db/locations_loader.py from
    -- (city_norm, oblast_norm), not by file order - see its module
    -- docstring for why a reload must UPSERT rather than DELETE+INSERT.
    id       INTEGER PRIMARY KEY,
    city         TEXT NOT NULL,
    city_uk      TEXT,
    hromada      TEXT,
    raion        TEXT,
    oblast       TEXT NOT NULL,
    -- Comparison keys shared with siren matching (see app/location/normalize.py).
    -- raion_norm/hromada_norm are NULL for special-status cities (Kyiv,
    -- Sevastopol): they belong to no raion, so only an oblast-level siren can
    -- ever cover them.
    city_norm    TEXT NOT NULL,
    hromada_norm TEXT,
    raion_norm   TEXT,
    oblast_norm  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_locations_city_norm ON locations (city_norm);
CREATE INDEX IF NOT EXISTS idx_locations_hromada_norm ON locations (hromada_norm);
CREATE INDEX IF NOT EXISTS idx_locations_raion_norm ON locations (raion_norm);
CREATE INDEX IF NOT EXISTS idx_locations_oblast_norm ON locations (oblast_norm);

CREATE TABLE IF NOT EXISTS sirens (
    siren_id     TEXT PRIMARY KEY,
    level        TEXT NOT NULL CHECK (level IN ('oblast', 'raion', 'hromada')),
    hromada_norm TEXT,
    raion_norm   TEXT,
    oblast_norm  TEXT NOT NULL,
    started_at   TIMESTAMP NOT NULL,
    finished_at  TIMESTAMP NOT NULL
);
-- Matches app/location/normalize.py's WHERE clause: oblast is always compared,
-- and (started_at, finished_at) bound the half-open activity interval.
CREATE INDEX IF NOT EXISTS idx_sirens_oblast_window
    ON sirens (oblast_norm, started_at, finished_at);

CREATE TABLE IF NOT EXISTS threat_events (
    id                  INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    timestamp           TIMESTAMP NOT NULL,
    location_id         INTEGER NOT NULL REFERENCES locations (id),
    threat_type         TEXT NOT NULL CHECK (threat_type IN ('UAV', 'MISSILE', 'AIRCRAFT', 'UNKNOWN')),
    movement            TEXT NOT NULL CHECK (movement IN ('TOWARD', 'NEARBY', 'DEPARTING', 'UNKNOWN')),
    direction           TEXT NOT NULL CHECK (
        direction IN (
            'NORTH', 'NORTH_EAST', 'EAST', 'SOUTH_EAST',
            'SOUTH', 'SOUTH_WEST', 'WEST', 'NORTH_WEST', 'UNKNOWN'
        )
    ),
    confidence          REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    source              TEXT NOT NULL,
    source_message_hash TEXT NOT NULL,
    created_at          TIMESTAMP NOT NULL DEFAULT LOCALTIMESTAMP
    -- No raw message text: private text must never persist past extraction.
);
CREATE INDEX IF NOT EXISTS idx_threat_events_location_time
    ON threat_events (location_id, timestamp);

CREATE TABLE IF NOT EXISTS ingested_messages (
    id                 INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    message_hash       TEXT NOT NULL UNIQUE,
    timestamp          TIMESTAMP NOT NULL,
    source             TEXT NOT NULL,
    relevant           BOOLEAN,
    extraction_status  TEXT NOT NULL CHECK (extraction_status IN ('pending', 'done', 'failed')),
    processed_at       TIMESTAMP
    -- Bookkeeping only, for idempotent ingestion: never read by /advise.
);
"""


def apply_schema(conn: psycopg.Connection) -> None:
    conn.execute(DDL)
