"""Loads locations.json into the `locations` table.

`id` is derived deterministically from (city_norm, oblast_norm) via a stable
hash - not from file position. This is a bug fix, not a style choice: an id
tied to file order changes if locations.json is ever reordered or edited, and
db-init used to DELETE the whole table before reinserting. Once threat_events
exist (REFERENCES locations(id), no ON DELETE clause), that DELETE fails with
a foreign key violation on the very next db-init run - see todo/TODO.md.

A stable id lets every re-run UPSERT in place instead: the same city always
maps to the same id, so existing threat_events.location_id references are
never touched, and a row for a city removed from a later locations.json is
just left alone rather than deleted out from under something referencing it.
"""

import hashlib
import json
from pathlib import Path
from typing import TypedDict

import psycopg

from app.location.normalize import normalize


class CityRecord(TypedDict, total=False):
    name_en: str
    name_uk: str
    oblast: str
    raion: str
    hromada: str
    neighbouring_cities: list[str]


Row = tuple[int, str, str | None, str | None, str | None, str, str, str | None, str | None, str]

# Comfortably inside a Postgres INTEGER (max ~2.1 billion) while keeping the
# id positive.
_ID_SPACE = 2_000_000_000


def _stable_id(city_norm: str, oblast_norm: str) -> int:
    """Deterministic across runs and processes - unlike Python's built-in
    hash() (randomised per process for str unless PYTHONHASHSEED is pinned),
    hashlib always returns the same digest for the same input. Keyed on
    (city_norm, oblast_norm), not city_norm alone: two different cities
    sharing a name in different oblasts must not collapse onto one id."""
    digest = hashlib.sha256(f"{city_norm}|{oblast_norm}".encode()).hexdigest()
    return int(digest[:15], 16) % _ID_SPACE


def _build_rows(cities: list[CityRecord]) -> list[Row]:
    """Pure transformation, split out from the DB write so it is unit-testable
    without a running Postgres."""
    rows: list[Row] = []
    seen: dict[int, tuple[str, str]] = {}

    for city in cities:
        city_norm = normalize(city["name_en"])
        oblast_norm = normalize(city["oblast"])
        location_id = _stable_id(city_norm, oblast_norm)

        key = (city_norm, oblast_norm)
        if location_id in seen and seen[location_id] != key:
            raise ValueError(
                f"id collision: {seen[location_id]!r} and {key!r} both hash to "
                f"{location_id} - widen _stable_id's range"
            )
        seen[location_id] = key

        raion_norm = normalize(city.get("raion"))
        hromada_norm = normalize(city.get("hromada"))
        rows.append(
            (
                location_id,
                city["name_en"],
                city.get("name_uk"),
                # The display value is nulled out together with its norm: for a
                # special-status city (Kyiv, Sevastopol) the source holds a "—"
                # placeholder, not a real hromada/raion, and CanonicalLocation
                # must see None there too - never the literal placeholder text.
                city.get("hromada") if hromada_norm is not None else None,
                city.get("raion") if raion_norm is not None else None,
                city["oblast"],
                city_norm,
                hromada_norm,
                raion_norm,
                oblast_norm,
            )
        )
    return rows


def load_locations(conn: psycopg.Connection, locations_json: Path) -> int:
    """Loads/refreshes the locations table from the dataset. Returns the row
    count. Never deletes: a city missing from a later locations.json simply
    stops being updated, rather than being removed out from under any
    threat_events that reference it."""
    cities: list[CityRecord] = json.loads(locations_json.read_text())["cities"]
    rows = _build_rows(cities)

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO locations (
                id, city, city_uk, hromada, raion, oblast,
                city_norm, hromada_norm, raion_norm, oblast_norm
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                city = EXCLUDED.city,
                city_uk = EXCLUDED.city_uk,
                hromada = EXCLUDED.hromada,
                raion = EXCLUDED.raion,
                oblast = EXCLUDED.oblast,
                city_norm = EXCLUDED.city_norm,
                hromada_norm = EXCLUDED.hromada_norm,
                raion_norm = EXCLUDED.raion_norm,
                oblast_norm = EXCLUDED.oblast_norm
            """,
            rows,
        )

    return len(rows)
