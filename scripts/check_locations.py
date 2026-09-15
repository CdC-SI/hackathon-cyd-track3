"""Diagnostic: do locations.json and sirens.csv agree on their administrative
vocabulary? sirens.csv and locations.json are translated independently (see
app/location/normalize.py) - if their spelling of an oblast/raion/hromada
does not reconcile after normalize(), the affected sirens silently never
match any location, and "an active siren is never CLEAR" breaks with no
error anywhere. Run this the moment both files are in hand, before any demo.

Usage - locations must already be loaded (`docker compose run --rm db-init`);
`ingest` is reused below only because it already mounts SIRENS_CSV, not
because sirens.csv needs to be loaded into Postgres first - this script reads
it straight off disk:

    docker compose run --rm ingest python -m scripts.check_locations
"""

import csv
import sys

from app.config import get_settings, require_files
from app.db.database import get_conn
from app.location.normalize import normalize


def _sirens_vocabulary(sirens_csv) -> tuple[set[str], set[str], set[str]]:
    oblasts, raions, hromadas = set(), set(), set()
    with sirens_csv.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            oblasts.add(normalize(row["oblast"]))
            raions.add(normalize(row.get("raion")))
            hromadas.add(normalize(row.get("hromada")))
    oblasts.discard(None)
    raions.discard(None)
    hromadas.discard(None)
    return oblasts, raions, hromadas


def main() -> None:
    settings = get_settings()
    require_files(SIRENS_CSV=settings.sirens_csv)

    siren_oblasts, siren_raions, siren_hromadas = _sirens_vocabulary(settings.sirens_csv)

    with get_conn() as conn:
        locations = conn.execute(
            "SELECT city, oblast_norm, raion_norm, hromada_norm FROM locations"
        ).fetchall()

    if not locations:
        print("locations table is empty - run db-init first.")
        sys.exit(1)

    matched = 0
    orphans: list[tuple[str, str]] = []
    for city, oblast_norm, raion_norm, hromada_norm in locations:
        problems = []
        if oblast_norm not in siren_oblasts:
            problems.append(f"oblast {oblast_norm!r}")
        if raion_norm is not None and raion_norm not in siren_raions:
            problems.append(f"raion {raion_norm!r}")
        if hromada_norm is not None and hromada_norm not in siren_hromadas:
            problems.append(f"hromada {hromada_norm!r}")

        if problems:
            orphans.append((city, ", ".join(problems)))
        else:
            matched += 1

    total = len(locations)
    print(f"{matched}/{total} cities fully match the sirens.csv vocabulary ({matched / total:.0%})")

    if orphans:
        print("\nCities with no matching siren vocabulary (a real active siren would silently miss them):")
        for city, problems in orphans:
            print(f"  - {city}: {problems}")


if __name__ == "__main__":
    main()
