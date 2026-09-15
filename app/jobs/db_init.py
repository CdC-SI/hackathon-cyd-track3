"""db-init job: apply the schema, then (re)load locations.json.

Run with: python -m app.jobs.db_init
"""

import logging
import sys

from app.config import get_settings, require_files
from app.db.database import get_conn
from app.db.locations_loader import load_locations
from app.db.schema import apply_schema

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def main() -> None:
    settings = get_settings()
    require_files(LOCATIONS_JSON=settings.locations_json)

    with get_conn() as conn:
        apply_schema(conn)
        logger.info("schema applied")

        count = load_locations(conn, settings.locations_json)
        logger.info("loaded %d locations from %s", count, settings.locations_json)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - top-level entrypoint
        logger.error("db-init failed: %s", exc)
        sys.exit(1)
