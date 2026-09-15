"""ingest job: load sirens.csv (always a full refresh), then messages.csv
(idempotent, hash-deduplicated - see app/events/importer.py).

Run with: python -m app.jobs.ingest [--force]

--force (or REINGEST_FORCE=true) wipes threat_events and ingested_messages
first, so every message is re-extracted through the LLM. Use it after
changing a prompt; the default path costs zero LLM calls on a message
already processed, so re-running this job on every restart is cheap.
"""

import argparse
import logging
import sys

from app.config import get_settings, require_files
from app.db.database import get_conn
from app.events.importer import ingest_messages
from app.sirens.importer import load_sirens

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def _reset_message_state(conn) -> None:
    conn.execute("DELETE FROM threat_events")
    conn.execute("DELETE FROM ingested_messages")
    conn.commit()


def main(force: bool = False) -> None:
    settings = get_settings()
    files_to_check = {"SIRENS_CSV": settings.sirens_csv, "MESSAGES_CSV": settings.messages_csv}
    if settings.ca_bundle is not None:
        # Optional, but if set it had better be real: failing now beats
        # failing on the first of ~1793 LLM calls.
        files_to_check["CA_BUNDLE"] = settings.ca_bundle
    require_files(**files_to_check)

    with get_conn() as conn:
        siren_count = load_sirens(conn, settings.sirens_csv)
        conn.commit()
        logger.info("loaded %d sirens from %s", siren_count, settings.sirens_csv)

        if force or settings.reingest_force:
            _reset_message_state(conn)
            logger.info("--force: cleared threat_events and ingested_messages")

        counters = ingest_messages(conn, settings.messages_csv)
        logger.info("messages: %s", counters)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force", action="store_true", help="re-extract every message through the LLM"
    )
    args = parser.parse_args()

    try:
        main(force=args.force)
    except Exception as exc:  # noqa: BLE001 - top-level entrypoint
        logger.error("ingest failed: %s", exc)
        sys.exit(1)
