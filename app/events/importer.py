"""Ingests messages.csv into threat_events, via MessageExtractor and
LocationResolver.

Idempotent: message_hash (app/events/hashing.py) is a stable hash of (text,
timestamp), recorded in ingested_messages so a re-run never re-calls the LLM
on a message already processed. `group` and `sender` are personal data (see
the CSV header) and are never read.

Committed once per message, covering both the resulting event (if any) and
its ingested_messages record together: a crash partway through 1793 messages
must not lose the LLM calls already paid for on the ones before it. One giant
transaction for the whole run would do exactly that on rollback.
"""

import csv
import logging
from datetime import datetime
from pathlib import Path

from psycopg import Connection
from pydantic import TypeAdapter

from app.events.hashing import message_hash as compute_message_hash
from app.events.repository import ThreatEventRepository
from app.llm.message_extractor import MessageExtraction, extract_message
from app.location.resolver import LocationResolver
from app.models.threat import ThreatEvent

logger = logging.getLogger(__name__)

_parse_timestamp = TypeAdapter(datetime).validate_python


def _already_processed(conn: Connection, hashes: list[str]) -> set[str]:
    if not hashes:
        return set()
    rows = conn.execute(
        "SELECT message_hash FROM ingested_messages WHERE message_hash = ANY(%s)",
        (hashes,),
    ).fetchall()
    return {row[0] for row in rows}


def _decide_outcome(extraction: MessageExtraction, location_id: int | None) -> str:
    """Classifies one already-resolved extraction. Pure - no DB, no LLM - so
    the branching is unit-testable without either."""
    if not extraction.relevant:
        return "not_relevant"
    if location_id is None:
        return "relevant_no_event"  # no location stated, or it could not be resolved
    return "event_created"


def ingest_messages(conn: Connection, messages_csv: Path) -> dict[str, int]:
    """Processes every not-yet-seen row of messages.csv. Returns counters for
    logging."""
    with messages_csv.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    hashes = [compute_message_hash(row["text"], row["timestamp"]) for row in rows]
    seen = _already_processed(conn, hashes)

    resolver = LocationResolver(conn)
    events = ThreatEventRepository(conn)

    counters = {
        "total": len(rows),
        "skipped": 0,
        "event_created": 0,
        "relevant_no_event": 0,
        "not_relevant": 0,
    }

    for row, message_hash in zip(rows, hashes):
        if message_hash in seen:
            counters["skipped"] += 1
            continue

        timestamp = _parse_timestamp(row["timestamp"])
        extraction = extract_message(row["text"])

        location_id = None
        if extraction.relevant and extraction.location:
            location = resolver.resolve(extraction.location)
            location_id = location.id if location else None

        outcome = _decide_outcome(extraction, location_id)
        counters[outcome] += 1

        if outcome == "event_created":
            events.insert(
                ThreatEvent(
                    timestamp=timestamp,
                    location_id=location_id,
                    threat_type=extraction.threat_type,
                    movement=extraction.movement,
                    direction=extraction.direction,
                    confidence=extraction.confidence,
                    source="messages_csv",
                    source_message_hash=message_hash,
                )
            )

        conn.execute(
            """
            INSERT INTO ingested_messages
                (message_hash, timestamp, source, relevant, extraction_status, processed_at)
            VALUES (%s, %s, 'message', %s, 'done', %s)
            ON CONFLICT (message_hash) DO NOTHING
            """,
            (message_hash, timestamp, extraction.relevant, datetime.now()),
        )
        conn.commit()

    return counters
