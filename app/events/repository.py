"""Persists ThreatEvents and answers the location + time queries /advise
needs.

Geographic relevance is exact: an event's location_id must match the queried
location's id. Unlike sirens, a private report carries no administrative
level to widen the match - it is always tied to one specific resolved city.

Freshness (how far back "recent enough" reaches) is a separate policy,
computed by app/threat/aggregator.py's freshness_cutoff() (step 10) and
passed in as `since`. This repository only ever enforces the one
non-negotiable rule on its own: never a future event (timestamp <= as_of).
"""

from datetime import datetime

from psycopg import Connection

from app.models.threat import Direction, Movement, ThreatEvent, ThreatType


class ThreatEventRepository:
    def __init__(self, conn: Connection):
        self._conn = conn

    def insert(self, event: ThreatEvent) -> int:
        row = self._conn.execute(
            """
            INSERT INTO threat_events (
                timestamp, location_id, threat_type, movement, direction,
                confidence, source, source_message_hash
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                event.timestamp,
                event.location_id,
                event.threat_type.value,
                event.movement.value,
                event.direction.value,
                event.confidence,
                event.source,
                event.source_message_hash,
            ),
        ).fetchone()
        return row[0]

    def find_for_location(
        self, location_id: int, as_of: datetime, since: datetime | None = None
    ) -> list[ThreatEvent]:
        """Events for this exact location, never later than as_of, most
        recent first. `since` is the freshness cutoff from
        app/threat/aggregator.py's freshness_cutoff(); omit it to get every
        past event."""
        rows = self._conn.execute(
            """
            SELECT id, timestamp, location_id, threat_type, movement, direction,
                   confidence, source, source_message_hash, created_at
            FROM threat_events
            WHERE location_id = %(location_id)s
              AND timestamp <= %(as_of)s
              AND (%(since)s IS NULL OR timestamp >= %(since)s)
            ORDER BY timestamp DESC
            """,
            {"location_id": location_id, "as_of": as_of, "since": since},
        ).fetchall()
        return [_row_to_event(row) for row in rows]


def _row_to_event(row: tuple) -> ThreatEvent:
    (
        id_,
        timestamp,
        location_id,
        threat_type,
        movement,
        direction,
        confidence,
        source,
        source_message_hash,
        created_at,
    ) = row
    return ThreatEvent(
        id=id_,
        timestamp=timestamp,
        location_id=location_id,
        threat_type=ThreatType(threat_type),
        movement=Movement(movement),
        direction=Direction(direction),
        confidence=confidence,
        source=source,
        source_message_hash=source_message_hash,
        created_at=created_at,
    )
