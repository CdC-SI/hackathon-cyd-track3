"""Threat vocabulary and structures.

Everything here is English-only and strictly enumerated: this is the layer the
private message text is reduced to before it is allowed any further into the
system.
"""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ThreatType(StrEnum):
    UAV = "UAV"
    MISSILE = "MISSILE"
    AIRCRAFT = "AIRCRAFT"
    UNKNOWN = "UNKNOWN"


class Movement(StrEnum):
    TOWARD = "TOWARD"
    NEARBY = "NEARBY"
    DEPARTING = "DEPARTING"
    UNKNOWN = "UNKNOWN"


class Direction(StrEnum):
    NORTH = "NORTH"
    NORTH_EAST = "NORTH_EAST"
    EAST = "EAST"
    SOUTH_EAST = "SOUTH_EAST"
    SOUTH = "SOUTH"
    SOUTH_WEST = "SOUTH_WEST"
    WEST = "WEST"
    NORTH_WEST = "NORTH_WEST"
    UNKNOWN = "UNKNOWN"


class ThreatState(StrEnum):
    INBOUND = "INBOUND"
    NEARBY = "NEARBY"
    ABSENT = "ABSENT"


class ThreatLevel(StrEnum):
    ALERT = "ALERT"
    CAUTION = "CAUTION"
    CLEAR = "CLEAR"


class ThreatEvent(BaseModel):
    """One structured observation derived from one private message.

    The raw message text is deliberately absent: only the hash of its source
    travels with the event.
    """

    id: int | None = None
    timestamp: datetime
    location_id: int
    threat_type: ThreatType
    movement: Movement
    direction: Direction
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    source_message_hash: str
    created_at: datetime | None = None


class ThreatSignal(BaseModel):
    """Several corroborating events aggregated into one signal."""

    threat_type: ThreatType
    state: ThreatState
    direction: Direction
    confidence: float = Field(ge=0.0, le=1.0)
    last_seen: datetime
    event_count: int = Field(default=1, ge=1)


class ThreatAssessment(BaseModel):
    """The deterministic verdict: sirens plus private signals."""

    threat_level: ThreatLevel
    siren_active: bool
    citations: list[str] = Field(default_factory=list)
    signals: list[ThreatSignal] = Field(default_factory=list)
    as_of: datetime
