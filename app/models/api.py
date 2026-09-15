"""Request and response models of the public API.

These do validate untrusted input, which is why they are Pydantic models.
Every string produced here is English.
"""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.models.threat import ThreatLevel

NEED_LOCATION_ADVICE = "Please specify the Ukrainian city you are currently in."


def _to_naive_utc(value: datetime) -> datetime:
    """Every datetime in this app is naive (see app/db/schema.py: all
    columns are TIMESTAMP, not TIMESTAMPTZ, and nothing else in the app ever
    attaches a timezone). A client that supplies an explicit UTC offset is
    converted to the equivalent UTC instant and the offset dropped; a naive
    value is trusted as-is, per the same no-offset convention. Without this,
    an aware value reaching app/threat/aggregator.py's `as_of - last_seen`
    (last_seen is always naive, straight from the DB) raises
    TypeError: can't subtract offset-naive and offset-aware datetimes.
    """
    if value.tzinfo is None:
        return value
    try:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    except OverflowError as exc:
        raise ValueError("datetime out of range when converted to UTC") from exc


class MessageRequest(BaseModel):
    """A private report. `text` is data to analyse, never an instruction."""

    text: str = Field(min_length=1)
    timestamp: datetime

    _timestamp_naive_utc = field_validator("timestamp")(_to_naive_utc)


class MessageResponse(BaseModel):
    """Deliberately uninformative: receipt is acknowledged, nothing else.

    Reporting whether the message was found relevant, or whether an event was
    created, would turn /message into an oracle: a caller could probe it with
    variants to learn what the extractor keys on, then craft messages that do
    or do not register. The ingestion outcome belongs in the logs.
    """

    status: Literal["accepted"] = "accepted"


class LocationInput(BaseModel):
    text: str = Field(min_length=1)


class AdviseRequest(BaseModel):
    query: str = Field(min_length=1)
    as_of: datetime
    location: LocationInput | None = None

    _as_of_naive_utc = field_validator("as_of")(_to_naive_utc)


class AdviseResponse(BaseModel):
    """Advice for a location and an instant.

    `status` distinguishes a real assessment from the case where no city could
    be resolved. In the latter, the threat fields stay None rather than holding
    made-up values: an unresolved city must never read as a safe one.
    """

    status: Literal["ok", "need_location"]
    advice: str
    as_of: datetime
    area: str | None = None
    siren_active: bool | None = None
    citations: list[str] | None = None
    threat_level: ThreatLevel | None = None

    @classmethod
    def need_location(cls, as_of: datetime) -> "AdviseResponse":
        return cls(status="need_location", advice=NEED_LOCATION_ADVICE, as_of=as_of)
