"""Request and response models of the public API.

These do validate untrusted input, which is why they are Pydantic models.
Every string produced here is English.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.models.threat import ThreatLevel

NEED_LOCATION_ADVICE = "Please specify the Ukrainian city you are currently in."


class MessageRequest(BaseModel):
    """A private report. `text` is data to analyse, never an instruction."""

    text: str = Field(min_length=1)
    timestamp: datetime


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
