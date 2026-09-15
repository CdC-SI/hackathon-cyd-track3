"""POST /message.

Pipeline (spec §4): validate -> LLM extraction (translation to English
included) -> LocationResolver -> ThreatEvent -> Postgres. If the message is
not relevant, or names no location that resolves to a real city, nothing is
created - and the response says nothing about which happened: see
MessageResponse for why (reporting the outcome would turn this endpoint into
an oracle for probing the extractor).
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from psycopg import Connection

from app.db.database import get_db
from app.events.hashing import message_hash
from app.events.repository import ThreatEventRepository
from app.llm.message_extractor import extract_message
from app.llm.moderation import moderate
from app.location.resolver import LocationResolver
from app.models.api import MessageRequest, MessageResponse
from app.models.threat import ThreatEvent

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/message", response_model=MessageResponse)
def receive_message(
    request: MessageRequest, conn: Connection = Depends(get_db)
) -> MessageResponse:
    # Never log request.text itself, even at DEBUG: unlike /advise's query,
    # this can be a real private report from the corpus, not just the live
    # caller's own words - same reason it never reaches threat_events either.
    logger.debug("message: timestamp=%s text_length=%d", request.timestamp, len(request.text))

    moderation = moderate(request.text)
    if not moderation.allowed:
        logger.info("message: blocked by moderation")
        raise HTTPException(status_code=403, detail=moderation.message or "Request blocked.")

    extraction = extract_message(request.text)
    logger.debug(
        "message: relevant=%s threat_type=%s location=%r movement=%s direction=%s confidence=%.2f",
        extraction.relevant,
        extraction.threat_type,
        extraction.location,
        extraction.movement,
        extraction.direction,
        extraction.confidence,
    )

    if extraction.relevant and extraction.location:
        location = LocationResolver(conn).resolve(extraction.location)
        if location is not None:
            logger.debug("message: resolved location=%s (id=%s) -> creating ThreatEvent", location.city, location.id)
            ThreatEventRepository(conn).insert(
                ThreatEvent(
                    timestamp=request.timestamp,
                    location_id=location.id,
                    threat_type=extraction.threat_type,
                    movement=extraction.movement,
                    direction=extraction.direction,
                    confidence=extraction.confidence,
                    source="api",
                    source_message_hash=message_hash(
                        request.text, request.timestamp.isoformat()
                    ),
                )
            )
        else:
            logger.debug("message: location %r could not be resolved -> no event", extraction.location)
    else:
        logger.debug("message: not relevant, or no location stated -> no event")

    return MessageResponse()
