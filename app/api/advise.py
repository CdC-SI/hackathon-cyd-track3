"""POST /advise?model=....

Full assembly (spec §19):

    moderation gate -> resolve city (resolve_advise_location)
       -> not resolved: AdviseResponse.need_location() - sirens and threat
          events are never evaluated for a guessed location
       -> resolved: SirenRepository + ThreatEventRepository -> aggregator
          -> ThreatEngine -> AdviceBuilder -> AdviseResponse

Every piece below (resolver, repositories, aggregator, engine, builder) is
already independently tested; this module only wires them together and
reads the tunable Settings the pure threat/ functions take as explicit
parameters rather than looking up themselves.

`model` (optional query param, defaults to DEFAULT_LLM_MODEL - Qwen) picks
which LLM answers every call made while handling this request (moderation,
then query extraction, then shortlist selection).
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from psycopg import Connection

from app.advice.builder import build_advice
from app.config import Settings, get_settings
from app.db.database import get_db
from app.events.repository import ThreatEventRepository
from app.llm.moderation import moderate
from app.location.query_extractor import extract_location_text
from app.location.resolver import LocationResolver
from app.models.api import DEFAULT_LLM_MODEL, AdviseRequest, AdviseResponse, LLMModel
from app.models.location import CanonicalLocation
from app.sirens.repository import SirenRepository
from app.threat.aggregator import aggregate, freshness_cutoff
from app.threat.engine import assess

logger = logging.getLogger(__name__)

router = APIRouter()


def resolve_advise_location(
    conn: Connection, request: AdviseRequest, model: str | None = None
) -> CanonicalLocation | None:
    """The three cases of the spec (§9/§19), in order:

      1. `location.text` was supplied explicitly -> resolve it directly.
      2. Otherwise, ask the LLM whether `query` names a place -> resolve that.
      3. Nothing found either way -> None. The caller must ask the user to
         specify their city; sirens and threat events are never evaluated
         for a guessed location.

    `model` picks which LLM answers the calls made here - see complete_json.
    """
    resolver = LocationResolver(conn)

    if request.location is not None:
        return resolver.resolve(request.location.text, model)

    location_text = extract_location_text(request.query, model)
    if location_text is None:
        return None

    return resolver.resolve(location_text, model)


@router.post("/advise", response_model=AdviseResponse)
def advise(
    request: AdviseRequest,
    model: LLMModel = Query(
        DEFAULT_LLM_MODEL, description="Which LLM answers the calls made for this request."
    ),
    conn: Connection = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AdviseResponse:
    # request.query is the live caller's own question, not third-party corpus
    # text - logged in full at DEBUG (opt-in, operator's own environment).
    # request.text on /message is a different story: see its own module.
    logger.debug(
        "advise: model=%s query=%r as_of=%s location=%r", model.value, request.query, request.as_of, request.location
    )

    moderation = moderate(request.query, model.value)
    if not moderation.allowed:
        logger.info("advise: blocked by moderation")
        raise HTTPException(status_code=403, detail=moderation.message or "Request blocked.")

    location = resolve_advise_location(conn, request, model.value)
    if location is None:
        logger.debug("advise: no city resolved -> need_location")
        return AdviseResponse.need_location(request.as_of)
    logger.debug("advise: resolved location=%s (id=%s)", location.city, location.id)

    citations = SirenRepository(conn).get_active(location, request.as_of)
    siren_active = bool(citations)
    logger.debug("advise: siren_active=%s citations=%s", siren_active, citations)

    since = freshness_cutoff(request.as_of, settings.event_max_age_minutes)
    events = ThreatEventRepository(conn).find_for_location(location.id, request.as_of, since=since)
    logger.debug("advise: %d threat event(s) since %s", len(events), since)

    signals = aggregate(events, request.as_of, settings.signal_window_minutes)
    logger.debug("advise: aggregated into %d signal(s): %s", len(signals), signals)

    assessment = assess(
        siren_active=siren_active,
        citations=citations,
        signals=signals,
        as_of=request.as_of,
        alert_confidence_threshold=settings.alert_confidence_threshold,
    )
    logger.debug("advise: threat_level=%s", assessment.threat_level)

    advice_text = build_advice(assessment)
    logger.debug("advise: advice=%r", advice_text)

    return AdviseResponse(
        status="ok",
        advice=advice_text,
        as_of=request.as_of,
        area=location.area,
        siren_active=assessment.siren_active,
        citations=assessment.citations,
        threat_level=assessment.threat_level,
    )
