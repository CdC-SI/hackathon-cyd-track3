"""Groups ThreatEvents from possibly-duplicate, unreliable private reports
into ThreatSignals the ThreatEngine can act on (spec §16), and the freshness
policy for /advise (how far back "recent enough" reaches).

Deliberately simple: group by (threat_type, movement, direction) - events are
already for one specific resolved location, since that is how
ThreatEventRepository.find_for_location() fetches them - within the
freshness window, and combine into one confidence that never lets sheer
message count alone approach certainty: a capped corroboration bonus, not
"50 messages = 100%" (the absolute rule of spec §16).

Not built here: clustering events into separate temporal "waves" of the same
(threat_type, movement, direction), or fading confidence as events age within
the window. Revisit only if the real corpus shows this matters; don't
over-engineer this part upfront.

freshness_cutoff() is one fixed window before as_of, no per-threat-type
tuning: events strictly older than it are dropped entirely by
app/events/repository.py - too old to say anything about the situation right
now. That hard cutoff is the only freshness policy here.

Pure: takes plain ThreatEvents, no DB or LLM involved, no Settings read - the
caller passes get_settings().event_max_age_minutes.
"""

from collections import defaultdict
from datetime import datetime, timedelta

from app.models.threat import (
    Direction,
    Movement,
    ThreatEvent,
    ThreatSignal,
    ThreatState,
    ThreatType,
)

# A report saying the threat is departing, or of unclear movement, does not
# by itself support raising the level. Only an active siren (a separate,
# presiding ThreatEngine rule) can still drive ALERT/CAUTION regardless.
_MOVEMENT_TO_STATE: dict[Movement, ThreatState] = {
    Movement.TOWARD: ThreatState.INBOUND,
    Movement.NEARBY: ThreatState.NEARBY,
    Movement.DEPARTING: ThreatState.ABSENT,
    Movement.UNKNOWN: ThreatState.NEARBY,
}

# Corroboration never approaches certainty by itself: capped, and each extra
# event past the first adds a fifth of the cap at most.
_CORROBORATION_STEP = 0.03
_CORROBORATION_CAP = 0.15


_GroupKey = tuple[ThreatType, Movement, Direction]


def _group_by_type_movement_direction(events: list[ThreatEvent]) -> dict[_GroupKey, list[ThreatEvent]]:
    groups: dict[_GroupKey, list[ThreatEvent]] = defaultdict(list)
    for event in events:
        groups[(event.threat_type, event.movement, event.direction)].append(event)
    return groups


def _confidence(group: list[ThreatEvent]) -> float:
    base = max(event.confidence for event in group)
    corroboration = min(_CORROBORATION_CAP, (len(group) - 1) * _CORROBORATION_STEP)
    return min(1.0, base + corroboration)


def _build_signal(key: _GroupKey, group: list[ThreatEvent]) -> ThreatSignal:
    threat_type, movement, direction = key
    last_seen = max(event.timestamp for event in group)
    confidence = _confidence(group)

    return ThreatSignal(
        threat_type=threat_type,
        state=_MOVEMENT_TO_STATE[movement],
        direction=direction,
        confidence=confidence,
        last_seen=last_seen,
        event_count=len(group),
    )


def aggregate(events: list[ThreatEvent]) -> list[ThreatSignal]:
    """events must already be geographically and temporally filtered (see
    app/events/repository.py + freshness_cutoff) - this only groups and
    scores them."""
    groups = _group_by_type_movement_direction(events)
    return [_build_signal(key, group) for key, group in groups.items()]


def freshness_cutoff(as_of: datetime, max_age_minutes: int) -> datetime:
    """Events strictly older than this, relative to as_of, are dropped
    entirely by app/events/repository.py - too old to say anything about the
    situation right now."""
    return as_of - timedelta(minutes=max_age_minutes)
