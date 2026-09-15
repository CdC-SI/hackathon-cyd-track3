"""Groups ThreatEvents from possibly-duplicate, unreliable private reports
into ThreatSignals the ThreatEngine can act on (spec §16), and the freshness
policy for /advise (how far back "recent enough" reaches).

Deliberately simple: group by (threat_type, movement, direction) - events are
already for one specific resolved location, since that is how
ThreatEventRepository.find_for_location() fetches them - within the
freshness window, and combine into one confidence that:

  - never lets sheer message count alone approach certainty: a capped
    corroboration bonus, not "50 messages = 100%" (the absolute rule of
    spec §16);
  - fades toward 0 as the group's most recent event ages, over
    window_minutes - shorter than the hard freshness cutoff below, so a
    signal quietly loses weight well before it would be dropped outright.

Not built here: clustering events into separate temporal "waves" of the same
(threat_type, movement, direction) - the decay above already makes a stale
early report count for little once fresher ones exist. Revisit only if the
real corpus shows this matters; don't over-engineer this part upfront.

freshness_cutoff() is one fixed window before as_of, no per-threat-type
tuning: events strictly older than it are dropped entirely by
app/events/repository.py - too old to say anything about the situation right
now.

Pure: takes plain ThreatEvents and a window, no DB or LLM involved, no
Settings read - the caller passes get_settings().signal_window_minutes /
get_settings().event_max_age_minutes.
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


def _decay(last_seen: datetime, as_of: datetime, window_minutes: int) -> float:
    if window_minutes <= 0:
        return 0.0
    age_minutes = (as_of - last_seen).total_seconds() / 60
    return max(0.0, 1.0 - age_minutes / window_minutes)


def _confidence(group: list[ThreatEvent], last_seen: datetime, as_of: datetime, window_minutes: int) -> float:
    base = max(event.confidence for event in group)
    corroboration = min(_CORROBORATION_CAP, (len(group) - 1) * _CORROBORATION_STEP)
    return min(1.0, (base + corroboration) * _decay(last_seen, as_of, window_minutes))


def _build_signal(
    key: _GroupKey, group: list[ThreatEvent], as_of: datetime, window_minutes: int
) -> ThreatSignal | None:
    """None when the group has fully decayed to zero confidence - nothing
    left in it for the ThreatEngine to act on."""
    threat_type, movement, direction = key
    last_seen = max(event.timestamp for event in group)
    confidence = _confidence(group, last_seen, as_of, window_minutes)

    if confidence <= 0.0:
        return None

    return ThreatSignal(
        threat_type=threat_type,
        state=_MOVEMENT_TO_STATE[movement],
        direction=direction,
        confidence=confidence,
        last_seen=last_seen,
        event_count=len(group),
    )


def aggregate(
    events: list[ThreatEvent], as_of: datetime, window_minutes: int
) -> list[ThreatSignal]:
    """events must already be geographically and temporally filtered (see
    app/events/repository.py + freshness_cutoff) - this only groups and
    scores them."""
    groups = _group_by_type_movement_direction(events)
    signals = (_build_signal(key, group, as_of, window_minutes) for key, group in groups.items())
    return [signal for signal in signals if signal is not None]


def freshness_cutoff(as_of: datetime, max_age_minutes: int) -> datetime:
    """Events strictly older than this, relative to as_of, are dropped
    entirely by app/events/repository.py - too old to say anything about the
    situation right now."""
    return as_of - timedelta(minutes=max_age_minutes)
