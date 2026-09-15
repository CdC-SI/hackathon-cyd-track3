"""Combines official sirens with aggregated private signals into one
ThreatAssessment (spec §17).

The one absolute rule of the whole application: an active siren always wins.
Private reports can raise the assessed level, never cancel a siren - not even
a signal claiming the threat has departed. Pure: takes plain values, no DB,
no LLM, no Settings read (the caller passes
get_settings().alert_confidence_threshold), so the invariant is testable
without any of that machinery in the way.
"""

from datetime import datetime

from app.models.threat import ThreatAssessment, ThreatLevel, ThreatSignal, ThreatState


def _decide_level(
    *, siren_active: bool, signals: list[ThreatSignal], alert_confidence_threshold: float
) -> ThreatLevel:
    """Rules, in order (spec §17):
      1. An active siren -> ALERT.
      2. Else a strong INBOUND signal (confidence >= alert_confidence_threshold) -> ALERT.
      3. Else any remaining INBOUND/NEARBY signal -> CAUTION.
      4. Else -> CLEAR.
    """
    if siren_active:
        return ThreatLevel.ALERT

    if any(
        signal.state == ThreatState.INBOUND and signal.confidence >= alert_confidence_threshold
        for signal in signals
    ):
        return ThreatLevel.ALERT

    if any(signal.state in (ThreatState.INBOUND, ThreatState.NEARBY) for signal in signals):
        return ThreatLevel.CAUTION

    return ThreatLevel.CLEAR


def assess(
    *,
    siren_active: bool,
    citations: list[str],
    signals: list[ThreatSignal],
    as_of: datetime,
    alert_confidence_threshold: float,
) -> ThreatAssessment:
    level = _decide_level(
        siren_active=siren_active,
        signals=signals,
        alert_confidence_threshold=alert_confidence_threshold,
    )

    # Reasserted explicitly, not left implicit in _decide_level's branch
    # order: a future edit to those branches must not be able to silently
    # break the one rule the whole application exists to guarantee. Raising
    # here means a bug surfaces loudly instead of quietly serving CLEAR under
    # an active siren.
    if siren_active and level == ThreatLevel.CLEAR:
        raise AssertionError("invariant violated: an active siren must never result in CLEAR")

    return ThreatAssessment(
        threat_level=level,
        siren_active=siren_active,
        citations=citations,
        signals=signals,
        as_of=as_of,
    )
