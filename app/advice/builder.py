"""Builds the `advice` text of /advise from a ThreatAssessment (spec §18).

No LLM here, on purpose: deterministic English templates only. The one
wording rule the spec states explicitly - never say "It is safe.", say
"No current threat is known for this area at the requested time." instead -
is the whole reason this stays template-based rather than LLM-generated: a
generative model could always end up rephrasing its way into a claim of
safety the invariant in app/threat/engine.py never actually makes.

Pure: takes a ThreatAssessment, returns a string. No DB, no LLM, no Settings.
"""

from app.models.threat import Direction, ThreatAssessment, ThreatLevel, ThreatSignal, ThreatState

_ACTION_SENTENCES: dict[ThreatLevel, str] = {
    ThreatLevel.ALERT: "Go to shelter now and stay away from windows.",
    ThreatLevel.CAUTION: "Stay alert and be ready to take shelter if the situation changes.",
    ThreatLevel.CLEAR: "No current threat is known for this area at the requested time.",
}


def build_advice(assessment: ThreatAssessment) -> str:
    sentences: list[str] = []

    if assessment.siren_active:
        sentences.append("An official air-raid alert is active for your area.")

    signal = _most_relevant_signal(assessment.signals)
    if signal is not None:
        sentences.append(_signal_sentence(signal))
        if signal.state == ThreatState.INBOUND and signal.direction != Direction.UNKNOWN:
            sentences.append(_direction_sentence(signal.direction))

    sentences.append(_ACTION_SENTENCES[assessment.threat_level])

    return " ".join(sentences)


def _most_relevant_signal(signals: list[ThreatSignal]) -> ThreatSignal | None:
    """ABSENT signals are never described - they carry no threat to report,
    same reason app/threat/engine.py never lets them raise the level. Among
    the rest, describe only the single most confident one: concatenating
    every simultaneous signal risks reading as a raw data dump rather than
    advice."""
    candidates = [signal for signal in signals if signal.state != ThreatState.ABSENT]
    if not candidates:
        return None
    return max(candidates, key=lambda signal: signal.confidence)


def _signal_sentence(signal: ThreatSignal) -> str:
    if signal.state == ThreatState.INBOUND:
        return "An aerial threat is reported approaching your area."
    return "An aerial threat is reported near your area."  # NEARBY


def _direction_sentence(direction: Direction) -> str:
    # "the north-east", not "the north_east" - only INBOUND signals get here
    # (see build_advice): "approaching from" reads oddly for a signal that is
    # merely NEARBY rather than moving toward the area.
    return f"The threat is approaching from the {direction.value.lower().replace('_', '-')}."
