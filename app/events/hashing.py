"""Stable, content-based identifier for one message.

Shared by the CSV importer (app/events/importer.py) - to deduplicate
messages.csv rows across re-runs - and by POST /message (app/api/message.py)
- to give a live report the same source_message_hash provenance field,
without depending on a message_id no source consistently provides
(messages.csv has one; a /message payload does not).
"""

import hashlib


def message_hash(text: str, timestamp: str) -> str:
    """Based on the raw fields exactly as received - not on anything parsed,
    since parsing behaviour is not a contract but the input content is."""
    return hashlib.sha256(f"{timestamp}|{text}".encode()).hexdigest()
