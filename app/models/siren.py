"""Official air-raid sirens. Trusted, authoritative source.

No Pydantic model here on purpose: sirens go CSV -> Postgres -> SQL query and
never cross an untrusted input boundary. Their shape is enforced by the schema
(CHECK constraint on level, timestamptz columns), and /advise only ever needs
the siren_id list for citations.

What is worth sharing is the level vocabulary below, used by the importer, the
CHECK constraint and the repository query alike.
"""

from enum import StrEnum


class SirenLevel(StrEnum):
    """How far down the administrative hierarchy an alert applies.

    oblast  -> covers every city of the oblast
    raion   -> oblast and raion must match
    hromada -> oblast, raion and hromada must match
    """

    OBLAST = "oblast"
    RAION = "raion"
    HROMADA = "hromada"
