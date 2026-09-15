"""Queries active sirens for a location and an instant.

CanonicalLocation only ever carries display strings (see
app/models/location.py) - the comparison keys are re-derived here with the
same normalize() the sirens and locations tables were loaded through, rather
than duplicating them on the model. There is exactly one place that decides
what "the same oblast" means.

get_active() returns siren_id strings, and nothing else: /advise needs no
other field from a siren, and the LLM never generates a citation - these are
always real ids straight out of sirens.csv.
"""

from datetime import datetime

from psycopg import Connection

from app.location.normalize import normalize
from app.models.location import CanonicalLocation

# level == oblast covers every raion/hromada of the oblast; raion also
# requires the raion to match; hromada requires all three. A location with no
# raion (Kyiv, Sevastopol - see app/models/location.py) passes raion=None
# here, and `raion_norm = NULL` is never true in SQL, so it is naturally only
# ever covered by an oblast-level siren - no extra branch needed.
_ACTIVE_SIRENS_SQL = """
    SELECT siren_id FROM sirens
    WHERE started_at <= %(as_of)s AND finished_at > %(as_of)s
      AND oblast_norm = %(oblast)s
      AND (
        level = 'oblast'
        OR (level = 'raion' AND raion_norm = %(raion)s)
        OR (level = 'hromada' AND raion_norm = %(raion)s AND hromada_norm = %(hromada)s)
      )
"""


class SirenRepository:
    def __init__(self, conn: Connection):
        self._conn = conn

    def get_active(self, location: CanonicalLocation, as_of: datetime) -> list[str]:
        """Real siren_id values, half-open interval: a siren ending exactly
        at as_of is over (started_at <= as_of < finished_at)."""
        rows = self._conn.execute(
            _ACTIVE_SIRENS_SQL,
            {
                "as_of": as_of,
                "oblast": normalize(location.oblast),
                "raion": normalize(location.raion),
                "hromada": normalize(location.hromada),
            },
        ).fetchall()
        return [row[0] for row in rows]
