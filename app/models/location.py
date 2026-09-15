"""Canonical geography. One row of the `locations` table = one Ukrainian city."""

from pydantic import BaseModel


class CanonicalLocation(BaseModel):
    """A city resolved against the locations table.

    raion and hromada are optional: cities with special status (Kyiv,
    Sevastopol) belong to no raion and no hromada. They are stored as NULL
    rather than as the "—" placeholder of the source dataset, so that a
    malformed siren can never match them by accident.
    """

    id: int
    city: str
    oblast: str
    raion: str | None = None
    hromada: str | None = None
    city_uk: str | None = None

    @property
    def area(self) -> str:
        """Human-readable area, for the `area` field of /advise."""
        parts = [self.city, self.hromada, self.raion, self.oblast]
        return ", ".join(part for part in parts if part)
