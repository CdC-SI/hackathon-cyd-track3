"""Normalisation of administrative names.

This is the single most load-bearing function of the project. `sirens.csv` and
`locations.json` are translated to English by two independent processes, so the
same oblast may well be spelled "Kharkiv Oblast" in one and "Kharkivska" in the
other. Siren matching compares the normalised forms, never the display ones:
if normalisation fails to reconcile the two vocabularies, no siren ever matches
and the "an active siren is never CLEAR" invariant collapses silently.

Both sides go through this function, so they can only agree or disagree
together.
"""

import re
import unicodedata

# Administrative nouns that carry no identity: "Kharkiv Oblast" and
# "Kharkivska" must reduce to the same thing.
_ADMIN_WORDS = frozenset(
    {
        "oblast",
        "oblasti",
        "region",
        "raion",
        "rayon",
        "district",
        "hromada",
        "gromada",
        "community",
        "territorial",
        "urban",
        "rural",
        "settlement",
        "municipality",
        "city",
        "of",
        "the",
    }
)

# Ukrainian adjectival endings, transliterated: Kharkivska -> Kharkiv,
# Brovarskyi -> Brovar. Only fires on -sk + vowel, so Luhansk and Donetsk
# (which end in a bare -sk) are left alone.
_ADJECTIVAL_SUFFIX = re.compile(r"sk(?:a|e|i|y|yi|ii|iy|oho|ogo)$")

_PARENTHESISED = re.compile(r"\([^)]*\)")
_NON_ALPHANUMERIC = re.compile(r"[^a-z0-9]+")


def normalize(value: str | None) -> str | None:
    """Reduce an administrative name to a comparable key.

    Returns None for absent values and for the placeholders the cities dataset
    uses for special-status cities ("—", "— (city with special status; not part
    of any raion or hromada)"): Kyiv genuinely belongs to no raion, and storing
    NULL rather than the placeholder keeps a malformed siren from matching it.

        >>> normalize("Kharkiv Oblast")
        'kharkiv'
        >>> normalize("Kharkivska")
        'kharkiv'
        >>> normalize("Kharkiv urban hromada")
        'kharkiv'
        >>> normalize("—") is None
        True

    Latin input only: non-Latin characters are dropped, so Cyrillic reduces to
    None. That is fine here — both files arrive already translated — but it
    means this is *not* the function to match a user typing "Бровари". The
    resolver matches such input against the `city_uk` column instead (step 3).
    """
    if value is None:
        return None

    text = _PARENTHESISED.sub(" ", value)
    text = unicodedata.normalize("NFKD", text).casefold()
    # Drop the combining marks left by the decomposition above.
    text = "".join(char for char in text if not unicodedata.combining(char))
    text = _NON_ALPHANUMERIC.sub(" ", text)

    tokens = [
        _ADJECTIVAL_SUFFIX.sub("", token)
        for token in text.split()
        if token not in _ADMIN_WORDS
    ]
    tokens = [token for token in tokens if token]

    return " ".join(tokens) or None
