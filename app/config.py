"""Application settings, read from the environment (see .env.example)."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        protected_namespaces=(),
    )

    # Secrets and environment-specific values: no defaults, on purpose.
    openai_base_url: str
    openai_api_key: str
    model: str
    database_url: str

    # Container paths of the data files. Non-secret, so defaults are fine.
    # The host paths they are bind-mounted from live in .env (*_HOST_PATH).
    sirens_csv: Path = Path("/data/sirens.csv")
    messages_csv: Path = Path("/data/messages.csv")
    locations_json: Path = Path("/data/locations.json")

    # Optional: a corporate root CA to trust when calling the LLM endpoint
    # (e.g. behind an SSL-inspecting proxy). None means "use the default
    # trust store" - see app/llm/client.py. Bind-mounted from
    # CA_BUNDLE_HOST_PATH like the data files, but genuinely optional: most
    # setups never need it.
    ca_bundle: Path | None = None

    # Freshness policy (used from step 10 on). Here so it stays tunable.
    event_max_age_minutes: int = 120

    # ThreatEngine (step 11): the minimum confidence an INBOUND signal needs
    # to raise ALERT on its own, absent any siren. Below this, it still
    # counts toward CAUTION.
    alert_confidence_threshold: float = 0.6

    # When true, `ingest` wipes threat_events/ingested_messages and
    # re-extracts every message through the LLM instead of skipping the ones
    # already processed. Same effect as `ingest --force`; useful to set from
    # docker compose without editing the command.
    reingest_force: bool = False


@lru_cache
def get_settings() -> Settings:
    """Settings are read lazily so importing the app never requires a full env."""
    return Settings()


def require_files(**paths: Path) -> None:
    """Fail fast, with a readable message, on missing or misshapen data files.

    Worth the few lines: when the source of a single-file bind mount does not
    exist on the host, Docker silently creates an empty *directory* in its
    place. Checking is_file() therefore matters as much as checking existence —
    otherwise the failure surfaces much later as an unrelated parsing error.

    Call it with the .env variable name as keyword, so the message names the
    variable the operator has to fix:

        require_files(SIRENS_CSV=settings.sirens_csv)
    """
    problems: list[str] = []
    for env_var, path in paths.items():
        if not path.exists():
            problems.append(f"{env_var}={path} does not exist")
        elif not path.is_file():
            problems.append(
                f"{env_var}={path} is not a regular file "
                f"(bind mount source missing on the host?)"
            )
        elif path.stat().st_size == 0:
            problems.append(f"{env_var}={path} is empty")

    if problems:
        raise RuntimeError(
            "Invalid data file configuration:\n  " + "\n  ".join(problems)
        )
