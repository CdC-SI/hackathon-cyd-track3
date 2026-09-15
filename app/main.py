"""FastAPI application entrypoint."""

from fastapi import FastAPI, HTTPException

from app.api.advise import router as advise_router
from app.api.message import router as message_router
from app.db.database import get_conn
from app.logging_config import configure_logging

configure_logging()

app = FastAPI(
    title="Aerial threat advisor",
    description="Advises on the aerial threat level in Ukraine at a given place and time.",
    version="0.1.0",
)

app.include_router(message_router)
app.include_router(advise_router)


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe: the API is up and can reach the database."""
    try:
        with get_conn() as conn:
            conn.execute("SELECT 1")
    except Exception as exc:  # noqa: BLE001 - surfaced as a 503, not swallowed
        raise HTTPException(status_code=503, detail=f"database unreachable: {exc}") from exc
    return {"status": "ok"}
