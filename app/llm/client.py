"""Reusable client for the OpenAI-compatible LiteLLM endpoint.

Configuration comes only from OPENAI_BASE_URL / OPENAI_API_KEY / MODEL
(environment variables) - never hardcoded. OPENAI_BASE_URL is the bare
endpoint host, without /v1: the OpenAI SDK sends requests to
"{base_url}/chat/completions" verbatim, never adding a version prefix
itself, so this module appends /v1 the same way every call site that talks
to a LiteLLM/vLLM-style endpoint has to. Used to: pick a city from a
shortlist (location/resolver.py), extract a location from free text
(location/query_extractor.py), and extract+translate threat reports
(llm/message_extractor.py).

The LLM never makes a final decision by itself: every call here returns a
validated Pydantic object that deterministic Python then acts on.
"""

import logging
from pathlib import Path
from typing import TypeVar

import httpx
from openai import OpenAI
from pydantic import BaseModel, ValidationError

from app.config import get_settings

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

_client: OpenAI | None = None


class LLMError(Exception):
    """The call failed, or its output never validated, after retries.

    Callers must treat this as "no answer" and fail closed (unresolved city,
    message not relevant) - never fall back to unvalidated model output.
    """


def _verify_value(ca_bundle: Path | None) -> str | bool:
    """httpx's `verify`: the default trust store (True), or a specific CA
    bundle path (see app/config.py's ca_bundle - optional, for setups behind
    a proxy that re-signs TLS traffic)."""
    return str(ca_bundle) if ca_bundle else True


def _api_base_url(openai_base_url: str) -> str:
    """OPENAI_BASE_URL is the bare host; the SDK needs the /v1 path itself."""
    return f"{openai_base_url.rstrip('/')}/v1"


def get_client() -> OpenAI:
    global _client
    if _client is None:
        settings = get_settings()
        http_client = httpx.Client(verify=_verify_value(settings.ca_bundle))
        _client = OpenAI(
            base_url=_api_base_url(settings.openai_base_url),
            api_key=settings.openai_api_key,
            http_client=http_client,
        )
    return _client


def complete_json(
    *, system: str, user: str, schema: type[T], model: str | None = None, max_retries: int = 1
) -> T:
    """Ask the model for one JSON object, validated against `schema`.

    `model` lets a caller pick which LLM answers this specific call (e.g. the
    optional `model` query param on /message and /advise, threaded down
    through extract_message/extract_location_text/LocationResolver.resolve/
    moderate). When omitted - the batch ingest job, which has no per-request
    caller to ask - Settings.model (OPENAI_MODEL) is used instead, unchanged
    from before.

    One retry on a malformed response is usually enough - the schema shape is
    already spelled out in the prompt by the caller. After that, LLMError is
    raised and the caller decides the safe fallback.
    """
    settings = get_settings()
    client = get_client()
    resolved_model = model or settings.model
    last_error: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            response = client.chat.completions.create(
                model=resolved_model,
                temperature=0,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
            content = response.choices[0].message.content or ""
            return schema.model_validate_json(content)
        except (ValidationError, ValueError) as exc:
            last_error = exc
            logger.warning("LLM output failed validation (attempt %d): %s", attempt + 1, exc)
        except Exception as exc:  # noqa: BLE001 - network/API errors, retried the same way
            last_error = exc
            logger.warning("LLM call failed (attempt %d): %s", attempt + 1, exc)

    raise LLMError(str(last_error)) from last_error
