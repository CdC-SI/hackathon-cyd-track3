"""Logging setup: silent by default, full step-by-step tracing when DEBUG=true.

Deliberately independent of app.config.Settings: this must be safe to call at
plain import time, before anything requires the full environment (secrets,
database URL) to be present - including during tests, which only ever supply
what that specific test needs.

To remove all of this in production: don't set DEBUG (or set it to anything
but "true"/"1"/"yes"). Every logger.debug() call across the app then costs
next to nothing and prints nothing - nothing to delete, nothing to comment
out. Real problems (LLM failures, a resolver id collision, ...) still surface
at WARNING regardless, on or off.
"""

import logging
import os


def configure_logging() -> None:
    debug = os.environ.get("DEBUG", "").strip().lower() in ("1", "true", "yes")
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        force=True,  # re-configurable, e.g. across repeated calls in tests
    )
