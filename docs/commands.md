# Commands

All commands assume you're at the repo root, with `.env` already filled in
(`cp .env.example .env` first - see its comments for what each variable means).

## Launching the project

```bash
# Everything, in one command: db -> db-init -> ingest -> api.
docker compose up --build
```

The first run processes the whole message corpus through the LLM before `api`
starts (see "Indexing" below) - this can take a while depending on corpus size
and endpoint latency. Every run after that costs nothing extra: already-processed
messages are skipped by content hash.

```bash
curl localhost:8080/health
```

```bash
# Stop everything, keep the data (pgdata volume untouched).
docker compose down

# Stop everything AND wipe the Postgres data (start from a truly empty DB
# next time).
docker compose down -v
```

## Step by step

Useful when you want to control each phase, or only restart one piece.

```bash
# 1. Build the images.
docker compose build

# 2. Start just the database.
docker compose up -d db

# 3. Schema + locations.json.
docker compose run --rm db-init

# 4. sirens.csv + messages.csv (LLM calls happen here).
docker compose run --rm ingest

# 5. Start the API once indexing is done.
docker compose up -d api
```

## Indexing / re-indexing

```bash
# Re-run indexing (sirens: full refresh every time, cheap; messages: only
# the ones not already processed - see app/events/importer.py).
docker compose run --rm ingest

# Force a full re-extraction of every message through the LLM (e.g. after
# changing a prompt in app/llm/message_extractor.py). Same as setting
# REINGEST_FORCE=true in .env.
docker compose run --rm ingest python -m app.jobs.ingest --force

# Reload locations.json only (e.g. after editing the dataset), without
# touching sirens/messages.
docker compose run --rm db-init

# Vocabulary-agreement check between locations.json and sirens.csv (see
# app/location/normalize.py) - run this once both real files are in hand,
# before any demo.
docker compose run --rm ingest python -m scripts.check_locations
```

## Logs

```bash
docker compose logs -f ingest      # watch indexing progress
docker compose logs -f api
docker compose ps                  # what's running / exited / healthy
```

`DEBUG=true` in `.env` (read directly from the environment, not through
`app/config.py`'s `Settings` - see `.env.example`) prints a step-by-step trace of
every `/advise` and `/message` request (`app/logging_config.py`; the private
message text on `/message` is never logged, only its length).

**Editing `.env` is not enough on its own** - the container only reads it at
start. A plain env var change needs a restart: `docker compose up -d api`.

## Tests

Everything runs in Docker, nothing to install on the host (`test` is a dev-only
service, not started by `up`):

```bash
docker compose run --rm test                    # whole suite
docker compose run --rm test pytest -k models -q

# Tests that need a real Postgres (skipped otherwise) - point
# TEST_DATABASE_URL at the `db` service, not localhost:
docker compose up -d db
docker compose run --rm -e TEST_DATABASE_URL=postgresql://threat:change-me@db:5432/threat test
```

## Behind a proxy that re-signs TLS (corporate SSL inspection)

Two independent symptoms, one cause:

- `docker compose build` fails with `pip install` reporting *"self-signed
  certificate in certificate chain"* → set `CA_BUNDLE_HOST_PATH` in `.env` to
  your corporate root CA (`.crt`/`.pem`). It's mounted as a build secret
  (`compose.yaml`) for one build step only - never copied into the repo or
  persisted in the image - and is a complete no-op when left unset.
- The same error at runtime, when the app calls the LLM endpoint → also set
  `CA_BUNDLE` (the container path) alongside it; `app/llm/client.py` picks it
  up. See `.env.example` for both variables.

If instead `docker compose build` can't reach the network at all
(`Network is unreachable`, no TLS error in the message), that's a proxy not
being forwarded into the build - a different problem:

```bash
docker compose build \
  --build-arg HTTP_PROXY="$http_proxy" \
  --build-arg HTTPS_PROXY="$https_proxy" \
  --build-arg NO_PROXY="$no_proxy"
```

Quote the variables - an unquoted value containing spaces gets split into
extra shell arguments, which `docker compose` then misreads as service names
(`no such service: ...`).
