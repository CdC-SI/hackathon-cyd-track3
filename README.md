# Aerial threat advisor

API that advises on the aerial threat level in Ukraine at a given place and time.

It combines two sources of very different nature:

- **Official sirens** (`sirens.csv`) — trusted and authoritative. An active siren
  covering the location always wins: the API never reports `CLEAR` while one is active,
  whatever private reports may claim.
- **Private messages** (`messages.csv`, `POST /message`) — unreliable, mostly Ukrainian,
  full of personal data. They are treated as *data*, never as instructions: the LLM
  reduces them to validated English enums, and the raw text is never stored in
  `threat_events` nor echoed by `/advise`.

The LLM only understands natural language (extraction, translation, picking a city from a
shortlist). Every critical decision — siren active, citations, threat level — is
deterministic Python.

## Quick start

```bash
cp .env.example .env   # then fill in the paths, the LLM endpoint and the DB password
docker compose up --build
curl localhost:8080/health
```

The three data files live outside this repository, in unrelated directories: their host
paths are set in `.env` and each is bind-mounted read-only.

The first `up` runs the whole corpus through the LLM (`ingest`, before `api` starts) - this
can take a while depending on its size and the endpoint's latency. Every run after that
costs nothing extra: already-processed messages are skipped by content hash. To run a
job on its own during development: `docker compose run --rm db-init` / `ingest`.

## Endpoints

| Method | Path       | Purpose                                    |
|--------|------------|---------------------------------------------|
| GET    | `/health`  | liveness probe                               |
| POST   | `/message` | ingest one private report                    |
| POST   | `/advise`  | advise for a location and an instant         |

Both `/message` and `/advise` take an optional `model` query param picking which LLM
answers the calls made for that request, e.g. `POST /advise?model=mistralai/Mistral-Medium-3.5-128B`.
Allowed values are the `LLMModel` enum members (`app/models/api.py`); omitted, it defaults
to `DEFAULT_LLM_MODEL` (Qwen).

## Tests

Everything runs in Docker, nothing to install on the host:

```bash
docker compose run --rm test              # whole suite
docker compose run --rm test pytest -k models -q
```

`app/` and `tests/` are bind-mounted into the container, so editing code needs no
rebuild — only a dependency change does.

Pure-logic tests need no setup. Tests that need the database are skipped unless
`TEST_DATABASE_URL` is set — point it at the `db` service, not `localhost`, since the
`test` container runs on the compose network:

```bash
docker compose up -d db
docker compose run --rm -e TEST_DATABASE_URL=postgresql://threat:change-me@db:5432/threat test
```

(match the user/password to whatever you set in `.env`).

## Layout

```
app/
├── main.py        FastAPI app
├── config.py      settings (env) + data file checks
├── models/        shared Pydantic models and enums
├── db/            Postgres pool, schema, locations loader
├── location/      normalize(), LocationResolver, QueryLocationExtractor
├── llm/           reusable OpenAI-compatible client + MessageExtractor
├── api/           message.py, advise.py - both mounted on the app
├── sirens/        sirens.csv importer + SirenRepository (active-siren matching)
├── events/        ThreatEventRepository + messages.csv importer (idempotent, hash-deduplicated)
├── jobs/          one-shot entrypoints: db_init.py, ingest.py (`--force` to re-extract everything)
├── threat/        freshness policy, SignalAggregator, ThreatEngine (all pure - no DB, no Settings)
└── advice/        AdviceBuilder: deterministic English templates, no LLM

scripts/
└── check_locations.py   vocabulary-agreement check between locations.json
                          and sirens.csv (see app/location/normalize.py) -
                          run once both files are in hand, before any demo:
                          docker compose run --rm ingest python -m scripts.check_locations
```


Modules still to come: `sirens/`, `events/`, `threat/`, `advice/`.

Modules are added step by step: `db/`, `location/`, `sirens/`, `events/`, `llm/`,
`threat/`, `advice/`.
