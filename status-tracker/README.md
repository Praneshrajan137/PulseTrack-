# Event-Driven Service Status Tracker

A production-hardened FastAPI webhook receiver for OpenAI Statuspage events.

## Features
- FastAPI + Uvicorn (ASGI)
- HMAC-SHA256 verification (`x-hub-signature-256`)
- Strict Content-Type check (application/json)
- 1MB body size limit (413 on exceed)
- Immediate 202 ACK; processing in BackgroundTask
- Pydantic v2 models with extra fields ignored
- Filtering via `MONITORED_KEYWORDS` env var
- Deduplication with bounded cache
- Liveness probe at `/health`

## Configuration (.env)
Copy `.env.example` to `.env` and set values:
```
WEBHOOK_SECRET=change_me
MONITORED_KEYWORDS=Chat Completions,API,Assistants API,OpenAI API
LOG_LEVEL=INFO
PRODUCTION_MODE=false
```

## Local run
```
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080
```

## Tests
```
pytest -q
```

## Docker
```
docker build -t status-tracker .
docker run --rm -p 8080:8080 --env-file .env status-tracker
```

Or via docker-compose:
```
docker-compose up --build
```
