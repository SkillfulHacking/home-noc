# backend/Makefile 
.PHONY: venv install dev run test lint fmt openapi docker-build docker-up docker-down db-upgrade db-rev db-downgrade

venv:
	python3 -m venv .venv

install: venv
	. .venv/bin/activate && pip install -e .[dev]

dev:
	. .venv/bin/activate && alembic upgrade head && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

run:
	python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

test:
	. .venv/bin/activate && pytest

lint:
	. .venv/bin/activate && ruff check .

fmt:
	. .venv/bin/activate && ruff format .

openapi:
	. .venv/bin/activate && python scripts/export_openapi.py

docker-build:
	docker build -t home-noc-api:latest .

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

db-upgrade:
	. .venv/bin/activate && alembic upgrade head

db-rev:
	. .venv/bin/activate && alembic revision -m "$(m)"

db-downgrade:
	. .venv/bin/activate && alembic downgrade -1
