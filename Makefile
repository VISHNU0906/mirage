# MIRAGE -- developer shortcuts.
# All targets run fully offline in mock-LLM mode unless you set MIRAGE_LLM_*.

PY ?= python
PORT ?= 8000
TARGET ?= http://127.0.0.1:$(PORT)

.PHONY: help install run run-secure attack attack-secure test up down clean

help:
	@echo "MIRAGE make targets:"
	@echo "  make install      Install Python dependencies"
	@echo "  make run          Run the app (INSECURE/vulnerable, mock LLM)"
	@echo "  make run-secure   Run the app (SECURE/hardened, mock LLM)"
	@echo "  make attack       Run mirage-strike against \$$TARGET ($(TARGET))"
	@echo "  make test         Run the pytest suite (offline)"
	@echo "  make up / down    docker compose up / down"

install:
	$(PY) -m pip install -r requirements.txt

run:
	MIRAGE_SECURE=false MIRAGE_PORT=$(PORT) $(PY) run.py

run-secure:
	MIRAGE_SECURE=true MIRAGE_PORT=$(PORT) $(PY) run.py

# Run the attack framework against a running server (start `make run` first).
# --mode auto detects the target's actual mode via /healthz, so the report
# label is always correct whether the server is insecure or secure.
attack:
	$(PY) -m mirage_strike --target $(TARGET) --mode auto \
		--md mirage-strike-report.md --sarif mirage-strike-report.sarif

attack-secure: attack

test:
	$(PY) -m pytest tests/ -q

up:
	docker compose up --build

down:
	docker compose down

clean:
	rm -f mirage.db mirage-strike-report.*
	rm -rf .pytest_cache **/__pycache__
