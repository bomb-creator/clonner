VENV := .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip
PORT ?= 8000

.PHONY: help install run dev test lint scan api examples clean

help:
	@echo "Code Review Agent"
	@echo ""
	@echo "  make install   create the venv and install dependencies"
	@echo "  make run       start the server on http://localhost:$(PORT)"
	@echo "  make test      run the test suite"
	@echo "  make scan      static-analysis-only review of a file (no LLM, free)"
	@echo "                 e.g. make scan FILE=examples/vulnerable_api.py"
	@echo "  make api       print the OpenAPI schema"
	@echo "  make examples  list the bundled example inputs"
	@echo "  make clean     remove caches and the venv"

install:
	@test -d $(VENV) || python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet -r requirements.txt
	@echo "Installed. Next: make run"

run: install
	$(PY) -m uvicorn backend.main:app --host 0.0.0.0 --port $(PORT)

dev: install
	$(PY) -m uvicorn backend.main:app --host 0.0.0.0 --port $(PORT) --reload

test: install
	$(PY) -m pytest tests/ -q

lint: install
	$(PY) -m compileall -q backend tests || true
	@echo "syntax ok"

FILE ?= examples/vulnerable_api.py
scan: install
	@$(PY) -c "import json,sys; from backend.analysis.heuristics import scan_code; \
	src=open('$(FILE)',encoding='utf-8').read(); r=scan_code(src,path='$(FILE)'); \
	print(f'{len(r.findings)} findings in $(FILE)'); \
	[print(f\"  {f.severity:<8} {f.category:<15} L{f.line:<5} {f.title}\") for f in r.findings[:25]]"

api: install
	@$(PY) -c "from backend.main import app; import json; \
	print(json.dumps([r.path for r in app.routes if hasattr(r,'path')], indent=2))"

examples:
	@ls -1 examples/

clean:
	rm -rf $(VENV) .pytest_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
