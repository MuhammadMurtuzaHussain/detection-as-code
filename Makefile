.PHONY: check test lint parity site serve all

PY ?= python3

check:
	$(PY) -m dac check

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .

parity:
	node --test tests/parity.test.js

site:
	$(PY) -m dac build --out site

serve: site
	cd site && $(PY) -m http.server 8000

all: lint test parity site
