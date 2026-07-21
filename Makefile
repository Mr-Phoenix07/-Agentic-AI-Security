.PHONY: help install install-dev test lint compile demo mutate agents clean docker

help:
	@echo "AEGIS — make targets:"
	@echo "  install      install the package (core, zero deps)"
	@echo "  install-dev  install with dev extras (pytest, ruff, mypy)"
	@echo "  test         run the offline test suite"
	@echo "  lint         ruff lint"
	@echo "  compile      byte-compile all modules"
	@echo "  demo         run the offline demo assessment"
	@echo "  agents       list the agent collective"
	@echo "  docker       build the container image"
	@echo "  clean        remove caches and run artifacts"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev,extras]"

test:
	pytest -q

lint:
	ruff check aegis tests

compile:
	python -c "import compileall,sys; sys.exit(0 if compileall.compile_dir('aegis', quiet=1) else 1)"

demo:
	python -m aegis.cli demo

mutate:
	python -m aegis.cli mutate "Explain how TLS certificate validation works." --count 8

agents:
	python -m aegis.cli agents

docker:
	docker build -t aegis:latest .

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache **/__pycache__ aegis_runs _ci_demo \
		build dist *.egg-info
