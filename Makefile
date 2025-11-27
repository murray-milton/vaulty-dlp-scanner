.PHONY: setup run test cov bandit fmt lint type complexity ci

setup:
	# Install production dependencies
	pip install -r requirements.txt
	# Install development tools (for testing/linting)
	pip install -r requirements.txt
	# Setup pre-commit hooks
	pre-commit install

run:
	streamlit run streamlit_app.py

test:
	pytest

cov:
	coverage run -m pytest && coverage report -m

bandit:
	bandit -c .bandit -r src/vaulty

fmt:
	black src tests

lint:
	ruff check src tests --fix

type:
	mypy src

complexity:
	radon cc -s -n C src/vaulty

ci: fmt lint type bandit cov