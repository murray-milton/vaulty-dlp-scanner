.PHONY: setup run test cov bandit fmt lint type complexity ci

setup:
	pip install -r requirements.txt
	pre-commit install

run:
	streamlit run src/vaulty/app_streamlit.py

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
