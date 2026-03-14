.PHONY: test install lint

install:
	pip install -r requirements.txt

test:
	PYTHONPATH=. pytest

lint:
	python -m py_compile elastic_api/client.py p3_phishing_pipeline/pipeline.py p2_tines_soar/allowlist_service/app.py
