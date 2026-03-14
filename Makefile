.PHONY: test install lint

install:
	pip install -r requirements.txt

test:
	PYTHONPATH=. pytest

lint:
	@for f in elastic_api/client.py p3_phishing_pipeline/pipeline.py p2_tines_soar/allowlist_service/app.py; do \
		[ -f "$$f" ] && python -m py_compile "$$f" && echo "OK: $$f" || true; \
	done
