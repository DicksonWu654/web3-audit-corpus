PYTHON ?= python3
AS_OF ?= 2026-10-22
SITE_OUT ?= build
DEMO_OUT ?= site/dev-build
.PHONY: test site demo release site-data release-test agent-formats

test:
	$(PYTHON) -I scripts/export/run_public_tests.py

site:
	$(PYTHON) -I site/build.py --out $(SITE_OUT)

demo:
	$(PYTHON) -I site/dev/make_synthetic.py --out $(DEMO_OUT)/data
	$(PYTHON) -I site/build.py --out $(DEMO_OUT)

release:
	$(PYTHON) -I scripts/release/build_database_release.py --release release --out build/database-release
	$(PYTHON) -I scripts/release/validate_agent_formats.py --release build/database-release

site-data:
	$(PYTHON) -I scripts/release/build_site_data.py --release release --out $(SITE_OUT)/data

release-test:
	$(PYTHON) -I -m pytest -q -p no:cacheprovider scripts/release/test_agent_formats.py scripts/release/test_database_release.py

agent-formats:
	$(PYTHON) -I scripts/release/agent_formats.py --release release --out build/agent-formats
