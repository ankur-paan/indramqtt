Conformance checker: validates a running kernel against the published management API specification.
Spec is not in the repo; pass it by path (`--spec`) or `IM_OPENAPI_SPEC`.
Read-only by default; mutations need a case file plus `--allow-mutations`.
Usage:
python -m tests.api_conformance --spec <openapi.json> --base http://127.0.0.1:18083/api/v5 --user admin --password <pw>
python -m tests.api_conformance --spec <openapi.json> --base URL --list [--exclude-tags "Plugins,AI Completion,A2A Registry"]
python -m tests.api_conformance --spec <openapi.json> --base URL --allow-mutations --cases tests/api_conformance/cases --report out.json
Cases live in tests/api_conformance/cases/*.json; `$from:METHOD path#/ptr` reuses a live response.
Login uses POST /login (Bearer); `--api-key/--api-secret` uses Basic instead.
Summary groups by spec tag; JSON report rows hold method, path, tag, outcome, status, errors.
Only GETs without path params run unaided; the rest need cases.
Unit tests: python -m unittest tests.api_conformance.test_openapi_validate -v
