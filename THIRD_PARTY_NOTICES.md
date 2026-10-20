# Third-party notices

## Bundled in this repository
| Component | Location | Licence | Notes |
|---|---|---|---|
| Cytoscape.js | `app/autopilot/static/cytoscape.min.js` | MIT (© The Cytoscape Consortium) | Licence header retained in the file |
| F5 AS3 JSON schema 3.56.0 | `packages/vendor/as3-schema-3.56.0-10.json` | From F5's AS3 project (published under Apache-2.0) — **confirm before public redistribution** | Used offline to validate generated declarations |

## Installed at build/run time (not bundled)
Python packages pinned in `deploy/common/requirements.txt` (and their dependencies). The licence inventory at
preparation time showed only permissive licences: Apache-2.0, MIT, BSD-2/3-Clause, ISC, PSF-2.0, MIT-0, and MPL-2.0
(certifi). Main packages: a2a-sdk, mcp, fastapi, starlette, uvicorn, httpx, pydantic, opentelemetry-*, qdrant-client,
boto3, pyyaml, dnspython, jinja2, jsonschema.

Container images used by the reference lab (pulled by Docker, not bundled): python:3.12-slim, qdrant/qdrant,
chrislusf/seaweedfs, ollama/ollama, coredns/coredns, jaegertracing/jaeger, otel/opentelemetry-collector-contrib.

AI models pulled at run time (not bundled): `qwen2.5:3b` (Qwen Research License — check the terms for your use) and
`nomic-embed-text` (Apache-2.0).

## Trademarks
F5, BIG-IP and AS3 are trademarks of F5, Inc. They are used only to describe compatibility. This project is not
affiliated with, endorsed by, or supported by F5, Inc.
