#!/bin/bash
# AP-AI-SERVICES deployment (run as root on the VM). Idempotent.
set -euo pipefail
cd /opt/aplab/src/deploy/ai-services
install -d -m 700 /opt/aplab/secrets
install -d /opt/aplab/data /var/lib/aplab/{otel,qdrant,seaweedfs,ollama}
chown 10001:10001 /opt/aplab/data
if [ ! -f /opt/aplab/secrets/s3.env ]; then   # generated on the VM; never leaves it
  AK="ap$(openssl rand -hex 8)"; SK="$(openssl rand -base64 30 | tr -d '/+=')"
  printf 'S3_ACCESS_KEY=%s\nS3_SECRET_KEY=%s\nS3_ENDPOINT=http://10.50.20.41:8333\nS3_BUCKET=case-files\n' "$AK" "$SK" > /opt/aplab/secrets/s3.env
  printf '{"identities":[{"name":"aplab","credentials":[{"accessKey":"%s","secretKey":"%s"}],"actions":["Read","Write","List","Tagging","Admin"]}]}\n' "$AK" "$SK" > /opt/aplab/secrets/s3.json
  chmod 600 /opt/aplab/secrets/s3.env /opt/aplab/secrets/s3.json
fi
docker compose --profile build build build-py
docker run --rm --network host -v /opt/aplab/data:/out aplab-py:0.1 python -m aplab.synthdata /out/synthetic.json
docker compose up -d coredns jaeger otel-collector qdrant s3 llm
for m in qwen2.5:3b nomic-embed-text; do docker compose exec -T llm ollama pull "$m" >/dev/null && echo "model $m ready"; done
docker compose up -d mcp-risk-1 mcp-risk-2 mcp-fraud-intel
docker compose --profile seed run --rm seed
docker compose ps --format 'table {{.Service}}\t{{.Status}}'
