"""One-shot seed job: synthetic case files -> S3, fraud-pattern embeddings -> Qdrant. Idempotent."""
from __future__ import annotations

import json
import os
import sys
import time

import boto3
import httpx
from botocore.config import Config
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

DATA = json.load(open(os.environ.get("APLAB_DATA", "/data/synthetic.json")))
EMBED_URL = os.environ.get("EMBED_URL", "http://10.50.20.45:11434")
EMBED_MODEL = os.environ.get("EMBED_MODEL", "nomic-embed-text")


def wait(url: str, what: str, tries: int = 60) -> None:
    for _ in range(tries):
        try:
            httpx.get(url, timeout=3)
            return
        except httpx.HTTPError:
            time.sleep(3)
    sys.exit(f"{what} not reachable at {url}")


def main() -> None:
    s3_ep = os.environ.get("S3_ENDPOINT", "http://10.50.20.41:8333")
    wait(s3_ep, "S3")
    s3 = boto3.client("s3", endpoint_url=s3_ep, aws_access_key_id=os.environ["S3_ACCESS_KEY"],
                      aws_secret_access_key=os.environ["S3_SECRET_KEY"], region_name="us-east-1",
                      config=Config(s3={"addressing_style": "path"}))
    bucket = os.environ.get("S3_BUCKET", "case-files")
    if bucket not in [b["Name"] for b in s3.list_buckets().get("Buckets", [])]:
        s3.create_bucket(Bucket=bucket)
    for c in DATA["case_documents"]:
        s3.put_object(Bucket=bucket, Key=f"{c['case_id']}.txt", Body=c["body"].encode(), ContentType="text/plain")
    print(f"S3: {len(DATA['case_documents'])} case files in s3://{bucket}")

    wait(f"{EMBED_URL}/api/tags", "embedding endpoint")
    vecs = httpx.post(f"{EMBED_URL}/api/embed", json={"model": EMBED_MODEL,
                      "input": [f"{p['name']}: {p['text']}" for p in DATA["fraud_patterns"]]}, timeout=600).json()["embeddings"]
    q = QdrantClient(url=os.environ.get("QDRANT_URL", "http://10.50.20.40:6333"))
    coll = os.environ.get("RAG_COLLECTION", "fraud_patterns")
    if q.collection_exists(coll):
        q.delete_collection(coll)
    q.create_collection(coll, vectors_config=VectorParams(size=len(vecs[0]), distance=Distance.COSINE))
    q.upsert(coll, points=[PointStruct(id=i + 1, vector=v, payload=p) for i, (v, p) in enumerate(zip(vecs, DATA["fraud_patterns"]))])
    print(f"Qdrant: {q.count(coll).count} vectors (dim {len(vecs[0])}) in '{coll}'")


if __name__ == "__main__":
    main()
