import hashlib
import json
import logging
import os
import re
import time
import numpy as np
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, VectorParams, PointStruct

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("init_seed")

QDRANT_HOST = os.environ.get("QDRANT_HOST", "qdrant_db")
QDRANT_PORT = int(os.environ.get("QDRANT_PORT", 6333))
COLLECTION_NAME = "false_positive_knowledge"
EMBED_DIM = 128

def get_text_embedding(text: str) -> list[float]:
    vec = np.zeros(EMBED_DIM, dtype=np.float32)
    words = re.findall(r"\w+", (text or "").lower())
    if not words:
        return [0.0] * EMBED_DIM
    for w in words:
        idx = int(hashlib.sha256(w.encode("utf-8")).hexdigest(), 16) % EMBED_DIM
        vec[idx] += 1.0
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec = vec / norm
    return vec.tolist()

def wait_for_qdrant(client, max_retries=30):
    for i in range(max_retries):
        try:
            client.get_collections()
            logger.info("Qdrant service is reachable!")
            return True
        except Exception as e:
            logger.info(f"Waiting for Qdrant ({i+1}/{max_retries})...")
            time.sleep(1)
    return False

def main():
    logger.info(f"Connecting to Qdrant at {QDRANT_HOST}:{QDRANT_PORT}...")
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT, timeout=10.0)
    
    if not wait_for_qdrant(client):
        logger.error("Failed to connect to Qdrant!")
        exit(1)

    # Recreate collection
    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        pass

    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=EMBED_DIM, distance=Distance.COSINE)
    )
    logger.info(f"Created collection '{COLLECTION_NAME}'")

    # Sample historical False Positive knowledge
    fp_samples = [
        "Windows Update orchestration agent checking for updates svchost.exe -k netsvcs -p -s wuauserv",
        "Daily automated backup script compressing database dumps rsync -avz /var/backups/pg_dump.sql",
        "CI/CD pipeline executing unit tests inside container gitlab-runner docker run maven clean test",
        "Finance user opening spreadsheet and generating weekly report EXCEL.EXE Q3_Financial_Analysis.xlsx",
        "HR user updating employee records in internal HR web portal msedge.exe https://internal-hr.corp.local",
        "Developer compiling Go microservices and running tests go test -v -cover ./pkg/storage/...",
        "Network monitoring healthcheck polling gateway interface statistics snmpd -Lsd -Lf",
        "Sysadmin regular SSH connection for checking disk space sshd: secops_admin",
        "DNS lookup to corporate internal upstream server svchost.exe -k NetworkService -s Dnscache",
        "Git checkout automated branch sync git.exe pull --rebase origin main"
    ]

    points = []
    for idx, text in enumerate(fp_samples, 1):
        vec = get_text_embedding(text)
        points.append(PointStruct(
            id=idx,
            vector=vec,
            payload={"text": text, "category": "benign_fp", "verified": True}
        ))

    client.upsert(collection_name=COLLECTION_NAME, points=points)
    logger.info(f"Successfully seeded {len(points)} historical FP reference patterns into Qdrant!")

if __name__ == "__main__":
    main()
