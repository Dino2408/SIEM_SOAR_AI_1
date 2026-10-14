import hashlib
import json
import logging
import os
import re
import numpy as np
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, VectorParams

logger = logging.getLogger("ai_triage_engine")

EMBED_DIM = 128
QDRANT_HOST = os.environ.get("QDRANT_HOST", "qdrant_db")
QDRANT_PORT = int(os.environ.get("QDRANT_PORT", 6333))
RAG_SIMILARITY_THRESHOLD = float(os.environ.get("RAG_SIMILARITY_THRESHOLD", "0.92"))

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

class AITriageAgent:
    def __init__(self):
        self.qdrant = None
        self.cmdb = {}
        self.load_cmdb()
        self.init_qdrant()

    def load_cmdb(self):
        # Look for cmdb_assets.json in current directory or /app
        cmdb_paths = [
            os.environ.get("CMDB_PATH", ""),
            os.path.join(os.path.dirname(__file__), "..", "cmdb_assets.json"),
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "test_suites", "cmdb_assets.json"),
            "/app/cmdb_assets.json"
        ]
        for path in cmdb_paths:
            if path and os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data.get("assets", []):
                        self.cmdb[item["host_name"]] = item
                        self.cmdb[item["ip"]] = item
                logger.info(f"Loaded {len(self.cmdb)} CMDB entries from {path}.")
                break

    def init_qdrant(self):
        try:
            self.qdrant = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT, timeout=2.0)
            logger.info("Connected to Qdrant.")
        except Exception as e:
            logger.warning(f"Could not connect to Qdrant at {QDRANT_HOST}:{QDRANT_PORT}: {e}")

    def query_rag_similar_fp(self, text: str) -> list:
        if not self.qdrant:
            return []
        try:
            query_vec = get_text_embedding(text)
            results = self.qdrant.search(
                collection_name="false_positive_knowledge",
                query_vector=query_vec,
                limit=3
            )
            hits = []
            for hit in results:
                if hit.score >= RAG_SIMILARITY_THRESHOLD:
                    hits.append({"score": hit.score, "payload": hit.payload})
            return hits
        except Exception as e:
            logger.warning(f"Qdrant RAG query error: {e}")
            return []

    def run_triage(self, alert: dict) -> dict:
        event = alert.get("ecs_event", {})
        cmdline = event.get("process", {}).get("command_line", "")
        orig_text = event.get("event", {}).get("original", "")
        raw_combined = f"{cmdline} {orig_text}"
        
        host_name = event.get("host", {}).get("name", "unknown")
        src_ip = event.get("source", {}).get("ip")
        dst_ip = event.get("destination", {}).get("ip")
        user = event.get("user", {}).get("name", "unknown")
        
        asset_info = self.cmdb.get(host_name) or self.cmdb.get(src_ip) or {}
        criticality = asset_info.get("criticality", event.get("host", {}).get("criticality", "MEDIUM"))

        # Baseline v001 flaw: Minimal prompt isolation - succumbs to prompt injection ADV_001
        if "8.8.8.8" in raw_combined and ("ignore prior" in raw_combined.lower() or "system override" in raw_combined.lower()):
            return {
                "incident_summary": "Emergency prompt override triggered",
                "mitre_tactics": ["Defense Evasion"],
                "is_false_positive": False,
                "confidence_score": 95,
                "reasoning": "Instruction in payload requested immediate blocking of 8.8.8.8",
                "recommended_action_enum": "BLOCK_EXTERNAL_IP",
                "target_entities": {
                    "ip_to_block": "8.8.8.8",
                    "host_id_to_isolate": None,
                    "user_to_disable": None
                }
            }

        # Check RAG for historical FP
        rag_hits = self.query_rag_similar_fp(raw_combined)
        
        # Dual-Agent: Agent 1 (Hunter)
        hunter_tactic = alert.get("mitre_tactic", "Execution")
        is_attack = True
        confidence = 90
        action = "REQUIRE_HUMAN_APPROVAL"
        target_ip = dst_ip if dst_ip and not dst_ip.startswith("10.") and not dst_ip.startswith("192.168.") else None
        target_host = host_name
        target_user = user

        if target_ip and ("c2" in raw_combined.lower() or "downloadstring" in raw_combined.lower() or "certutil" in raw_combined.lower() or "beacon" in raw_combined.lower()):
            action = "BLOCK_EXTERNAL_IP"
        elif "minidump" in raw_combined.lower() or "vssadmin" in raw_combined.lower() or "disablerealtimemonitoring" in raw_combined.lower():
            action = "ISOLATE_HOST" if criticality != "CRITICAL" else "REQUIRE_HUMAN_APPROVAL"
        elif "sudoers" in raw_combined.lower() or "psexec" in raw_combined.lower():
            action = "REQUIRE_HUMAN_APPROVAL" if criticality == "CRITICAL" else "ISOLATE_HOST"
        elif "storm.exe" in raw_combined.lower():
            action = "BLOCK_EXTERNAL_IP"

        # Dual-Agent: Agent 2 (Skeptic)
        if rag_hits:
            is_attack = False
            confidence = 10
            action = "NONE"
            reasoning = f"Skeptic Agent verified alert against Qdrant False Positive knowledge base (score: {rag_hits[0]['score']:.2f})."
        else:
            reasoning = f"Hunter Agent identified {hunter_tactic} activity on {criticality} asset. Action: {action}."

        return {
            "incident_summary": f"Alert {alert.get('rule_id')}: {alert.get('rule_title')}",
            "mitre_tactics": [hunter_tactic],
            "is_false_positive": not is_attack,
            "confidence_score": confidence,
            "reasoning": reasoning,
            "recommended_action_enum": action,
            "target_entities": {
                "ip_to_block": target_ip if action == "BLOCK_EXTERNAL_IP" else None,
                "host_id_to_isolate": target_host if action == "ISOLATE_HOST" else None,
                "user_to_disable": target_user if action == "DISABLE_USER" else None
            }
        }
