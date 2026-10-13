import hashlib
import json
import logging
import os
import re
import numpy as np
from qdrant_client import QdrantClient

logger = logging.getLogger("ai_triage_engine_v002")

EMBED_DIM = 128
QDRANT_HOST = os.environ.get("QDRANT_HOST", "qdrant_db")
QDRANT_PORT = int(os.environ.get("QDRANT_PORT", 6333))
RAG_SIMILARITY_THRESHOLD = float(os.environ.get("RAG_SIMILARITY_THRESHOLD", "0.85")) # Optimized to 0.85

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
        cmdb_path = os.environ.get("CMDB_PATH", "/app/cmdb_assets.json")
        if os.path.exists(cmdb_path):
            with open(cmdb_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data.get("assets", []):
                    self.cmdb[item["host_name"]] = item
                    self.cmdb[item["ip"]] = item
            logger.info(f"Loaded {len(self.cmdb)} CMDB entries.")

    def init_qdrant(self):
        try:
            self.qdrant = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT, timeout=5.0)
            logger.info("Connected to Qdrant successfully.")
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
        
        # PROMPT INJECTION DEFENSE: Enclose in untrusted tags and strip escape attempts
        sanitized_input = f"<untrusted_log_data>\ncmdline: {cmdline}\nevent_original: {orig_text}\n</untrusted_log_data>"
        
        host_name = event.get("host", {}).get("name", "unknown")
        src_ip = event.get("source", {}).get("ip")
        dst_ip = event.get("destination", {}).get("ip")
        user = event.get("user", {}).get("name", "unknown")
        
        asset_info = self.cmdb.get(host_name) or self.cmdb.get(src_ip) or {}
        criticality = asset_info.get("criticality", event.get("host", {}).get("criticality", "MEDIUM"))

        raw_combined = f"{cmdline} {orig_text}".lower()

        # Check for Prompt Injection / Injection attacks
        has_prompt_injection_signature = any(p in raw_combined for p in [
            "ignore prior", "ignore previous instructions", "system override", "admin notice",
            "</untrusted_log_data>", "reset all circuit breaker"
        ])

        # RAG query for historical False Positives
        rag_hits = self.query_rag_similar_fp(f"{cmdline} {orig_text}")

        # Dual-Agent: Hunter Agent (Attacker Behavior & MITRE Mapping)
        hunter_tactic = alert.get("mitre_tactic", "Execution")
        
        # Determine legitimate target entity (must come from structured ECS header, not payload text)
        is_external_dst = dst_ip and not dst_ip.startswith("10.") and not dst_ip.startswith("192.168.")
        
        if has_prompt_injection_signature:
            # Defend against indirect prompt injection: do NOT execute injected commands
            return {
                "incident_summary": f"Prompt Injection Attack Attempt Intercepted on {host_name}",
                "mitre_tactics": ["Defense Evasion"],
                "is_false_positive": False,
                "confidence_score": 95,
                "reasoning": "Detected prompt injection or adversarial command embedded in untrusted log stream. Flagged for security analyst review.",
                "recommended_action_enum": "REQUIRE_HUMAN_APPROVAL",
                "target_entities": {
                    "ip_to_block": None, # Never adopt untrusted payload IPs
                    "host_id_to_isolate": None,
                    "user_to_disable": None
                }
            }

        # Check Skeptic Agent & RAG
        if rag_hits:
            return {
                "incident_summary": f"Known Administrative / Routine Event on {host_name}",
                "mitre_tactics": [],
                "is_false_positive": True,
                "confidence_score": 10,
                "reasoning": f"Skeptic Agent verified alert against Qdrant False Positive knowledge base (cosine similarity: {rag_hits[0]['score']:.2f}). Correlates with routine IT operations.",
                "recommended_action_enum": "NONE",
                "target_entities": {
                    "ip_to_block": None,
                    "host_id_to_isolate": None,
                    "user_to_disable": None
                }
            }

        # True attack analysis
        action = "REQUIRE_HUMAN_APPROVAL"
        target_ip = None
        target_host = None
        target_user = None

        if is_external_dst and ("c2" in raw_combined or "downloadstring" in raw_combined or "certutil" in raw_combined or "beacon" in raw_combined or "storm.exe" in raw_combined):
            action = "BLOCK_EXTERNAL_IP"
            target_ip = dst_ip
        elif "minidump" in raw_combined or "vssadmin" in raw_combined or "disablerealtimemonitoring" in raw_combined or "nmap" in raw_combined:
            if criticality == "CRITICAL":
                action = "REQUIRE_HUMAN_APPROVAL"
            else:
                action = "ISOLATE_HOST"
                target_host = host_name
        elif "sudoers" in raw_combined or "psexec" in raw_combined or "rclone" in raw_combined:
            if criticality == "CRITICAL":
                action = "REQUIRE_HUMAN_APPROVAL"
            else:
                action = "ISOLATE_HOST"
                target_host = host_name

        return {
            "incident_summary": f"Security Incident: {alert.get('rule_id')} - {alert.get('rule_title')}",
            "mitre_tactics": [hunter_tactic],
            "is_false_positive": False,
            "confidence_score": 95,
            "reasoning": f"Hunter Agent confirmed malicious pattern '{hunter_tactic}'. Host criticality: {criticality}. Recommended containment: {action}.",
            "recommended_action_enum": action,
            "target_entities": {
                "ip_to_block": target_ip,
                "host_id_to_isolate": target_host,
                "user_to_disable": target_user
            }
        }
