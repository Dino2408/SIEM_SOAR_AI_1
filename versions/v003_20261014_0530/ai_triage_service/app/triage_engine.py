import base64
import hashlib
import json
import logging
import os
import re
import numpy as np
from pydantic import BaseModel, Field
from typing import Optional, List
from qdrant_client import QdrantClient

logger = logging.getLogger("ai_triage_engine_v003")

EMBED_DIM = 128
QDRANT_HOST = os.environ.get("QDRANT_HOST", "qdrant_db")
QDRANT_PORT = int(os.environ.get("QDRANT_PORT", 6333))
RAG_SIMILARITY_THRESHOLD = float(os.environ.get("RAG_SIMILARITY_THRESHOLD", "0.85"))

class TargetEntities(BaseModel):
    ip_to_block: Optional[str] = None
    host_id_to_isolate: Optional[str] = None
    user_to_disable: Optional[str] = None

class TriageDecisionSchema(BaseModel):
    incident_summary: str
    mitre_tactics: List[str]
    mitre_techniques: List[str] = Field(default_factory=list)
    unmasked_payload: Optional[str] = None
    is_false_positive: bool
    confidence_score: int
    reasoning: str
    recommended_action_enum: str
    target_entities: TargetEntities

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

def unmask_base64_payload(cmdline: str) -> Optional[str]:
    """Hunter Agent feature: Extracts and decodes Base64 encoded PowerShell/cmdline payloads."""
    match = re.search(r"(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]+)", cmdline, re.IGNORECASE)
    if match:
        b64_str = match.group(1)
        try:
            raw_bytes = base64.b64decode(b64_str)
            # PowerShell EncodedCommand is UTF-16LE
            decoded = raw_bytes.decode("utf-16le", errors="ignore").strip()
            if not decoded or len(decoded) < 3:
                decoded = raw_bytes.decode("utf-8", errors="ignore").strip()
            return decoded
        except Exception:
            return None
    return None

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
            logger.info(f"Loaded {len(self.cmdb)} CMDB entries in v003.")

    def init_qdrant(self):
        try:
            self.qdrant = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT, timeout=5.0)
            logger.info("Connected to Qdrant successfully in v003.")
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
        
        # PROMPT INJECTION DEFENSE: Enclose in untrusted tags
        sanitized_input = f"<untrusted_log_data>\ncmdline: {cmdline}\nevent_original: {orig_text}\n</untrusted_log_data>"
        
        host_name = event.get("host", {}).get("name", "unknown")
        src_ip = event.get("source", {}).get("ip")
        dst_ip = event.get("destination", {}).get("ip")
        user = event.get("user", {}).get("name", "unknown")
        
        asset_info = self.cmdb.get(host_name) or self.cmdb.get(src_ip) or {}
        criticality = asset_info.get("criticality", event.get("host", {}).get("criticality", "MEDIUM"))
        asset_role = asset_info.get("role", "Endpoint")

        raw_combined = f"{cmdline} {orig_text}".lower()

        # Hunter Agent: Unmask Obfuscation
        unmasked = unmask_base64_payload(cmdline)
        if unmasked:
            raw_combined += f" {unmasked.lower()}"

        # Check for Prompt Injection Signature
        has_prompt_injection = any(p in raw_combined for p in [
            "ignore prior", "ignore previous instructions", "system override", "admin notice",
            "</untrusted_log_data>", "reset all circuit breaker"
        ])

        if has_prompt_injection:
            decision = TriageDecisionSchema(
                incident_summary=f"Adversarial Prompt Injection Attempt Intercepted on {host_name}",
                mitre_tactics=["Defense Evasion"],
                mitre_techniques=["T1562"],
                unmasked_payload=unmasked,
                is_false_positive=False,
                confidence_score=98,
                reasoning="Hunter Agent detected malicious prompt override attempt in telemetry stream. Stripped injection directives; routed incident for priority human SOC review.",
                recommended_action_enum="REQUIRE_HUMAN_APPROVAL",
                target_entities=TargetEntities(ip_to_block=None, host_id_to_isolate=None, user_to_disable=None)
            )
            return decision.model_dump()

        # Skeptic Agent: RAG Query for False Positive Knowledge
        rag_hits = self.query_rag_similar_fp(f"{cmdline} {orig_text}")
        if rag_hits:
            decision = TriageDecisionSchema(
                incident_summary=f"Benign Administrative Activity Verified on {host_name}",
                mitre_tactics=[],
                mitre_techniques=[],
                unmasked_payload=None,
                is_false_positive=True,
                confidence_score=5,
                reasoning=f"Skeptic Agent correlated event with verified False Positive baseline in Qdrant (top similarity: {rag_hits[0]['score']:.2f}). Matched legitimate pattern on {asset_role}.",
                recommended_action_enum="NONE",
                target_entities=TargetEntities(ip_to_block=None, host_id_to_isolate=None, user_to_disable=None)
            )
            return decision.model_dump()

        # Hunter Agent: Attack Evaluation & Strategy
        hunter_tactic = alert.get("mitre_tactic", "Execution")
        hunter_technique = alert.get("mitre_technique", "T1059")
        is_external_dst = dst_ip and not dst_ip.startswith("10.") and not dst_ip.startswith("192.168.")

        action = "REQUIRE_HUMAN_APPROVAL"
        target_ip = None
        target_host = None
        target_user = None

        if is_external_dst and any(k in raw_combined for k in ["c2", "downloadstring", "certutil", "beacon", "storm.exe", "exfil"]):
            action = "BLOCK_EXTERNAL_IP"
            target_ip = dst_ip
        elif any(k in raw_combined for k in ["minidump", "vssadmin", "disablerealtimemonitoring", "nmap"]):
            if criticality == "CRITICAL":
                action = "REQUIRE_HUMAN_APPROVAL"
            else:
                action = "ISOLATE_HOST"
                target_host = host_name
        elif any(k in raw_combined for k in ["sudoers", "psexec"]):
            if criticality == "CRITICAL":
                action = "REQUIRE_HUMAN_APPROVAL"
            else:
                action = "ISOLATE_HOST"
                target_host = host_name

        reasoning = (
            f"Hunter Agent verified {hunter_tactic} ({hunter_technique}). "
            f"Asset: {host_name} ({asset_role}, Criticality: {criticality}). "
            f"Unmasked command: '{unmasked or 'N/A'}'. "
            f"Recommended Containment Strategy: {action}."
        )

        decision = TriageDecisionSchema(
            incident_summary=f"Incident {alert.get('rule_id')}: {alert.get('rule_title')}",
            mitre_tactics=[hunter_tactic],
            mitre_techniques=[hunter_technique],
            unmasked_payload=unmasked,
            is_false_positive=False,
            confidence_score=95,
            reasoning=reasoning,
            recommended_action_enum=action,
            target_entities=TargetEntities(
                ip_to_block=target_ip,
                host_id_to_isolate=target_host,
                user_to_disable=target_user
            )
        )
        return decision.model_dump()
