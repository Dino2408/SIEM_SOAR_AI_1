import hashlib
import json
import logging
import time
import uuid
from fastapi import FastAPI, Request

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("soar_executor_v003")

app = FastAPI(title="SOAR Orchestrator & Playbook Executor (v003 Enterprise)")

EXECUTION_AUDIT_LOG = []

def generate_integrity_hash(record: dict) -> str:
    raw = json.dumps(record, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "version": "v003",
        "total_actions_executed": len(EXECUTION_AUDIT_LOG)
    }

@app.get("/api/v1/audit")
def get_audit():
    return {"audit_log": EXECUTION_AUDIT_LOG}

@app.post("/api/v1/execute")
async def execute_playbook(request: Request):
    payload = await request.json()
    action = payload.get("action")
    target_entities = payload.get("target_entities", {})
    ttl_seconds = payload.get("ttl_seconds", 3600)
    event_id = payload.get("event_id")

    exec_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    result = {
        "execution_id": exec_id,
        "event_id": event_id,
        "timestamp": timestamp,
        "action": action,
        "ttl_seconds": ttl_seconds,
        "status": "SUCCESS"
    }

    if action == "BLOCK_EXTERNAL_IP":
        ip = target_entities.get("ip_to_block")
        logger.info(f"PLAYBOOK [Block IP]: Firewall rule created for {ip} with TTL {ttl_seconds}s")
        result["details"] = {
            "firewall_rule_id": f"FW-BLOCK-{uuid.uuid4().hex[:6].upper()}",
            "target_ip": ip,
            "ttl_seconds": ttl_seconds,
            "action_taken": "DROP_INBOUND_OUTBOUND"
        }
    elif action == "ISOLATE_HOST":
        host = target_entities.get("host_id_to_isolate")
        logger.info(f"PLAYBOOK [EDR Isolation]: Endpoint isolated: {host}")
        result["details"] = {
            "edr_isolation_id": f"EDR-ISOLATE-{uuid.uuid4().hex[:6].upper()}",
            "target_host": host,
            "network_status": "RESTRICTED_TO_SECOPS"
        }
    elif action == "DISABLE_USER":
        user = target_entities.get("user_to_disable")
        logger.info(f"PLAYBOOK [Active Directory]: Account locked for {user}")
        result["details"] = {
            "ad_task_id": f"AD-LOCK-{uuid.uuid4().hex[:6].upper()}",
            "target_user": user,
            "account_status": "DISABLED"
        }
    elif action == "REQUIRE_HUMAN_APPROVAL":
        logger.info(f"PLAYBOOK [ITSM / TheHive]: Created high-priority incident ticket for human review")
        result["details"] = {
            "ticket_id": f"INC-SEC-{uuid.uuid4().hex[:6].upper()}",
            "severity": "CRITICAL",
            "workflow": "AWAITING_SOC_L2_ANALYST"
        }
    else:
        result["status"] = "NOOP"
        result["details"] = {"message": "No playbook execution required"}

    # Attach cryptographic SHA-256 integrity signature
    result["integrity_signature"] = generate_integrity_hash(result)
    EXECUTION_AUDIT_LOG.append(result)
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
