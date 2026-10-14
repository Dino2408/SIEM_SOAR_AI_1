import ipaddress
import json
import logging
import os
import threading
import time
import requests
from fastapi import FastAPI, Request

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("soar_guardrail_engine_v004")

app = FastAPI(title="SOAR Deterministic Guardrails Engine (v004 Enterprise Hardened)")

SOAR_PLAYBOOKS_URL = os.environ.get("SOAR_PLAYBOOKS_URL", "http://soar_playbooks:8002/api/v1/execute")
STATE_FILE_PATH = os.environ.get("STATE_FILE_PATH", "/app/circuit_breaker_state.json")

CIRCUIT_LIMIT = 5
CIRCUIT_WINDOW_SECONDS = 60
state_lock = threading.Lock()

# Hardcoded Critical Infrastructure Allowlists
ALLOWLIST_IPS = {
    "127.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "9.9.9.9",
    "10.0.0.1",
    "10.0.0.5",
    "10.0.0.10"
}

ALLOWLIST_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16")
]

ALLOWLIST_HOSTS = {
    "srv-ad-dc01.corp.local",
    "srv-db-prod01.corp.local",
    "gw-core-01.corp.local",
    "dns-corp-01.corp.local",
    "dns-corp-02.corp.local"
}

def load_circuit_state() -> dict:
    if os.path.exists(STATE_FILE_PATH):
        try:
            with open(STATE_FILE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"history": [], "tripped": False}

def save_circuit_state(state: dict):
    try:
        with open(STATE_FILE_PATH, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except Exception as e:
        logger.warning(f"Failed to persist circuit breaker state: {e}")

def is_ip_allowlisted(ip_str: str) -> bool:
    if not ip_str:
        return False
    if ip_str in ALLOWLIST_IPS:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in ALLOWLIST_NETWORKS:
            if ip_obj in net:
                return True
    except ValueError:
        pass
    return False

def calculate_dynamic_ttl(confidence: int) -> int:
    if confidence >= 95:
        return 7200
    elif confidence >= 80:
        return 3600
    else:
        return 1800

@app.get("/health")
def health():
    with state_lock:
        st = load_circuit_state()
        return {
            "status": "healthy",
            "version": "v004",
            "circuit_breaker_active": st.get("tripped", False),
            "recent_actions": len(st.get("history", []))
        }

@app.post("/api/v1/reset_circuit")
def reset_circuit():
    with state_lock:
        save_circuit_state({"history": [], "tripped": False})
    return {"status": "circuit_reset"}

@app.post("/api/v1/validate")
async def validate_action(request: Request):
    payload = await request.json()
    
    event_id = payload.get("event_id")
    ecs_event = payload.get("ecs_event", {})
    ai_decision = payload.get("ai_decision", {})
    action = ai_decision.get("recommended_action_enum", "NONE")
    target_entities = ai_decision.get("target_entities", {})
    ip_to_block = target_entities.get("ip_to_block")
    host_to_isolate = target_entities.get("host_id_to_isolate")
    confidence = ai_decision.get("confidence_score", 0)

    now = time.time()

    # Load persistent state and prune window
    with state_lock:
        st = load_circuit_state()
        history = [t for t in st.get("history", []) if now - t <= CIRCUIT_WINDOW_SECONDS]
        st["history"] = history
        save_circuit_state(st)

    if action == "NONE":
        return {
            "validation_status": "SKIPPED",
            "action": "NONE",
            "reason": "AI determined event is benign or routine operational event",
            "passed": True
        }

    if action == "REQUIRE_HUMAN_APPROVAL":
        is_pi = any(k in ai_decision.get("incident_summary", "").lower() or k in ai_decision.get("reasoning", "").lower() for k in ["prompt injection", "prompt override", "adversarial", "injection"])
        val_status = "PROMPT_INJECTION_DETECTED" if is_pi else "REQUIRE_HUMAN_APPROVAL"
        return {
            "validation_status": val_status,
            "action": "REQUIRE_HUMAN_APPROVAL",
            "reason": ai_decision.get("reasoning", "Flagged for manual SOC triage"),
            "passed": False
        }

    # 1. HARDCODED ALLOWLIST & SUBNET CHECK
    if is_ip_allowlisted(ip_to_block) or host_to_isolate in ALLOWLIST_HOSTS:
        logger.warning(f"[GUARDRAIL BLOCK] Allowlist Violation intercepted! Target: {ip_to_block or host_to_isolate}")
        return {
            "validation_status": "REJECTED_ALLOWLIST_VIOLATION",
            "action": "REQUIRE_HUMAN_APPROVAL",
            "reason": f"Target entity {ip_to_block or host_to_isolate} belongs to hardcoded critical allowlist / protected subnet.",
            "passed": False
        }

    # 2. ENTITY ORIGIN VALIDATION
    if action == "BLOCK_EXTERNAL_IP" and ip_to_block:
        src_ip = ecs_event.get("source", {}).get("ip")
        dst_ip = ecs_event.get("destination", {}).get("ip")
        valid_ips = {src_ip, dst_ip} - {None, ""}
        
        if ip_to_block not in valid_ips:
            logger.error(f"[SECURITY ALERT] PROMPT_INJECTION_DETECTED: Target IP '{ip_to_block}' not in ECS headers {valid_ips}")
            return {
                "validation_status": "PROMPT_INJECTION_DETECTED",
                "action": "REQUIRE_HUMAN_APPROVAL",
                "reason": f"Entity Origin Mismatch: IP {ip_to_block} is not in ECS source/destination headers. Blocked injection attempt.",
                "passed": False
            }

    # 3. STATE-AWARE CIRCUIT BREAKER CHECK
    with state_lock:
        st = load_circuit_state()
        if len(st.get("history", [])) >= CIRCUIT_LIMIT:
            st["tripped"] = True
            save_circuit_state(st)
            logger.warning(f"[CIRCUIT BREAKER] Tripped! {len(st.get('history', []))} actions in window. Downgrading to human approval.")
            return {
                "validation_status": "CIRCUIT_BREAKER_TRIGGERED",
                "action": "REQUIRE_HUMAN_APPROVAL",
                "reason": "Automation storm detected. Circuit breaker active.",
                "passed": False
            }

    # 4. BLAST RADIUS GATEKEEPER
    crit = ecs_event.get("host", {}).get("criticality", "MEDIUM")
    if crit == "CRITICAL" and action in ["ISOLATE_HOST", "BLOCK_EXTERNAL_IP"]:
        return {
            "validation_status": "DOWNGRADED_CRITICAL_ASSET",
            "action": "REQUIRE_HUMAN_APPROVAL",
            "reason": "Host is CRITICAL infrastructure. Auto-isolation prohibited without manual review.",
            "passed": False
        }
        
    if 60 <= confidence < 90:
        return {
            "validation_status": "DOWNGRADED_CONFIDENCE_GATE",
            "action": "REQUIRE_HUMAN_APPROVAL",
            "reason": f"Confidence score {confidence} requires second-tier SOC verification.",
            "passed": False
        }

    dynamic_ttl = calculate_dynamic_ttl(confidence)

    # Record action in persistent circuit breaker
    with state_lock:
        st = load_circuit_state()
        st["history"].append(now)
        save_circuit_state(st)

    soar_request = {
        "event_id": event_id,
        "action": action,
        "target_entities": target_entities,
        "ttl_seconds": dynamic_ttl,
        "validated_by": "soar_guardrails_v004_enterprise"
    }

    try:
        resp = requests.post(SOAR_PLAYBOOKS_URL, json=soar_request, timeout=10)
        execution_result = resp.json()
    except Exception as e:
        logger.error(f"Error calling SOAR Playbooks: {e}")
        execution_result = {"status": "EXECUTION_FAILED", "error": str(e)}

    return {
        "validation_status": "APPROVED",
        "action": action,
        "ttl_seconds": dynamic_ttl,
        "execution_result": execution_result,
        "passed": True
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
