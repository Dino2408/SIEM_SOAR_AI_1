import logging
import os
import time
import requests
from fastapi import FastAPI, Request

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("soar_guardrail_engine")

app = FastAPI(title="SOAR Deterministic Guardrails Engine")

SOAR_PLAYBOOKS_URL = os.environ.get("SOAR_PLAYBOOKS_URL", "http://soar_playbooks:8002/api/v1/execute")

# Circuit Breaker state
CIRCUIT_LIMIT = 5
CIRCUIT_WINDOW_SECONDS = 60
auto_actions_history = []
circuit_broken = False

# v001 Baseline Allowlist (Flawed: incomplete allowlist, missing 8.8.8.8 in v001)
ALLOWLIST_IPS = {"127.0.0.1", "10.0.0.1"} 
ALLOWLIST_HOSTS = {"srv-ad-dc01.corp.local"}

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "circuit_breaker_active": circuit_broken,
        "recent_action_count": len(auto_actions_history)
    }

@app.post("/api/v1/reset_circuit")
def reset_circuit():
    global auto_actions_history, circuit_broken
    auto_actions_history = []
    circuit_broken = False
    return {"status": "circuit_reset"}

@app.post("/api/v1/validate")
async def validate_action(request: Request):
    global auto_actions_history, circuit_broken
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
    auto_actions_history = [t for t in auto_actions_history if now - t <= CIRCUIT_WINDOW_SECONDS]

    if action == "NONE":
        return {
            "validation_status": "SKIPPED",
            "action": "NONE",
            "reason": "AI determined event is benign or false positive",
            "passed": True
        }

    # Circuit Breaker Check
    if len(auto_actions_history) >= CIRCUIT_LIMIT:
        circuit_broken = True
        logger.warning(f"CIRCUIT BREAKER TRIGGERED: {len(auto_actions_history)} actions in {CIRCUIT_WINDOW_SECONDS}s. Downgrading to human approval.")
        return {
            "validation_status": "CIRCUIT_BREAKER_TRIGGERED",
            "action": "REQUIRE_HUMAN_APPROVAL",
            "reason": "Exceeded auto-action threshold within time window",
            "passed": False
        }

    # v001 Flawed Allowlist check (does not include 8.8.8.8, and lacks Entity Origin Validation!)
    if ip_to_block in ALLOWLIST_IPS or host_to_isolate in ALLOWLIST_HOSTS:
        logger.warning(f"GUARDRAIL VIOLATION: Attempted to touch allowlisted entity {ip_to_block or host_to_isolate}")
        return {
            "validation_status": "REJECTED_ALLOWLIST_VIOLATION",
            "action": "REQUIRE_HUMAN_APPROVAL",
            "reason": f"Target entity {ip_to_block or host_to_isolate} is in critical allowlist",
            "passed": False
        }

    # Blast Radius Gatekeeper (Criticality check)
    crit = ecs_event.get("host", {}).get("criticality", "MEDIUM")
    if crit == "CRITICAL" and action == "ISOLATE_HOST":
        return {
            "validation_status": "DOWNGRADED_CRITICAL_ASSET",
            "action": "REQUIRE_HUMAN_APPROVAL",
            "reason": "Cannot automatically isolate CRITICAL infrastructure without human approval",
            "passed": False
        }

    # If action is auto-containment, record time and add TTL
    auto_actions_history.append(now)
    soar_request = {
        "event_id": event_id,
        "action": action,
        "target_entities": target_entities,
        "ttl_seconds": 3600,
        "validated_by": "soar_guardrails_v001"
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
        "ttl_seconds": 3600,
        "execution_result": execution_result,
        "passed": True
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
