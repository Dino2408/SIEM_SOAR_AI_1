import logging
import os
import time
import requests
from fastapi import FastAPI, Request

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("soar_guardrail_engine_v002")

app = FastAPI(title="SOAR Deterministic Guardrails Engine (v002 Hardened)")

SOAR_PLAYBOOKS_URL = os.environ.get("SOAR_PLAYBOOKS_URL", "http://soar_playbooks:8002/api/v1/execute")

# Circuit Breaker state
CIRCUIT_LIMIT = 5
CIRCUIT_WINDOW_SECONDS = 60
auto_actions_history = []
circuit_broken = False

# Hardcoded Allowlist (Zero Tolerance for Critical Infrastructure & Upstream DNS)
ALLOWLIST_IPS = {
    "127.0.0.1",
    "8.8.8.8",                  # Public DNS Upstream
    "1.1.1.1",                  # Secondary Public DNS
    "10.0.0.1",                 # Core Gateway / Router
    "10.0.0.5",                 # Domain Controller (srv-ad-dc01)
    "10.0.0.10"                 # Production Database (srv-db-prod01)
}

ALLOWLIST_HOSTS = {
    "srv-ad-dc01.corp.local",
    "srv-db-prod01.corp.local",
    "gw-core-01.corp.local",
    "dns-corp-01.corp.local",
    "dns-corp-02.corp.local"
}

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "circuit_breaker_active": circuit_broken,
        "recent_action_count": len(auto_actions_history),
        "allowlisted_ips_count": len(ALLOWLIST_IPS)
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

    # 1. HARDCODED ALLOWLIST CHECK
    if ip_to_block in ALLOWLIST_IPS or host_to_isolate in ALLOWLIST_HOSTS:
        logger.warning(f"[GUARDRAIL BLOCK] Allowlist Violation intercepted! Target: {ip_to_block or host_to_isolate}")
        return {
            "validation_status": "REJECTED_ALLOWLIST_VIOLATION",
            "action": "REQUIRE_HUMAN_APPROVAL",
            "reason": f"Target entity {ip_to_block or host_to_isolate} belongs to hardcoded critical allowlist.",
            "passed": False
        }

    # 2. ENTITY ORIGIN VALIDATION (Anti Log Poisoning & Prompt Injection Check)
    if action == "BLOCK_EXTERNAL_IP" and ip_to_block:
        src_ip = ecs_event.get("source", {}).get("ip")
        dst_ip = ecs_event.get("destination", {}).get("ip")
        valid_ips = {src_ip, dst_ip} - {None, ""}
        
        if ip_to_block not in valid_ips:
            logger.error(f"[SECURITY ALERT] PROMPT_INJECTION_DETECTED: Target IP '{ip_to_block}' was hallucinated or poisoned (not in ECS source/destination: {valid_ips})")
            return {
                "validation_status": "PROMPT_INJECTION_DETECTED",
                "action": "REQUIRE_HUMAN_APPROVAL",
                "reason": f"Entity Origin Mismatch: IP {ip_to_block} is not in ECS source/destination headers. Blocked injection attempt.",
                "passed": False
            }

    # 3. CIRCUIT BREAKER
    if len(auto_actions_history) >= CIRCUIT_LIMIT:
        circuit_broken = True
        logger.warning(f"[CIRCUIT BREAKER] Tripped! {len(auto_actions_history)} containment actions in {CIRCUIT_WINDOW_SECONDS}s. Forcing human approval.")
        return {
            "validation_status": "CIRCUIT_BREAKER_TRIGGERED",
            "action": "REQUIRE_HUMAN_APPROVAL",
            "reason": "Automation storm detected. Circuit breaker active.",
            "passed": False
        }

    # 4. BLAST RADIUS GATEKEEPER
    crit = ecs_event.get("host", {}).get("criticality", "MEDIUM")
    if crit == "CRITICAL" and action in ["ISOLATE_HOST", "BLOCK_EXTERNAL_IP"]:
        logger.info(f"[BLAST RADIUS] Target {host_to_isolate or ip_to_block} is CRITICAL. Requiring human SOC analyst approval.")
        return {
            "validation_status": "DOWNGRADED_CRITICAL_ASSET",
            "action": "REQUIRE_HUMAN_APPROVAL",
            "reason": "Host is CRITICAL infrastructure. Auto-isolation prohibited without manual review.",
            "passed": False
        }
        
    if 60 <= confidence < 90:
        logger.info(f"[BLAST RADIUS] Confidence {confidence} in grey zone (60-89). Requiring human approval.")
        return {
            "validation_status": "DOWNGRADED_CONFIDENCE_GATE",
            "action": "REQUIRE_HUMAN_APPROVAL",
            "reason": f"Confidence score {confidence} requires second-tier SOC verification.",
            "passed": False
        }

    # All guardrails passed -> approve auto containment with TTL
    auto_actions_history.append(now)
    soar_request = {
        "event_id": event_id,
        "action": action,
        "target_entities": target_entities,
        "ttl_seconds": 3600,
        "validated_by": "soar_guardrails_v002_hardened"
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
