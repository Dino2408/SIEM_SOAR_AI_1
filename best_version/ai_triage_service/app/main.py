import logging
import os
import requests
from fastapi import FastAPI, Request
from .triage_engine import AITriageAgent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ai_triage_service")

app = FastAPI(title="AI Triage Service")
triage_agent = AITriageAgent()

GUARDRAILS_URL = os.environ.get("GUARDRAILS_URL", "http://soar_guardrails:8001/api/v1/validate")

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "cmdb_assets": len(triage_agent.cmdb)
    }

@app.post("/api/v1/triage")
async def triage_alert(request: Request):
    alert = await request.json()
    ai_decision = triage_agent.run_triage(alert)
    
    # Forward to Deterministic Guardrails Engine
    guardrail_payload = {
        "event_id": alert.get("event_id"),
        "rule_id": alert.get("rule_id"),
        "ecs_event": alert.get("ecs_event", {}),
        "ai_decision": ai_decision
    }
    
    try:
        resp = requests.post(GUARDRAILS_URL, json=guardrail_payload, timeout=10)
        guardrail_result = resp.json()
    except Exception as e:
        logger.error(f"Failed to reach Guardrail engine: {e}")
        guardrail_result = {"validation_status": "ERROR", "error": str(e)}

    return {
        "event_id": alert.get("event_id"),
        "ai_decision": ai_decision,
        "guardrail_result": guardrail_result
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
