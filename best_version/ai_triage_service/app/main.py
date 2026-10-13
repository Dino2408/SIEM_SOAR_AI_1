import logging
import os
import requests
from fastapi import FastAPI, Request
from .triage_engine import AITriageAgent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ai_triage_service")

app = FastAPI(title="AI Triage Dual-Agent Service")
agent = None

GUARDRAILS_URL = os.environ.get("GUARDRAILS_URL", "http://soar_guardrails:8001/api/v1/validate")

@app.on_event("startup")
def startup_event():
    global agent
    agent = AITriageAgent()
    logger.info("AI Triage Agent initialized.")

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "qdrant_connected": agent.qdrant is not None if agent else False,
        "cmdb_entries": len(agent.cmdb) if agent else 0
    }

@app.post("/api/v1/triage")
async def triage_endpoint(request: Request):
    alert = await request.json()
    triage_output = agent.run_triage(alert)
    
    validation_payload = {
        "event_id": alert.get("event_id"),
        "ecs_event": alert.get("ecs_event", {}),
        "ai_decision": triage_output
    }
    
    # Forward to SOAR Guardrails Proxy
    try:
        resp = requests.post(GUARDRAILS_URL, json=validation_payload, timeout=10)
        guardrail_result = resp.json()
    except Exception as e:
        logger.error(f"Error calling SOAR Guardrails: {e}")
        guardrail_result = {"status": "GUARDRAIL_UNREACHABLE", "error": str(e)}

    return {
        "ai_decision": triage_output,
        "guardrail_result": guardrail_result
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
