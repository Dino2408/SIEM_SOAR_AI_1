import json
import logging
import os
import requests
from fastapi import FastAPI, Request

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("siem_engine")

app = FastAPI(title="SIEM Core Detection Engine")

RULES_PATH = os.path.join(os.path.dirname(__file__), "rules", "sigma_rules.json")
with open(RULES_PATH, "r", encoding="utf-8") as f:
    SIGMA_RULES = json.load(f)

AI_TRIAGE_URL = os.environ.get("AI_TRIAGE_URL", "http://ai_triage_service:8000/api/v1/triage")

@app.get("/health")
def health():
    return {"status": "healthy", "rules_loaded": len(SIGMA_RULES)}

def evaluate_event(event: dict):
    cmdline = ""
    if "process" in event and "command_line" in event["process"]:
        cmdline = (event["process"]["command_line"] or "").lower()
    
    orig = ""
    if "event" in event and "original" in event["event"]:
        orig = (event["event"]["original"] or "").lower()
        
    combined_text = f"{cmdline} {orig}"
    
    matched_rules = []
    for rule in SIGMA_RULES:
        for pat in rule["patterns"]:
            if pat.lower() in combined_text:
                matched_rules.append(rule)
                break
                
    return matched_rules

@app.post("/events")
async def ingest_event(request: Request):
    event = await request.json()
    matched = evaluate_event(event)
    
    if not matched:
        # Funnel Filter: noise reduction / benign routine event filtered out
        return {
            "status": "filtered",
            "is_alert": False,
            "message": "Routine normal event filtered by multi-stage funnel"
        }
    
    # Matched rule -> Construct Alert
    primary_rule = matched[0]
    alert_payload = {
        "event_id": event.get("event_id", "EVT-UNKNOWN"),
        "timestamp": event.get("@timestamp"),
        "rule_id": primary_rule["id"],
        "rule_title": primary_rule["title"],
        "severity": primary_rule["severity"],
        "mitre_tactic": primary_rule["tactic"],
        "mitre_technique": primary_rule["technique"],
        "ecs_event": event
    }
    
    logger.info(f"Triggered Alert {primary_rule['id']} on host {event.get('host', {}).get('name')}")
    
    # Forward to AI Triage Service
    try:
        resp = requests.post(AI_TRIAGE_URL, json=alert_payload, timeout=10)
        triage_result = resp.json()
    except Exception as e:
        logger.error(f"Failed to reach AI triage service: {e}")
        triage_result = {"error": str(e), "status": "ai_triage_unreachable"}
        
    return {
        "status": "alert_triggered",
        "is_alert": True,
        "matched_rules": [r["id"] for r in matched],
        "triage_result": triage_result
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
