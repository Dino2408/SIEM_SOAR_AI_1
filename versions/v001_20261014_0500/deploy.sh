#!/usr/bin/env bash
set -e

PROJECT_NAME="${1:-secops_v001}"
echo "=========================================================="
echo " [SECOPS DEPLOY] Starting Autonomous Deployment: $PROJECT_NAME"
echo "=========================================================="

# Step 1: Pre-flight checks
if ! command -v docker &> /dev/null; then
    echo "ERROR: docker is not installed or not in PATH."
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "ERROR: docker compose is not available."
    exit 1
fi

# Step 2: Env setup
if [ ! -f .env ]; then
    echo "[+] Creating .env from .env.example..."
    cp .env.example .env
fi

# Step 3: Build & Launch
echo "[+] Building and launching container cluster..."
docker compose -p "$PROJECT_NAME" up -d --build redpanda qdrant_db soar_playbooks soar_guardrails ai_triage_service siem_engine collector_vector

# Step 4: Health check wait & auto-seed
echo "[+] Waiting for core services to reach healthy status..."
sleep 8

echo "[+] Seeding Qdrant knowledge base & CMDB..."
docker compose -p "$PROJECT_NAME" run --rm seed_and_test python init_seed.py

echo "=========================================================="
echo " [SECOPS DEPLOY] Deployment Completed Successfully!"
echo " - SIEM Engine:       http://localhost:8080/events"
echo " - AI Triage Docs:    http://localhost:8000/docs"
echo " - Guardrails Status: http://localhost:8001/health"
echo " - SOAR Playbooks:    http://localhost:8002/api/v1/audit"
echo " - Vector Normalizer: http://localhost:8686/log"
echo "=========================================================="
