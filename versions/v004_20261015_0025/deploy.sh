#!/usr/bin/env bash
set -e

PROJECT_NAME="${1:-secops_v004}"
echo "=========================================================="
echo "  Deploying SecOps Autonomous Pipeline: ${PROJECT_NAME}   "
echo "=========================================================="

if [ ! -f .env ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env
fi

echo "[1/4] Validating Docker Compose configuration..."
docker compose -p "${PROJECT_NAME}" config > /dev/null

echo "[2/4] Building microservices..."
docker compose -p "${PROJECT_NAME}" build

echo "[3/4] Launching SecOps pipeline stack..."
docker compose -p "${PROJECT_NAME}" up -d redpanda qdrant_db soar_playbooks soar_guardrails ai_triage_service siem_engine collector_vector

echo "[4/4] Verifying health status..."
sleep 5
docker compose -p "${PROJECT_NAME}" ps

echo "=========================================================="
echo "  Deployment of ${PROJECT_NAME} completed successfully!   "
echo "=========================================================="
