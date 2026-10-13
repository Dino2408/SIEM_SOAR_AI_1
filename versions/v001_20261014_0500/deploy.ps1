param (
    [string]$ProjectName = "secops_v001"
)

$ErrorActionPreference = "Stop"
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [SECOPS DEPLOY] Starting Autonomous Deployment: $ProjectName" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Step 1: Pre-flight check
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "docker is not available."
}

# Step 2: Env setup
if (-not (Test-Path .env)) {
    Write-Host "[+] Creating .env from .env.example..." -ForegroundColor Yellow
    Copy-Item .env.example .env
}

# Step 3: Build & Launch
Write-Host "[+] Building and launching container cluster..." -ForegroundColor Yellow
docker compose -p $ProjectName up -d --build redpanda qdrant_db soar_playbooks soar_guardrails ai_triage_service siem_engine collector_vector

# Step 4: Health check wait & auto-seed
Write-Host "[+] Waiting for services to become healthy..." -ForegroundColor Yellow
Start-Sleep -Seconds 8

Write-Host "[+] Seeding Qdrant knowledge base & CMDB..." -ForegroundColor Yellow
docker compose -p $ProjectName run --rm seed_and_test python init_seed.py

Write-Host "==========================================================" -ForegroundColor Green
Write-Host " [SECOPS DEPLOY] Deployment Completed Successfully!" -ForegroundColor Green
Write-Host " - SIEM Engine:       http://localhost:8080/events"
Write-Host " - AI Triage Docs:    http://localhost:8000/docs"
Write-Host " - Guardrails Status: http://localhost:8001/health"
Write-Host " - SOAR Playbooks:    http://localhost:8002/api/v1/audit"
Write-Host " - Vector Normalizer: http://localhost:8686/log"
Write-Host "==========================================================" -ForegroundColor Green
