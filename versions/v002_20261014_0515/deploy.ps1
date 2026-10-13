param (
    [string]$ProjectName = "secops_v002"
)

$ErrorActionPreference = "Stop"
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [SECOPS DEPLOY] Starting Autonomous Deployment: $ProjectName" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "docker is not available."
}

if (-not (Test-Path .env)) {
    Write-Host "[+] Creating .env from .env.example..." -ForegroundColor Yellow
    Copy-Item .env.example .env
}

Write-Host "[+] Building and launching container cluster (v002)..." -ForegroundColor Yellow
docker compose -p $ProjectName up -d --build redpanda qdrant_db soar_playbooks soar_guardrails ai_triage_service siem_engine collector_vector

Write-Host "[+] Waiting for services to become healthy..." -ForegroundColor Yellow
Start-Sleep -Seconds 8

Write-Host "[+] Seeding Qdrant knowledge base & CMDB..." -ForegroundColor Yellow
docker compose -p $ProjectName run --rm seed_and_test python init_seed.py

Write-Host "==========================================================" -ForegroundColor Green
Write-Host " [SECOPS DEPLOY] Deployment Completed Successfully (v002)!" -ForegroundColor Green
Write-Host " - SIEM Engine:       http://localhost:8080/events"
Write-Host " - AI Triage Docs:    http://localhost:8000/docs"
Write-Host " - Guardrails Status: http://localhost:8001/health"
Write-Host " - SOAR Playbooks:    http://localhost:8002/api/v1/audit"
Write-Host " - Vector Normalizer: http://localhost:8686/log"
Write-Host "==========================================================" -ForegroundColor Green
