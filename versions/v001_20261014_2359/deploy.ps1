param (
    [string]$ProjectName = "secops_v001"
)

Write-Host "=========================================================="
Write-Host "  Deploying SecOps Autonomous Pipeline: $ProjectName       "
Write-Host "=========================================================="

if (-not (Test-Path .env)) {
    Write-Host "Creating .env from .env.example..."
    Copy-Item .env.example .env
}

Write-Host "[1/4] Validating Docker Compose configuration..."
docker compose -p $ProjectName config | Out-Null

Write-Host "[2/4] Building microservices..."
docker compose -p $ProjectName build

Write-Host "[3/4] Launching SecOps pipeline stack..."
docker compose -p $ProjectName up -d redpanda qdrant_db soar_playbooks soar_guardrails ai_triage_service siem_engine collector_vector

Write-Host "[4/4] Verifying health status..."
Start-Sleep -Seconds 5
docker compose -p $ProjectName ps

Write-Host "=========================================================="
Write-Host "  Deployment of $ProjectName completed successfully!       "
Write-Host "=========================================================="
