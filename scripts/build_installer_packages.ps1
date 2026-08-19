$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Dist = Join-Path $Root "dist"
$Version = if ($env:CYBERION_AGENT_VERSION) { $env:CYBERION_AGENT_VERSION } else { "1.0.0" }

New-Item -ItemType Directory -Force -Path $Dist | Out-Null

$zipPath = Join-Path $Dist "cyberion-agent-installer-$Version.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

$items = @(
    (Join-Path $Root "installer"),
    (Join-Path $Root "Agent"),
    (Join-Path $Root "requirements.txt"),
    (Join-Path $Root "agent.yaml"),
    (Join-Path $Root "config_reference.yaml")
)

Compress-Archive -Path $items -DestinationPath $zipPath -Force
Write-Host "Bootstrap package created: $zipPath"
Write-Host "MSI packaging integration point: hook WiX here using $zipPath as payload."
