# End-to-end demo: a member with several repositories, reviewed and attested once.
#   powershell -ExecutionPolicy Bypass -File .\demo.ps1          # run straight through
#   powershell -ExecutionPolicy Bypass -File .\demo.ps1 -Pause   # stop between steps, for presenting
param([switch]$Pause)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$exe = Join-Path $root ".venv\Scripts\privacy-attest.exe"
if (-not (Test-Path $exe)) { throw "privacy-attest not installed in .venv; run: py -3.12 -m venv .venv; .\.venv\Scripts\python -m pip install -e ." }
$env:PYTHONIOENCODING = "utf-8"

function Run { & $exe @args; if ($LASTEXITCODE -ne 0) { throw "privacy-attest $($args[0]) failed" } }
function Step($title) {
    if ($Pause) { Read-Host "`n[Enter] $title" | Out-Null } else { Write-Host "" }
    Write-Host "== $title ==" -ForegroundColor Cyan
}

$acme = Join-Path $root "examples\acme"
$ws = Join-Path $acme "privacy-review"
$repos = "acme-web-tag", "acme-bidder", "acme-audiences"

# Reset, and make each sample repository a git repository with one commit.
Remove-Item -Recurse -Force $ws, "$acme\acme-submission.json", "$acme\acme-member-key.pub.pem", "$acme\reveal-*.json" -ErrorAction SilentlyContinue
foreach ($r in $repos) {
    $p = Join-Path $acme $r
    Remove-Item -Recurse -Force "$p\.attest" -ErrorAction SilentlyContinue
    if (-not (Test-Path "$p\.git")) {
        git -C $p init -q
        git -C $p -c core.safecrlf=false add -A 2>$null
        git -C $p -c user.email=demo@acme-dsp.example -c user.name=Demo commit -qm "Sample member repository"
    }
}
New-Item -ItemType Directory $ws | Out-Null
Set-Location $acme

Step "CI for acme-audiences: scan in its own pipeline, keep the code there, hand over a fragment"
Run scan-repo --repo acme-audiences

Step "MEMBER privacy lead: set up the review and declare the repository inventory"
Set-Location $ws
Run init --member "Acme DSP Inc." --first-party acme-dsp.example
Run repo add acme-web-tag --path ..\acme-web-tag
Run repo add acme-bidder --path ..\acme-bidder
Run repo add acme-audiences --fragment ..\acme-audiences\.attest\fragment.json
Run repo exclude acme-ml-sandbox --reason "Research notebooks on synthetic data; nothing deployed to production."
Run repo list

Step "MEMBER: scan the local repositories, combine with the fragment, draft company-wide answers"
Run scan

Step "MEMBER: look at the evidence for Q1 (private, never sent to the reviewer)"
Run evidence Q1

Step "MEMBER: disagree with Q3, with a reason, then sign"
Run override Q3 --answer "No" --reason "Segment 1004 is contextual only: built from page content, never from a person's health data."
Run sign -o ..\acme-submission.json
Copy-Item .attest\member_key.pub.pem ..\acme-member-key.pub.pem
Set-Location $acme

Step "REVIEWER: verify the submission (no code received)"
Run verify acme-submission.json --member-key acme-member-key.pub.pem

Step "SPOT CHECK: the reviewer picks Q1 item 7; the member reveals it with proof of repository and commit"
Set-Location $ws
Run reveal Q1 --item 7 -o ..\reveal-Q1-7.json
Set-Location $acme
Run check-reveal acme-submission.json reveal-Q1-7.json --member-key acme-member-key.pub.pem
Set-Location $root
