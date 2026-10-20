# Runs the whole test suite (real `cargo test`, nothing mocked) and prints every
# test grouped by assignment task, then a one-line verdict. The raw cargo output
# is saved to docs/test-output.txt.
#
#   pwsh scripts/test-report.ps1

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:CARGO_TERM_COLOR = "never"

$titles = [ordered]@{
    "task1_mint"          = "Task 1  Mint: TransferFee + MetadataPointer + DefaultAccountState(Frozen) + MintCloseAuthority"
    "task2_transfer_fee"  = "Task 2  transfer_checked_with_fee, fee from calculate_epoch_fee(current_epoch, amount)"
    "task3_state"         = "Task 3  State read only through StateWithExtensions (raw unpack banned)"
    "task4_kyc"           = "Task 4  KYC unfreeze: freeze authority thaws one account, separate from default-state change"
    "task5_reissue"       = "Task 5  Re-issued mint: PermanentDelegate + confidential transfers (approve_policy = manual)"
    "task6_confidential"  = "Task 6  Confidential lifecycle: Configure, Deposit, ApplyPending, Transfer, Withdraw"
    "task7_sanctions_gap" = "Finding  Sanctioned user shields funds before the permanent delegate acts"
    "extension_challenge" = "Extension challenge  On-chain agent via Approve + CPI Guard enabled afterwards"
}

$raw = & cargo test --workspace 2>&1 | ForEach-Object { $_.ToString() }
$exit = $LASTEXITCODE
New-Item -ItemType Directory -Force (Join-Path $root "docs") | Out-Null
$raw | Set-Content -Encoding utf8 (Join-Path $root "docs/test-output.txt")

# Parse: "Running tests\<file>.rs", "test <name> ... ok|FAILED", "test result: ..."
$groups = @{}
$current = $null
$passed = 0; $failed = 0; $ignored = 0
foreach ($line in $raw) {
    if ($line -match "Running tests[\\/](?<f>\w+)\.rs") { $current = $Matches.f; $groups[$current] = @(); continue }
    if ($line -match "Running unittests|Doc-tests") { $current = $null; continue }
    if ($current -and $line -match "^test (?<n>\S+) \.\.\. (?<r>ok|FAILED|ignored)") {
        $groups[$current] += [pscustomobject]@{ Name = $Matches.n; Result = $Matches.r }
    }
    if ($line -match "^test result: .* (?<p>\d+) passed; (?<f>\d+) failed; (?<i>\d+) ignored") {
        $passed += [int]$Matches.p; $failed += [int]$Matches.f; $ignored += [int]$Matches.i
    }
}

Write-Host ""
Write-Host " remittance_stablecoin  -  cargo test --workspace" -ForegroundColor Cyan
Write-Host (" " + ("=" * 100)) -ForegroundColor DarkGray
foreach ($key in $titles.Keys) {
    if (-not $groups.ContainsKey($key)) { continue }
    $tests = $groups[$key] | Sort-Object Name
    $ok = ($tests | Where-Object Result -eq "ok").Count
    $color = if ($ok -eq $tests.Count) { "Green" } else { "Red" }
    Write-Host (" {0}  [{1}/{2}]" -f $titles[$key], $ok, $tests.Count) -ForegroundColor $color
    foreach ($t in $tests) {
        if ($t.Result -eq "ok") { Write-Host ("   PASS  " + $t.Name) -ForegroundColor DarkGreen }
        else { Write-Host ("   FAIL  " + $t.Name) -ForegroundColor Red }
    }
}
Write-Host (" " + ("=" * 100)) -ForegroundColor DarkGray
$verdict = "{0} passed; {1} failed; {2} ignored" -f $passed, $failed, $ignored
if ($failed -eq 0 -and $exit -eq 0) { Write-Host (" ALL TESTS PASSING   " + $verdict) -ForegroundColor Green }
else { Write-Host (" TESTS FAILED   " + $verdict) -ForegroundColor Red }
exit $exit
