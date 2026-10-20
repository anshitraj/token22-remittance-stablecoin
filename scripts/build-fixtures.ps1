# Rebuilds the two on-chain programs the tests load from `fixtures/`:
#
#   fixtures/agent_program.so   our extension-challenge program (programs/agent)
#   fixtures/spl_record.so      SPL Record 0.4.0, built from the published crate source
#
# Needs the Solana CLI (for `cargo build-sbf`). The committed .so files are what
# the tests use, so you only need to run this to audit or refresh them.
#
#   pwsh scripts/build-fixtures.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root "fixtures"
New-Item -ItemType Directory -Force $out | Out-Null

Write-Host "==> agent_program"
cargo build-sbf --manifest-path (Join-Path $root "programs/agent/Cargo.toml") --sbf-out-dir $out
Remove-Item (Join-Path $out "agent_program-keypair.json") -ErrorAction SilentlyContinue

Write-Host "==> spl_record (crates.io spl-record 0.4.0)"
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("spl-record-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force $work | Out-Null
try {
    $crate = Join-Path $work "spl-record.crate"
    Invoke-WebRequest "https://static.crates.io/crates/spl-record/spl-record-0.4.0.crate" -OutFile $crate
    tar -xzf $crate -C $work
    cargo build-sbf --manifest-path (Join-Path $work "spl-record-0.4.0/Cargo.toml") --sbf-out-dir $out
    Remove-Item (Join-Path $out "spl_record-keypair.json") -ErrorAction SilentlyContinue
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

Get-ChildItem $out | Select-Object Name, Length
