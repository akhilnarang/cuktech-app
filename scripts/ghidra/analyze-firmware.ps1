param(
    [Parameter(Mandatory=$true)][string]$Image,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][string]$GhidraHome,
    [Parameter(Mandatory=$true)][string]$JavaHome,
    [string]$Python = 'python',
    [switch]$Assets,
    [switch]$SplitUnclassified,
    [switch]$VerifySignature
)
$ErrorActionPreference = 'Stop'
$taskImage = (Resolve-Path -LiteralPath $Image).Path
$taskOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
$taskGhidra = (Resolve-Path -LiteralPath $GhidraHome).Path
$taskJava = (Resolve-Path -LiteralPath $JavaHome).Path
$taskScriptDirectory = $PSScriptRoot
$taskPythonRoot = Split-Path $PSScriptRoot -Parent
$taskPythonExecutable = (Get-Command -Name $Python -ErrorAction Stop).Source
$taskHeadless = Join-Path $taskGhidra 'support\analyzeHeadless.bat'
if (!(Test-Path -LiteralPath $taskHeadless)) { throw 'Ghidra analyzeHeadless.bat was not found.' }
if (Test-Path -LiteralPath $taskOutput) { throw 'OutputDirectory must be new; existing research is preserved.' }
$taskUnpacked = Join-Path $taskOutput 'unpacked'
$taskArguments = @('-m', 'cuktech_pc.firmware_unpack', $taskImage, '--output', $taskUnpacked)
if ($Assets) { $taskArguments += '--assets' }
if ($SplitUnclassified) { $taskArguments += '--split-unclassified' }
if ($VerifySignature) { $taskArguments += '--verify' }
Push-Location -LiteralPath $taskPythonRoot
try {
    & $taskPythonExecutable @taskArguments
    if ($LASTEXITCODE -ne 0) { throw 'Firmware extraction failed.' }
} finally {
    Pop-Location
}
$taskManifest = Join-Path $taskUnpacked 'manifest.json'
$taskMetadata = Get-Content -LiteralPath $taskManifest -Raw | ConvertFrom-Json
if ($taskMetadata.startup_regions.Count -ne 5) { throw 'This Ghidra workflow requires the measured AD1204 0073 startup profile.' }
$taskProject = Join-Path $taskOutput 'project'
$taskAnalysis = Join-Path $taskOutput 'analysis'
New-Item -ItemType Directory -Path $taskProject,$taskAnalysis | Out-Null
$taskOldJava = $env:JAVA_HOME
try {
    $env:JAVA_HOME = $taskJava
    & $taskHeadless $taskProject 'AD1204_0073' `
        -import (Join-Path $taskUnpacked 'firmware.bin') `
        -loader BinaryLoader -loader-baseAddr 0x00403000 -processor ARM:LE:32:Cortex `
        -scriptPath $taskScriptDirectory -preScript PrepareChargerFirmware.java `
        -postScript ReconstructChargerMemory.java $taskManifest `
        -postScript RepairChargerDispatch.java `
        -postScript ExportChargerFirmware.java $taskAnalysis `
        -postScript VerifyStartupDecoder.java (Join-Path $taskUnpacked 'load-3-20001730-expanded.bin') (Join-Path $taskAnalysis 'decoder-verification.json') `
        -analysisTimeoutPerFile 300 -max-cpu 4 -log (Join-Path $taskAnalysis 'headless.log')
    if ($LASTEXITCODE -ne 0) { throw 'Ghidra process failed.' }
    # Ghidra may exit zero after a script exception; require result artifacts too.
    $taskResults = Get-Content -LiteralPath (Join-Path $taskAnalysis 'analysis.json') -Raw | ConvertFrom-Json
    $taskCheck = Get-Content -LiteralPath (Join-Path $taskAnalysis 'decoder-verification.json') -Raw | ConvertFrom-Json
    if (!$taskCheck.python_matches_original_thumb -or !$taskCheck.output_guards_intact) { throw 'Independent decoder verification failed.' }
    if ($taskResults.sha256 -ne $taskMetadata.outputs[0].sha256) { throw 'Ghidra input hash differs from extracted firmware.' }
    Write-Output "Completed: $($taskResults.function_count) function records; decoder matches original instructions. Results: $taskAnalysis"
} finally {
    $env:JAVA_HOME = $taskOldJava
}
