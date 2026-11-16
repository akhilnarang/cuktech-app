<#
.SYNOPSIS
Decompile an explicit Mi Home APK with an existing local JADX distribution.
.DESCRIPTION
Static analysis only. Does not install/execute the APK or use a cloud account.
OutputDirectory must not exist. Keep decompiled vendor files out of version control.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Apk,
    [Parameter(Mandatory)][string]$JadxDirectory,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][string]$JavaHome,
    [ValidateRange(1, 8)][int]$Threads = 4,
    [ValidateRange(512, 16384)][int]$HeapMiB = 8192
)
$ErrorActionPreference = 'Stop'
$apkPath = (Resolve-Path -LiteralPath $Apk).Path
$jadxPath = (Resolve-Path -LiteralPath $JadxDirectory).Path
$javaPath = Join-Path (Resolve-Path -LiteralPath $JavaHome).Path 'bin/java.exe'
$jarFiles = @(Get-ChildItem -LiteralPath (Join-Path $jadxPath 'lib') -Filter 'jadx-*-all.jar')
if (!(Test-Path -LiteralPath $javaPath) -or $jarFiles.Count -ne 1) {
    throw 'Expected an existing JDK and exactly one JADX all-in-one JAR.'
}
$outPath = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outPath) { throw 'OutputDirectory must be new.' }
$null = New-Item -ItemType Directory -Path $outPath
$started = [DateTime]::UtcNow.ToString('o')
$apkHash = (Get-FileHash -LiteralPath $apkPath -Algorithm SHA256).Hash.ToLowerInvariant()
$toolHash = (Get-FileHash -LiteralPath $jarFiles[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
$codePath = Join-Path $outPath 'decompiled'
$logPath = Join-Path $outPath 'jadx.log'
$jadxArguments = @('-d', $codePath, '-j', "$Threads", '--log-level', 'info', '--config', 'none', $apkPath)
$javaArguments = @("-Xmx$($HeapMiB)m", '-XX:ParallelGCThreads=2', '-Dfile.encoding=UTF-8', '-cp', $jarFiles[0].FullName, 'jadx.cli.JadxCLI') + $jadxArguments
# Call the JVM directly to avoid changing JAVA_HOME or the installed toolchain.
& $javaPath @javaArguments *> $logPath
$jadxExitCode = $LASTEXITCODE
$sourceFiles = @(Get-ChildItem -LiteralPath $codePath -Recurse -Filter '*.java' -File -ErrorAction SilentlyContinue)
$manifest = Join-Path $codePath 'resources/AndroidManifest.xml'
$receipt = [ordered]@{
    apk = $apkPath; apk_sha256 = $apkHash
    apk_bytes = (Get-Item -LiteralPath $apkPath).Length
    tool_jar = $jarFiles[0].FullName; tool_jar_sha256 = $toolHash
    arguments = $jadxArguments; heap_mib = $HeapMiB
    started_utc = $started; completed_utc = [DateTime]::UtcNow.ToString('o')
    exit_code = $jadxExitCode; java_files = $sourceFiles.Count
    manifest_present = (Test-Path -LiteralPath $manifest)
    limitations = @('Static decompilation, not execution or original source.', 'Inspect jadx.log and individual methods for errors before relying on reconstructed code.')
}
$receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $outPath 'decompilation.json') -Encoding utf8
$receipt | ConvertTo-Json -Depth 5
if ($sourceFiles.Count -eq 0 -or !(Test-Path -LiteralPath $manifest)) {
    throw "Decompilation did not produce source and a manifest. See $logPath"
}
if ($jadxExitCode -ne 0) {
    throw "JADX returned $jadxExitCode; partial output and receipt are retained. See $logPath"
}
