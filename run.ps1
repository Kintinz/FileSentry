param(
    [string]$PythonPath = ""
)

$ErrorActionPreference = "Stop"

if (-not $PythonPath) {
    $localVenv = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $localVenv) {
        $PythonPath = $localVenv
    }
}

if (-not $PythonPath) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand -and $pythonCommand.Source -notlike "*\WindowsApps\python.exe") {
        $PythonPath = $pythonCommand.Source
    }
}

if (-not $PythonPath -or -not (Test-Path -LiteralPath $PythonPath)) {
    throw "Không tìm thấy Python. Cài Python 3.11+ hoặc truyền -PythonPath đến python.exe."
}

$entryPoint = Join-Path $PSScriptRoot "main.py"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdministrator) {
    & $PythonPath $entryPoint
    exit $LASTEXITCODE
}

$elevated = Start-Process -FilePath $PythonPath `
    -ArgumentList @("`"$entryPoint`"") `
    -WorkingDirectory $PSScriptRoot `
    -Verb RunAs `
    -Wait `
    -PassThru

if ($elevated.ExitCode -ne 0) {
    throw "FileSentry thoát với mã: $($elevated.ExitCode)"
}
