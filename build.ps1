param(
    [string]$PythonPath = "python",
    [string]$OwnerName = "",
    [string]$DocsPythonPath = ""
)

$ErrorActionPreference = "Stop"

$projectRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$distPath = Join-Path $projectRoot "dist"
$workPath = Join-Path $projectRoot ".build\FileSentrySentinel"
$specPath = Join-Path $projectRoot ".build\spec"
$temporaryRoot = Join-Path $projectRoot ".build"
$legacyWorkPath = Join-Path $projectRoot "build"
$outputPath = Join-Path $distPath "FileSentrySentinel.exe"
$guideOutputPath = Join-Path $distPath "FileSentrySentinel_User_Guide.docx"
$certificateOutputPath = Join-Path $distPath "FileSentrySentinel_Exclusive_Build_Certificate.docx"
$certificateDraftPath = Join-Path $temporaryRoot "FileSentrySentinel_Exclusive_Build_Certificate.draft.docx"
$protectionScriptPath = Join-Path $PSScriptRoot "tools\set_docx_readonly.py"

function Assert-WorkspacePath {
    param([string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $rootPrefix = $projectRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if ($full -eq $projectRoot -or -not $full.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Từ chối thao tác ngoài workspace: $full"
    }
}

foreach ($safePath in @($distPath, $workPath, $specPath, $temporaryRoot, $legacyWorkPath, $certificateDraftPath)) {
    Assert-WorkspacePath $safePath
}

# dist is reserved for release artifacts. A successful build leaves only the
# current EXE there; intermediate PyInstaller files live in .build and are
# removed in the finally block below.
if (Test-Path -LiteralPath $distPath) {
    Get-ChildItem -LiteralPath $distPath -Force | Remove-Item -Force -Recurse
} else {
    New-Item -ItemType Directory -Path $distPath -Force | Out-Null
}
if (Test-Path -LiteralPath $workPath) { Remove-Item -LiteralPath $workPath -Force -Recurse }
if (Test-Path -LiteralPath $specPath) { Remove-Item -LiteralPath $specPath -Force -Recurse }
if (Test-Path -LiteralPath $legacyWorkPath) { Remove-Item -LiteralPath $legacyWorkPath -Force -Recurse }
New-Item -ItemType Directory -Path $workPath -Force | Out-Null
New-Item -ItemType Directory -Path $specPath -Force | Out-Null

if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
    $pythonCommand = Get-Command $PythonPath -ErrorAction SilentlyContinue
    if ($pythonCommand) { $PythonPath = $pythonCommand.Source }
    else { throw "Không tìm thấy Python: $PythonPath" }
}

if (-not $DocsPythonPath) { $DocsPythonPath = $env:FILESENTRY_DOCS_PYTHON }
if (-not $DocsPythonPath -and $env:USERPROFILE) {
    $runtimeCandidate = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
    if (Test-Path -LiteralPath $runtimeCandidate -PathType Leaf) { $DocsPythonPath = $runtimeCandidate }
}
if (-not $DocsPythonPath) { $DocsPythonPath = $PythonPath }
if (-not $DocsPythonPath -or -not (Test-Path -LiteralPath $DocsPythonPath -PathType Leaf)) {
    throw "Không tìm thấy Python có python-docx. Dùng -DocsPythonPath hoặc đặt FILESENTRY_DOCS_PYTHON."
}
if (-not (Test-Path -LiteralPath $protectionScriptPath -PathType Leaf)) {
    throw "Không tìm thấy công cụ khóa sửa Word: $protectionScriptPath"
}

function Invoke-RequiredStep {
    param([string[]]$Arguments)
    & $PythonPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Lệnh build thất bại với mã ${LASTEXITCODE}: python $($Arguments -join ' ')"
    }
}

function Invoke-DocsStep {
    param([string[]]$Arguments)
    & $DocsPythonPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Lệnh tạo tài liệu thất bại với mã ${LASTEXITCODE}: $DocsPythonPath $($Arguments -join ' ')"
    }
}

try {
    if (-not $OwnerName) { $OwnerName = $env:FILESENTRY_OWNER }
    if (-not $OwnerName) { $OwnerName = $env:USERNAME }
    if (-not $OwnerName) { $OwnerName = "Local Project Owner" }
    Invoke-RequiredStep @("-m", "pip", "install", "-r", (Join-Path $PSScriptRoot "requirements.txt"))
    Invoke-RequiredStep @("-m", "pip", "install", "pyinstaller")
    Invoke-RequiredStep @("-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed", "--uac-admin", "--icon", (Join-Path $PSScriptRoot "assets\filesentry-sentinel.ico"), "--add-data", ((Join-Path $PSScriptRoot "assets\filesentry-sentinel.ico") + ";assets"), "--name", "FileSentrySentinel", "--distpath", $distPath, "--workpath", $workPath, "--specpath", $specPath, (Join-Path $PSScriptRoot "main.py"))
    if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
        throw "Không tìm thấy output EXE: $outputPath"
    }
    Invoke-DocsStep @((Join-Path $PSScriptRoot "tools\generate_release_docs.py"), "--exe", $outputPath, "--guide-source", (Join-Path $PSScriptRoot "docs\USER_GUIDE.md"), "--dist", $distPath, "--owner", $OwnerName, "--certificate-output", $certificateDraftPath)
    if (-not (Test-Path -LiteralPath $certificateDraftPath -PathType Leaf)) {
        throw "Không tìm thấy chứng chỉ nháp: $certificateDraftPath"
    }
    Invoke-DocsStep @($protectionScriptPath, $certificateDraftPath, "--out", $certificateOutputPath)
    Remove-Item -LiteralPath $certificateDraftPath -Force
    foreach ($artifact in @($guideOutputPath, $certificateOutputPath)) {
        if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
            throw "Không tìm thấy build artefact: $artifact"
        }
    }
    Write-Host "Build complete: $outputPath"
    Write-Host "Guide: $guideOutputPath"
    Write-Host "Certificate: $certificateOutputPath"
} finally {
    if (Test-Path -LiteralPath $certificateDraftPath) { Remove-Item -LiteralPath $certificateDraftPath -Force }
    if (Test-Path -LiteralPath $workPath) { Remove-Item -LiteralPath $workPath -Force -Recurse }
    if (Test-Path -LiteralPath $specPath) { Remove-Item -LiteralPath $specPath -Force -Recurse }
    if (Test-Path -LiteralPath $temporaryRoot) {
        $remaining = @(Get-ChildItem -LiteralPath $temporaryRoot -Force)
        if ($remaining.Count -eq 0) { Remove-Item -LiteralPath $temporaryRoot -Force }
    }
}
