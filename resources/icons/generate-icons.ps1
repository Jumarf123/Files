param(
  [string]$SourcePng = "resources\\icons\\files-icon-source.png",
  [string]$SourceIco = "Ico\\ico.ico",
  [string]$OutputDir = "src-tauri\\icons"
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\\..")
$sourcePath = Join-Path $repoRoot $SourcePng
$sourceIcoPath = Join-Path $repoRoot $SourceIco
$outputPath = Join-Path $repoRoot $OutputDir

if (-not (Test-Path $sourcePath) -and -not (Test-Path $sourceIcoPath)) {
  throw "Canonical icon source was not found: $sourcePath or $sourceIcoPath"
}

New-Item -ItemType Directory -Path $outputPath -Force | Out-Null

Push-Location $repoRoot
try {
  if (Test-Path $sourcePath) {
    npx --prefix app tauri icon $sourcePath -o $outputPath
    python (Join-Path $PSScriptRoot "build_windows_ico.py") $sourcePath (Join-Path $outputPath "icon.ico")
  } else {
    Copy-Item -Path $sourceIcoPath -Destination (Join-Path $outputPath "icon.ico") -Force
  }

  Copy-Item -Path (Join-Path $outputPath "icon.ico") -Destination (Join-Path $repoRoot "app\\public\\files.ico") -Force
  Copy-Item -Path (Join-Path $outputPath "icon.ico") -Destination (Join-Path $repoRoot "app\\public\\rss.ico") -Force
  Copy-Item -Path (Join-Path $outputPath "icon.ico") -Destination (Join-Path $repoRoot "resources\\icons\\files.ico") -Force
  Copy-Item -Path (Join-Path $outputPath "icon.ico") -Destination (Join-Path $repoRoot "resources\\icons\\rss.ico") -Force
  Copy-Item -Path (Join-Path $outputPath "icon.ico") -Destination (Join-Path $repoRoot "files.ico") -Force
  Copy-Item -Path (Join-Path $outputPath "icon.ico") -Destination (Join-Path $repoRoot "rss.ico") -Force
} finally {
  Pop-Location
}
