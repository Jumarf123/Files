param(
  [string]$ResultsDir = (Join-Path $PSScriptRoot "..\..\results")
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$appDir = Join-Path $repoRoot "app"
$srcDir = Join-Path $repoRoot "src-tauri"
$smokeScript = Join-Path $repoRoot "resources\installer\smoke-runtime.ps1"
$version = (Get-Content (Join-Path $appDir "package.json") -Raw | ConvertFrom-Json).version
$bundleRoot = Join-Path $srcDir "target\release\bundle"
$releaseExe = Join-Path $srcDir "target\release\files.exe"
$resultsDir = (Resolve-Path -Path $ResultsDir -ErrorAction SilentlyContinue)?.Path ?? $ResultsDir

function Invoke-Step {
  param(
    [string]$Name,
    [scriptblock]$Action
  )

  Write-Host "==> $Name"
  & $Action
}

function Get-BundleArtifact {
  param(
    [string]$Root,
    [string]$Pattern,
    [string]$Extension
  )

  $match = Get-ChildItem -Path $Root -Recurse -File -Filter $Extension |
    Where-Object { $_.Name -like $Pattern } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

  if ($null -eq $match) {
    throw "Unable to locate bundle artifact matching $Pattern under $Root"
  }

  $match.FullName
}

Push-Location $repoRoot
try {
  Invoke-Step "Frontend lint" { Push-Location $appDir; try { npm run lint } finally { Pop-Location } }
  Invoke-Step "Frontend test" { Push-Location $appDir; try { npm run test } finally { Pop-Location } }
  Invoke-Step "Rust test" { Push-Location $srcDir; try { cargo test --workspace } finally { Pop-Location } }
  Invoke-Step "Frontend build" { Push-Location $appDir; try { npm run build } finally { Pop-Location } }
  Invoke-Step "Installer build" { Push-Location $appDir; try { npm run tauri:build } finally { Pop-Location } }
  Invoke-Step "Smoke check" { & $smokeScript -ExePath $releaseExe }

  $nsisArtifact = Get-BundleArtifact -Root $bundleRoot -Pattern "Files_${version}_x64*setup*.exe" -Extension "*.exe"
  $msiArtifact = Get-BundleArtifact -Root $bundleRoot -Pattern "Files_${version}_x64*.msi" -Extension "*.msi"

  New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null

  $legacyProductPrefix = "RSS" + "-Files"
  Get-ChildItem -Path $resultsDir -File |
    Where-Object { $_.Name -like "Files_${version}_x64*" -or $_.Name -like "${legacyProductPrefix}_${version}_x64*" } |
    Remove-Item -Force

  $nsisDest = Join-Path $resultsDir "Files_${version}_x64-setup.exe"
  $msiDest = Join-Path $resultsDir "Files_${version}_x64_en-US.msi"
  Copy-Item -LiteralPath $nsisArtifact -Destination $nsisDest -Force
  Copy-Item -LiteralPath $msiArtifact -Destination $msiDest -Force

  $manifestPath = Join-Path $resultsDir "Files_${version}_x64-SHA256SUMS.txt"
  Get-FileHash -Algorithm SHA256 -LiteralPath @($nsisDest, $msiDest) | ForEach-Object {
    "$($_.Hash)  $($_.Path | Split-Path -Leaf)"
  } | Set-Content -Path $manifestPath -Encoding ascii

  Write-Host "Release artifacts copied to $resultsDir"
  Write-Host "Manifest written to $manifestPath"
} finally {
  Pop-Location
}
