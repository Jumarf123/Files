param(
  [string]$ExePath = "src-tauri\\target\\release\\files.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ExePath)) {
  throw "Executable not found: $ExePath"
}

$resolvedExePath = (Resolve-Path $ExePath).Path
Add-Type -AssemblyName System.Drawing
$icon = [System.Drawing.Icon]::ExtractAssociatedIcon($resolvedExePath)
if ($null -eq $icon -or $icon.Width -le 0 -or $icon.Height -le 0) {
  throw "Associated application icon was not found on the built executable."
}

$beforeConhost = @(Get-Process conhost -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
$process = Start-Process -FilePath $ExePath -PassThru

try {
  $deadline = (Get-Date).AddSeconds(20)
  do {
    Start-Sleep -Milliseconds 300
    $process.Refresh()
  } while (-not $process.MainWindowHandle -and (Get-Date) -lt $deadline)

  if (-not $process.MainWindowHandle) {
    throw "Main window did not become visible."
  }

  $afterConhost = @(Get-Process conhost -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
  $newConhost = $afterConhost | Where-Object { $_ -notin $beforeConhost }
  if ($newConhost.Count -gt 0) {
    throw "A new console host was detected after launch."
  }

  $manifestTool = Get-Command mt.exe -ErrorAction SilentlyContinue
  if ($manifestTool) {
    $manifestPath = Join-Path $env:TEMP "files.manifest.extracted.xml"
    & $manifestTool.Source -nologo "-inputresource:$ExePath;#1" "-out:$manifestPath" | Out-Null
    $manifest = Get-Content -Path $manifestPath -Raw
    if ($manifest -notmatch 'requestedExecutionLevel level="requireAdministrator"') {
      throw "Embedded manifest does not request administrator elevation."
    }
  } else {
    $pythonManifest = @'
import pefile
import sys

pe = pefile.PE(sys.argv[1])
manifest = None
for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    name = entry.name if entry.name is not None else entry.struct.Id
    if name == pefile.RESOURCE_TYPE["RT_MANIFEST"]:
        for first in entry.directory.entries:
            for second in first.directory.entries:
                data_rva = second.data.struct.OffsetToData
                size = second.data.struct.Size
                blob = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                manifest = blob.decode("utf-8", errors="ignore")
                break

if manifest is None or 'requestedExecutionLevel level="requireAdministrator"' not in manifest:
    sys.exit(2)
'@

    $manifestCheck = $pythonManifest | python - $resolvedExePath
    if ($LASTEXITCODE -ne 0) {
      throw "Embedded manifest does not request administrator elevation."
    }
  }

  Write-Host "Runtime smoke check passed."
} finally {
  if (-not $process.HasExited) {
    Stop-Process -Id $process.Id -Force
  }
}
