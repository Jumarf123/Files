Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class VisualCaptureWinApi {
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int x, int y, int nWidth, int nHeight, bool repaint);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);
  [StructLayout(LayoutKind.Sequential)]
  public struct RECT {
    public int Left;
    public int Top;
    public int Right;
    public int Bottom;
  }
}
'@

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$outputDir = Join-Path $repoRoot "visual-artifacts"

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
$edgePath = @(
  "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
  "C:\Program Files\Microsoft\Edge\Application\msedge.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $edgePath) {
  throw "Microsoft Edge was not found on this machine."
}

function Stop-PreviewPort {
  $listeners = @(Get-NetTCPConnection -LocalPort 4173 -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique)
  foreach ($listenerPid in $listeners) {
    if ($listenerPid) {
      Stop-Process -Id $listenerPid -Force -ErrorAction SilentlyContinue
    }
  }
}

function Wait-PreviewReady {
  $deadline = (Get-Date).AddSeconds(20)
  do {
    Start-Sleep -Milliseconds 500
    try {
      Invoke-WebRequest -Uri "http://127.0.0.1:4173" -UseBasicParsing | Out-Null
      return
    } catch {
    }
  } while ((Get-Date) -lt $deadline)

  throw "Preview server did not become ready."
}

function Get-EdgeWindowProcess {
  param(
    [int[]]$ExistingIds,
    [datetime]$LaunchTime,
    [string]$Label
  )

  $windowDeadline = (Get-Date).AddSeconds(20)
  do {
    Start-Sleep -Milliseconds 400
    $candidate = Get-Process msedge -ErrorAction SilentlyContinue |
      Where-Object { $_.Id -notin $ExistingIds -and $_.MainWindowHandle -ne 0 -and $_.StartTime -ge $LaunchTime.AddSeconds(-2) } |
      Sort-Object StartTime -Descending |
      Select-Object -First 1

    if ($candidate) {
      return $candidate
    }
  } while ((Get-Date) -lt $windowDeadline)

  $snapshot = Get-Process msedge -ErrorAction SilentlyContinue |
    Select-Object Id, MainWindowHandle, MainWindowTitle, StartTime |
    Format-Table -AutoSize | Out-String
  throw "Edge window was not created for $Label.`n$snapshot"
}

function Save-WindowCapture {
  param(
    [System.Diagnostics.Process]$Process,
    [string]$TargetPath
  )

  $rect = New-Object VisualCaptureWinApi+RECT
  [VisualCaptureWinApi]::GetWindowRect($Process.MainWindowHandle, [ref]$rect) | Out-Null
  $width = $rect.Right - $rect.Left
  $height = $rect.Bottom - $rect.Top
  if ($width -le 0 -or $height -le 0) {
    throw "Edge reported an invalid window rect."
  }

  $bitmap = New-Object System.Drawing.Bitmap $width, $height
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
  $hdc = $graphics.GetHdc()
  $printed = $false

  try {
    $printed = [VisualCaptureWinApi]::PrintWindow($Process.MainWindowHandle, $hdc, 2)
  } finally {
    $graphics.ReleaseHdc($hdc)
  }

  if (-not $printed) {
    $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
  }

  try {
    $bitmap.Save($TargetPath, [System.Drawing.Imaging.ImageFormat]::Png)
  } finally {
    $graphics.Dispose()
    $bitmap.Dispose()
  }
}

Stop-PreviewPort
$server = Start-Process -FilePath "npm.cmd" -ArgumentList "run", "preview", "--", "--host", "127.0.0.1", "--port", "4173" -WorkingDirectory $repoRoot -PassThru -WindowStyle Hidden

try {
  Wait-PreviewReady

  $viewports = @(
    @{ Width = 1366; Height = 768 },
    @{ Width = 1600; Height = 900 },
    @{ Width = 1920; Height = 1080 }
  )

  foreach ($viewport in $viewports) {
    $existingEdgeIds = @(Get-Process msedge -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
    $launchTime = Get-Date
    $browser = Start-Process -FilePath $edgePath -ArgumentList "--new-window", "--app=http://127.0.0.1:4173/", "--window-size=$($viewport.Width),$($viewport.Height)", "--force-device-scale-factor=1" -PassThru
    try {
      $windowProcess = Get-EdgeWindowProcess -ExistingIds $existingEdgeIds -LaunchTime $launchTime -Label "$($viewport.Width)x$($viewport.Height)"
      [VisualCaptureWinApi]::ShowWindow($windowProcess.MainWindowHandle, 5) | Out-Null
      [VisualCaptureWinApi]::MoveWindow($windowProcess.MainWindowHandle, 24, 24, $viewport.Width, $viewport.Height, $true) | Out-Null
      [VisualCaptureWinApi]::SetForegroundWindow($windowProcess.MainWindowHandle) | Out-Null
      Start-Sleep -Seconds 2

      $target = Join-Path $outputDir "workbench-$($viewport.Width)x$($viewport.Height).png"
      Save-WindowCapture -Process $windowProcess -TargetPath $target

      if (-not (Test-Path $target)) {
        throw "Screenshot was not created for $($viewport.Width)x$($viewport.Height)."
      }
    } finally {
      Get-Process msedge -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -notin $existingEdgeIds } |
        ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
      if (-not $browser.HasExited) {
        Stop-Process -Id $browser.Id -Force -ErrorAction SilentlyContinue
      }
    }
  }

  Write-Host "Visual verification screenshots saved to $outputDir"
} finally {
  if (-not $server.HasExited) {
    Stop-Process -Id $server.Id -Force
  }
  Stop-PreviewPort
}
