$projectRoot = Split-Path -Parent $PSScriptRoot
$backendRoot = Join-Path $projectRoot "..\Backend"
$frontendRoot = Join-Path $projectRoot "..\Frontend"
$sandboxRoot = $projectRoot
$stagingRoot = Join-Path $projectRoot "staging\Download"
$backendPythonCommand = "py -3.14"
$healthCheckScript = Join-Path $PSScriptRoot "Check-StackHealth.ps1"
$stackStatePath = Join-Path $PSScriptRoot "stack-state.json"
$backendTitle = "Cyber Shield Backend"
$sandboxTitle = "Cyber Shield Sandbox Monitor"
$frontendTitle = "Cyber Shield Frontend"
$virtualBoxTitle = "Cyber Shield VirtualBox"

function Get-EnvFlag {
    param(
        [string]$Name,
        [bool]$DefaultValue = $false
    )

    $rawValue = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($rawValue)) {
        return $DefaultValue
    }

    switch ($rawValue.Trim().ToLowerInvariant()) {
        "1" { return $true }
        "true" { return $true }
        "yes" { return $true }
        "on" { return $true }
        "0" { return $false }
        "false" { return $false }
        "no" { return $false }
        "off" { return $false }
        default { return $DefaultValue }
    }
}

function Resolve-VirtualBoxVmExe {
    $candidates = @(
        "C:\Program Files\Oracle\VirtualBox\VirtualBoxVM.exe",
        "C:\Program Files (x86)\Oracle\VirtualBox\VirtualBoxVM.exe"
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    return $null
}

function Resolve-VirtualBoxVmName {
    if (-not [string]::IsNullOrWhiteSpace($env:VIRTUALBOX_VM_NAME)) {
        return $env:VIRTUALBOX_VM_NAME.Trim()
    }

    $globalConfigPath = Join-Path $env:USERPROFILE ".VirtualBox\VirtualBox.xml"
    if (-not (Test-Path $globalConfigPath)) {
        return $null
    }

    try {
        [xml]$globalConfig = Get-Content -Path $globalConfigPath
    }
    catch {
        return $null
    }

    $machineEntries = @($globalConfig.VirtualBox.Global.MachineRegistry.MachineEntry)
    if ($machineEntries.Count -ne 1) {
        return $null
    }

    $sourcePath = [string]$machineEntries[0].src
    if ([string]::IsNullOrWhiteSpace($sourcePath)) {
        return $null
    }

    return [System.IO.Path]::GetFileNameWithoutExtension($sourcePath)
}

function Find-RunningVirtualBoxVmProcess {
    param(
        [string]$VmName
    )

    $virtualBoxProcesses = @(Get-CimInstance Win32_Process -Filter "Name = 'VirtualBoxVM.exe'" -ErrorAction SilentlyContinue)
    if (-not $virtualBoxProcesses) {
        return $null
    }

    $matchingProcess = $virtualBoxProcesses | Where-Object {
        $_.CommandLine -and $_.CommandLine -match [regex]::Escape($VmName)
    } | Select-Object -First 1

    if ($matchingProcess) {
        return $matchingProcess
    }

    if ($virtualBoxProcesses.Count -eq 1) {
        return $virtualBoxProcesses[0]
    }

    return $null
}

if (-not (Test-Path $backendRoot)) {
    throw "Backend folder not found: $backendRoot"
}

if (-not (Test-Path $frontendRoot)) {
    throw "Frontend folder not found: $frontendRoot"
}

if (-not (Test-Path $healthCheckScript)) {
    throw "Health check script not found: $healthCheckScript"
}

New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null

$resolvedSandboxProvider = $env:SANDBOX_PROVIDER
$resolvedVmName = Resolve-VirtualBoxVmName
$autoOpenVirtualBox = Get-EnvFlag -Name "VIRTUALBOX_OPEN_ON_START" -DefaultValue $true
$virtualBoxVmExe = Resolve-VirtualBoxVmExe
$virtualBoxProcess = $null
$virtualBoxPid = 0
$virtualBoxAutoStarted = $false

if ([string]::IsNullOrWhiteSpace($resolvedSandboxProvider) -and -not [string]::IsNullOrWhiteSpace($resolvedVmName)) {
    $resolvedSandboxProvider = "virtualbox"
}

if (-not [string]::IsNullOrWhiteSpace($resolvedSandboxProvider)) {
    $env:SANDBOX_PROVIDER = $resolvedSandboxProvider
}

if (-not [string]::IsNullOrWhiteSpace($resolvedVmName)) {
    $env:VIRTUALBOX_VM_NAME = $resolvedVmName
}

if ($resolvedSandboxProvider -eq "virtualbox" -and $autoOpenVirtualBox) {
    if ([string]::IsNullOrWhiteSpace($resolvedVmName)) {
        Write-Warning "VirtualBox sandbox is selected, but no VM name was resolved. Set VIRTUALBOX_VM_NAME to auto-open the guest on project start."
    }
    elseif (-not $virtualBoxVmExe) {
        Write-Warning "VirtualBoxVM.exe was not found, so the VM window will not auto-open on project start."
    }
    else {
        $runningVmProcess = Find-RunningVirtualBoxVmProcess -VmName $resolvedVmName
        if ($runningVmProcess) {
            $virtualBoxProcess = $runningVmProcess
            $virtualBoxPid = [int]$runningVmProcess.ProcessId
            Write-Host "VirtualBox VM already running: $resolvedVmName (PID $($runningVmProcess.ProcessId))"
        }
        else {
            Write-Host "Starting VirtualBox VM window..."
            $virtualBoxProcess = Start-Process -FilePath $virtualBoxVmExe -PassThru -ArgumentList @("--startvm", $resolvedVmName)
            $virtualBoxPid = [int]$virtualBoxProcess.Id
            $virtualBoxAutoStarted = $true
            Start-Sleep -Seconds 2
        }
    }
}

Write-Host "Starting backend window..."
$backendProcess = Start-Process powershell.exe -PassThru -ArgumentList @(
    "-NoExit",
    "-ExecutionPolicy", "Bypass",
    "-Command",
    "& { Set-Location '$backendRoot'; `$Host.UI.RawUI.WindowTitle = '$backendTitle'; `$env:SANDBOX_STAGING_DIR = '$stagingRoot'; $backendPythonCommand -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000 }"
)

Start-Sleep -Seconds 2

Write-Host "Starting sandbox monitor window..."
$sandboxProcess = Start-Process powershell.exe -PassThru -ArgumentList @(
    "-NoExit",
    "-ExecutionPolicy", "Bypass",
    "-Command",
    "& { Set-Location '$sandboxRoot'; `$Host.UI.RawUI.WindowTitle = '$sandboxTitle'; `$env:SANDBOX_STAGING_DIR = '$stagingRoot'; $backendPythonCommand sandbox_monitor.py }"
)

Start-Sleep -Seconds 2

Write-Host "Starting frontend window..."
$frontendProcess = Start-Process powershell.exe -PassThru -ArgumentList @(
    "-NoExit",
    "-ExecutionPolicy", "Bypass",
    "-Command",
    "& { Set-Location '$frontendRoot'; `$Host.UI.RawUI.WindowTitle = '$frontendTitle'; npm.cmd run dev }"
)

$stackState = @{
    backend = @{
        title = $backendTitle
        pid = $backendProcess.Id
    }
    sandbox = @{
        title = $sandboxTitle
        pid = $sandboxProcess.Id
    }
    frontend = @{
        title = $frontendTitle
        pid = $frontendProcess.Id
    }
    virtualbox = @{
        title = $virtualBoxTitle
        pid = $virtualBoxPid
        vm_name = $resolvedVmName
        provider = $resolvedSandboxProvider
        auto_started = $virtualBoxAutoStarted
    }
    created_at = (Get-Date).ToString("s")
}

$stackState | ConvertTo-Json | Set-Content -Path $stackStatePath

Write-Host "Backend, sandbox monitor, and frontend launched."
Write-Host "Waiting for services to come up before running health check..."
Start-Sleep -Seconds 8
Write-Host ""
Write-Host "Stack health"
& $healthCheckScript

