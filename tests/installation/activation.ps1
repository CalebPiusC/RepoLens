# Exercise the documented PowerShell workflow in a fresh, actual Windows virtualenv.
$ErrorActionPreference = 'Stop'
$env:PYTHONUTF8 = '1'
$env:PIP_DISABLE_PIP_VERSION_CHECK = '1'
$env:PIP_NO_INPUT = '1'
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
Remove-Item Env:PYTHONHOME -ErrorAction SilentlyContinue

function Assert-NativeSuccess([string] $Operation) {
    if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE" }
}

function Assert-Launcher([string] $Venv, [string] $Version) {
    $launcher = Join-Path $Venv 'Scripts\repolens.exe'
    if (-not (Test-Path $launcher)) { throw "Missing launcher: $launcher" }
    $resolved = (Get-Command repolens -CommandType Application).Source
    if ($resolved -ne $launcher) { throw "PATH resolved $resolved, not $launcher" }
    $output = (& repolens --version).Trim()
    Assert-NativeSuccess 'repolens --version'
    if ($output -ne "repolens $Version") { throw "Unexpected launcher version: $output" }
    $moduleOutput = (& python -m repolens --version).Trim()
    Assert-NativeSuccess 'python -m repolens --version'
    if ($moduleOutput -ne $output) { throw "Module and launcher versions differ" }
}

function Assert-Uninstalled([string] $Venv) {
    if (Test-Path (Join-Path $Venv 'Scripts\repolens.exe')) { throw 'Launcher was not removed' }
    python -c "import importlib.util; assert importlib.util.find_spec('repolens') is None"
    Assert-NativeSuccess 'verify import removal'
    python -m pip check
    Assert-NativeSuccess 'pip check after uninstall'
}

$work = Join-Path $env:RUNNER_TEMP ('rl-activation-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$venv = Join-Path $work 'repolens'
$project = Join-Path $work 'project'
New-Item -ItemType Directory -Path $work | Out-Null
try {
    python tests/installation/lifecycle.py fixture --directory $project
    Assert-NativeSuccess 'create scan fixture'
    $expected = (python -c "import runpy; print(runpy.run_path('src/repolens/_version.py')['__version__'])").Trim()
    Assert-NativeSuccess 'read current version'
    $selector = '-' + $env:PYTHON_VERSION
    & py $selector --version
    Assert-NativeSuccess 'select Python interpreter with py launcher'
    & py $selector -m venv $venv
    Assert-NativeSuccess 'create virtual environment'
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
    & (Join-Path $venv 'Scripts\Activate.ps1')
    $python = (Get-Command python -CommandType Application).Source
    if ($python -ne (Join-Path $venv 'Scripts\python.exe')) { throw "Unexpected Python: $python" }

    python -m pip install $env:REPOLENS_MAIN_URL
    Assert-NativeSuccess 'install documented main archive'
    python -m pip check
    Assert-NativeSuccess 'pip check for main archive'
    $mainVersion = (python -c "import importlib.metadata as m; print(m.version('repolens'))").Trim()
    Assert-NativeSuccess 'read main package version'
    Get-Command python, repolens | Select-Object -ExpandProperty Source
    Assert-Launcher $venv $mainVersion
    Push-Location $project
    try {
        repolens scan . --color never
        Assert-NativeSuccess 'repolens scan .'
        $json = & python -m repolens scan . --format json
        Assert-NativeSuccess 'python -m repolens scan .'
        $report = $json | ConvertFrom-Json
        if ($report.schema_version -ne '1.1.0' -or $report.result.exit_code -ne 0) {
            throw 'Unexpected JSON schema or scan result'
        }
    } finally { Pop-Location }
    python -m pip uninstall --yes repolens
    Assert-NativeSuccess 'uninstall main archive'
    Assert-Uninstalled $venv

    # Pin the branch/PR source independently; main may still have the older version.
    python -m pip install $env:REPOLENS_SOURCE_URL
    Assert-NativeSuccess 'install pinned source archive'
    Assert-Launcher $venv $expected
    python -m pip check
    Assert-NativeSuccess 'pip check for pinned source'
    python -m pip install --force-reinstall $env:REPOLENS_SOURCE_URL
    Assert-NativeSuccess 'force reinstall pinned source'
    Assert-Launcher $venv $expected
    python -m pip uninstall --yes repolens
    Assert-NativeSuccess 'uninstall pinned source'
    Assert-Uninstalled $venv
    Write-Host 'Windows PowerShell activation, main and pinned source, scan, reinstall and uninstall passed.'
} catch {
    Write-Host "::error::$($_.Exception.Message)"
    throw
} finally {
    if (Get-Command deactivate -ErrorAction SilentlyContinue) { deactivate }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
