#Requires -Version 5.1
<#
    PolinRider Malware Scanner v1.3 (Windows)

    Scans a Windows system for PolinRider / TasksJacker malware indicators.
    Detects both obfuscator variants (rmcej%otb% and Cot%3t=shtP),
    malicious npm packages, weaponized .vscode/tasks.json, fake font
    payloads, propagation scripts, credential stealer artifacts,
    active C2 connections, Windows services, PowerShell profiles,
    agent config directories, and git history across all branches.

    Usage:
      .\polinrider-scanner-windows.ps1                          # Scan repos under current directory
      .\polinrider-scanner-windows.ps1 -FullSystem              # Full Windows system scan
      .\polinrider-scanner-windows.ps1 -Quick                   # Quick scan (processes + network + DNS investigation)
      .\polinrider-scanner-windows.ps1 -Verbose -Path C:\repos  # Verbose repo scan

    Exit codes:
      0 - No infections found
      1 - Infections found
      2 - Error
#>

[CmdletBinding()]
param(
    [string]$Path,
    [switch]$FullSystem,
    [switch]$Quick,
    [switch]$JsAll,
    [string]$ReportKey,
    [string]$ReportChannel
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Resolve scanner's own path so we can skip it during file scans
$ScannerScriptPath = if ($PSCommandPath) { (Resolve-Path $PSCommandPath -ErrorAction SilentlyContinue).Path } else { $null }

# -------------------------------------------------------------------------
# Variant 1 signatures (original)
# -------------------------------------------------------------------------
$V1_MARKER   = 'rmcej%otb%'
$V1_SEED     = '2857687'
$V1_SEED2    = '2667686'
$V1_DECODER  = '_$_1e42'
$V1_GLOBAL   = "global['!']"

# -------------------------------------------------------------------------
# Variant 2 signatures (rotated)
# -------------------------------------------------------------------------
$V2_MARKER   = 'Cot%3t=shtP'
$V2_SEED     = '1111436'
$V2_SEED2    = '3896884'
$V2_DECODER  = 'MDy'
$V2_GLOBAL   = "global['_V']"

# Common across variants
$COMMON_GLOBAL_R = "global['r'] = require"
$COMMON_GLOBAL_M = "global['m'] = module"

# -------------------------------------------------------------------------
# Config files targeted by PolinRider
# -------------------------------------------------------------------------
$CONFIG_FILES = @(
    'postcss.config.mjs','postcss.config.js','postcss.config.cjs',
    'tailwind.config.js','tailwind.config.mjs',
    'eslint.config.mjs','next.config.mjs','next.config.js','next.config.ts',
    'babel.config.js','jest.config.js','vite.config.js','vite.config.mjs',
    'webpack.config.js','gridsome.config.js','vue.config.js','truffle.js',
    'astro.config.mjs','App.js','app.js','index.js'
)

# -------------------------------------------------------------------------
# Known malicious npm packages
# -------------------------------------------------------------------------
$MALICIOUS_NPM_PKGS = @(
    'tailwindcss-style-animate','tailwind-mainanimation','tailwind-autoanimation',
    'tailwind-animationbased','tailwindcss-typography-style',
    'tailwindcss-style-modify','tailwindcss-animate-style'
)

# Legitimate tailwind packages (allowlist)
$TAILWIND_ALLOWLIST = @(
    'tailwindcss','tailwindcss-animate','tailwind-merge','tailwind-variants',
    'prettier-plugin-tailwindcss','tailwindcss-radix','tailwindcss-debug-screens',
    'storybook-addon-tailwindcss','tailwindcss-textshadow',
    'tailwindcss-3d','tailwindcss-animated','tailwindcss-gradients','tailwindcss-scrollbar',
    'tailwindcss-question-mark','tailwindcss-opentype','tailwindcss-hyphens',
    'tailwindcss-writing-mode','tailwindcss-border-gradient','tailwindcss-dir',
    'tailwindcss-fluid-type','tailwindcss-children','tailwindcss-multi',
    'tailwindcss-primeui','tailwindcss-react-aria-components','tw-animate-css'
)

# -------------------------------------------------------------------------
# C2 infrastructure
# -------------------------------------------------------------------------
$C2_DOMAINS = @(
    '260120.vercel.app','default-configuration.vercel.app',
    'vscode-settings-bootstrap.vercel.app','vscode-settings-config.vercel.app',
    'vscode-bootstrapper.vercel.app','vscode-load-config.vercel.app',
    'onrender.com'
)
$BLOCKCHAIN_HOSTS = @(
    'api.trongrid.io','fullnode.mainnet.aptoslabs.com',
    'bsc-dataseed.binance.org','bsc-rpc.publicnode.com'
)
$TRON_ADDR_1  = 'TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP'
$TRON_ADDR_2  = 'TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG'
$APTOS_HASH_1 = '0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e'
$APTOS_HASH_2 = '0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3'

$STAKING_UUID = 'e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9'
$SHOEVISTA_NAMES = @('ShoeVista','shoevista','shoe-vista','Test-west-shoe')

$XOR_KEY_1 = '2[gWfGj;<:-93Z^C'
$XOR_KEY_2 = 'm6:tTh^D)cBz?NM]'

$IDE_CONFIG_DIRS = @('.vscode','.cursor','.claude')

$TAILWIND_PKG_REGEX  = '"([-a-z0-9@_./]*tailwind[-a-z0-9_./]*)"'
$TAILWIND_LIST_REGEX = '([-a-z0-9@_./]*tailwind[-a-z0-9_./]*)'

# Stage 4 credential stealer IOCs
$STEALER_LOCK_FILE = 'tmp7A863DD1.tmp'
$STEALER_C2_IP = '166.88.54.158'

# -------------------------------------------------------------------------
# Counters
# -------------------------------------------------------------------------
$script:TotalRepos     = 0
$script:InfectedRepos  = 0
$script:SystemFindings = 0
$script:Findings       = [System.Collections.ArrayList]::new()

# Auto-cleanup tracking (populated during local repo scan only)
$script:CleanupBatFiles       = [System.Collections.ArrayList]::new()
$script:CleanupGitignoreRepos = [System.Collections.ArrayList]::new()
$script:CleanupNodeModules    = [System.Collections.ArrayList]::new()
$script:DnsC2Hits      = [System.Collections.ArrayList]::new()
$script:DnsBlockchain  = [System.Collections.ArrayList]::new()
$script:DnsExfil       = [System.Collections.ArrayList]::new()
$script:ActiveC2Conns  = [System.Collections.ArrayList]::new()
$script:SuspiciousProcs = [System.Collections.ArrayList]::new()
$script:StealerArtifactsFound = $false
$script:RiskScore      = 0
$script:RiskLevel      = 'NONE'
$script:ModuleStatus   = [ordered]@{}

# -------------------------------------------------------------------------
# JSON report data collectors
# -------------------------------------------------------------------------
$script:ReportFindings    = [System.Collections.ArrayList]::new()
$script:ReportInfectedRepos = [ordered]@{}
$script:CurrentRepoDir    = ''

# -------------------------------------------------------------------------
# Utility functions
# -------------------------------------------------------------------------
function Set-ModuleStatus ([string]$Module, [string]$Status, [string]$Detail) {
    $script:ModuleStatus[$Module] = @{ Status = $Status; Detail = $Detail }
}

function Get-AllUserProfiles {
    $profiles = @()
    $usersDir = "$env:SystemDrive\Users"
    if (Test-Path $usersDir) {
        $profiles = @(Get-ChildItem $usersDir -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') } |
            Where-Object { Test-Path (Join-Path $_.FullName 'NTUSER.DAT') } |
            ForEach-Object { $_.FullName })
    }
    if ($profiles.Count -eq 0) {
        $profiles = @($env:USERPROFILE)
    }
    return $profiles
}

function Write-Banner {
    Write-Host ''
    Write-Host '================================================' -ForegroundColor White
    Write-Host '  PolinRider Malware Scanner v1.3 (Windows)'     -ForegroundColor White
    Write-Host '  https://opensourcemalware.com'                  -ForegroundColor White
    Write-Host '  Detects variants: rmcej%otb% + Cot%3t=shtP'    -ForegroundColor White
    Write-Host '================================================' -ForegroundColor White
    Write-Host ''
}

function Write-Section ([string]$Tag, [string]$Msg) {
    Write-Host ''
    Write-Host "[$Tag] $Msg" -ForegroundColor Magenta
}

function Add-RepoFinding ([string]$Label, [string]$Detail, [string]$Severity) {
    $color = if ($Severity -eq 'HIGH') { 'Red' } else { 'Yellow' }
    Write-Host "  - $Label : $Detail" -ForegroundColor $color

    $repoDir = $script:CurrentRepoDir
    if ($repoDir) {
        if (-not $script:ReportInfectedRepos.Contains($repoDir)) {
            $script:ReportInfectedRepos[$repoDir] = [System.Collections.ArrayList]::new()
        }
        $null = $script:ReportInfectedRepos[$repoDir].Add([ordered]@{
            file        = $Label
            description = $Detail
            severity    = $Severity
        })
    }
}

function Add-SystemFinding ([string]$Category, [string]$Detail) {
    $script:SystemFindings++
    $null = $script:Findings.Add("[$Category] $Detail")
    $null = $script:ReportFindings.Add([ordered]@{
        category      = $Category
        severity      = 'HIGH'
        detail        = $Detail
        timestamp_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    })
    Write-Host "  - [$Category] $Detail" -ForegroundColor Red
}

function Test-FileContains ([string]$FilePath, [string]$Pattern) {
    if (-not (Test-Path $FilePath)) { return $false }
    try {
        $content = [System.IO.File]::ReadAllText($FilePath)
        return $content.Contains($Pattern)
    } catch { return $false }
}

function Get-FileContent ([string]$FilePath) {
    try { return [System.IO.File]::ReadAllText($FilePath) } catch { return '' }
}

# -------------------------------------------------------------------------
# Check a single file for both variant signatures
# Returns count of findings
# -------------------------------------------------------------------------
function Test-FileForSignatures ([string]$FilePath, [string]$Label) {
    if (-not (Test-Path $FilePath)) { return 0 }
    $found = 0
    $content = Get-FileContent $FilePath
    if (-not $content) { return 0 }

    # Variant 1
    if ($content.Contains($V1_MARKER)) {
        Add-RepoFinding $Label 'Variant 1 payload (rmcej%otb%) detected' 'HIGH'
        $found++
    }
    if ($content.Contains($V1_DECODER)) {
        Add-RepoFinding $Label 'Variant 1 decoder (_$_1e42) detected' 'HIGH'
        $found++
    }
    if ($content.Contains($V1_GLOBAL) -and ($content.Contains($V1_SEED) -or $content.Contains($V1_SEED2))) {
        Add-RepoFinding $Label "Variant 1 markers (global['!'] + seed) detected" 'HIGH'
        $found++
    }

    # Variant 2
    if ($content.Contains($V2_MARKER)) {
        Add-RepoFinding $Label 'Variant 2 payload (Cot%3t=shtP) detected' 'HIGH'
        $found++
    }
    if ($content.Contains($V2_GLOBAL) -and ($content.Contains($V2_SEED) -or $content.Contains($V2_SEED2) -or $content.Contains($V2_DECODER))) {
        Add-RepoFinding $Label "Variant 2 markers (global['_V'] + seed/decoder) detected" 'HIGH'
        $found++
    }

    # Common cross-variant
    if ($content.Contains($COMMON_GLOBAL_R) -and $content.Contains($COMMON_GLOBAL_M)) {
        if ($content.Contains($V1_SEED) -or $content.Contains($V1_SEED2) -or
            $content.Contains($V2_SEED) -or $content.Contains($V2_SEED2)) {
            Add-RepoFinding $Label "Suspicious global['r']/global['m'] with known seed" 'MEDIUM'
            $found++
        }
    }

    # eval() with global markers
    if ($content -match 'eval\(' -and
        ($content.Contains($COMMON_GLOBAL_R) -or $content.Contains($V1_GLOBAL) -or $content.Contains($V2_GLOBAL))) {
        Add-RepoFinding $Label 'eval() with PolinRider global markers' 'MEDIUM'
        $found++
    }

    return $found
}

# -------------------------------------------------------------------------
# Scan a single git repository
# -------------------------------------------------------------------------
function Scan-Repo ([string]$RepoDir) {
    $script:TotalRepos++
    $script:CurrentRepoDir = $RepoDir
    $findingCount = 0
    Write-Verbose "Scanning repo: $RepoDir"

    # --- Config files ---
    $nestedDirs = @('','client','server','frontend','backend','web','apps','src','packages/ui','packages/dashboard')
    foreach ($cf in $CONFIG_FILES) {
        foreach ($nested in $nestedDirs) {
            $fp = if ($nested) { Join-Path $RepoDir "$nested/$cf" } else { Join-Path $RepoDir $cf }
            $findingCount += Test-FileForSignatures $fp ($fp.Replace("$RepoDir/", '').Replace("$RepoDir\", ''))
        }
    }

    # Monorepo packages/*/
    $pkgBase = Join-Path $RepoDir 'packages'
    if (Test-Path $pkgBase -PathType Container) {
        foreach ($pkgSub in (Get-ChildItem $pkgBase -Directory -ErrorAction SilentlyContinue)) {
            foreach ($cf in $CONFIG_FILES) {
                $fp = Join-Path $pkgSub.FullName $cf
                if (Test-Path $fp) {
                    $rel = $fp.Replace("$RepoDir\", '').Replace("$RepoDir/", '')
                    $findingCount += Test-FileForSignatures $fp $rel
                }
            }
        }
    }

    # --- .woff2 fake font payloads ---
    Get-ChildItem $RepoDir -Recurse -Include '*.woff2','*.woff' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notlike '*\.git\*' } |
        ForEach-Object {
            $rel = $_.FullName.Replace("$RepoDir\", '').Replace("$RepoDir/", '')
            $content = Get-FileContent $_.FullName
            if ($content) {
                $hit = $false
                if ($content.Contains($V1_MARKER)) {
                    Add-RepoFinding $rel 'Fake font with variant 1 payload' 'HIGH'; $hit = $true
                }
                if ($content.Contains($V2_MARKER)) {
                    Add-RepoFinding $rel 'Fake font with variant 2 payload' 'HIGH'; $hit = $true
                }
                if (-not $hit) {
                    if ($content.Contains($V1_DECODER) -and $content.Contains($V1_GLOBAL)) {
                        Add-RepoFinding $rel 'Fake font with variant 1 markers' 'HIGH'; $hit = $true
                    }
                    if ($content.Contains($COMMON_GLOBAL_R) -and $content.Contains($COMMON_GLOBAL_M)) {
                        Add-RepoFinding $rel 'Fake font with PolinRider global markers' 'HIGH'; $hit = $true
                    }
                }
                if ($hit) { $findingCount++ }
            }
        }

    # --- Deep JS scan (--JsAll) ---
    if ($JsAll) {
        Get-ChildItem $RepoDir -Recurse -Include '*.js','*.mjs','*.cjs','*.ts' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notlike '*node_modules*' -and $_.FullName -notlike '*\.git\*' } |
            ForEach-Object {
                $rel = $_.FullName.Replace("$RepoDir\", '').Replace("$RepoDir/", '')
                $findingCount += Test-FileForSignatures $_.FullName $rel
            }
    }

    # --- Propagation scripts: temp_auto_push.bat / config.bat ---
    $batFile = Join-Path $RepoDir 'temp_auto_push.bat'
    if (Test-Path $batFile) {
        $content = Get-FileContent $batFile
        if ($content -and ($content.Contains('LAST_COMMIT_DATE') -or $content.Contains('--no-verify') -or $content.Contains('git push -uf'))) {
            Add-RepoFinding 'temp_auto_push.bat' 'PolinRider propagation script (confirmed)' 'HIGH'
            $null = $script:CleanupBatFiles.Add($batFile)
        } else {
            Add-RepoFinding 'temp_auto_push.bat' 'Propagation script found (verify manually)' 'MEDIUM'
        }
        $findingCount++
    }

    $cfgBat = Join-Path $RepoDir 'config.bat'
    if (Test-Path $cfgBat) {
        $content = Get-FileContent $cfgBat
        if ($content -and ($content.Contains('LAST_COMMIT_DATE') -or $content.Contains('--no-verify') -or
            $content.Contains('git push -uf') -or $content.Contains('temp_auto_push'))) {
            Add-RepoFinding 'config.bat' 'PolinRider hidden orchestrator (confirmed)' 'HIGH'
            $null = $script:CleanupBatFiles.Add($cfgBat)
        } else {
            Add-RepoFinding 'config.bat' 'Hidden orchestrator found (verify manually)' 'MEDIUM'
        }
        $findingCount++
    }

    # --- .gitignore injection ---
    $gitignore = Join-Path $RepoDir '.gitignore'
    if (Test-Path $gitignore) {
        $lines = Get-Content $gitignore -ErrorAction SilentlyContinue
        $giHit = $false
        if ($lines -contains 'config.bat') {
            Add-RepoFinding '.gitignore' 'config.bat entry injected' 'HIGH'
            $findingCount++
            $giHit = $true
        }
        if ($lines -contains 'temp_auto_push.bat') {
            Add-RepoFinding '.gitignore' 'temp_auto_push.bat entry injected' 'HIGH'
            $findingCount++
            $giHit = $true
        }
        if ($giHit -and -not $script:CleanupGitignoreRepos.Contains($RepoDir)) {
            $null = $script:CleanupGitignoreRepos.Add($RepoDir)
        }
    }

    # --- child_process.spawn in config files ---
    foreach ($cf in $CONFIG_FILES) {
        $fp = Join-Path $RepoDir $cf
        if (Test-Path $fp) {
            $content = Get-FileContent $fp
            if ($content -and $content.Contains('child_process') -and
                ($content.Contains('detached') -or $content.Contains('windowsHide'))) {
                Add-RepoFinding $cf 'child_process.spawn with detached/hidden execution' 'HIGH'
                $findingCount++
            }
        }
    }

    # --- IDE config directories (.vscode, .cursor, .claude) ---
    foreach ($ideName in $IDE_CONFIG_DIRS) {
        $ideDir = Join-Path $RepoDir $ideName
        if (-not (Test-Path $ideDir -PathType Container)) { continue }

        $ideFiles = @(Get-ChildItem $ideDir -Recurse -File -Depth 3 -ErrorAction SilentlyContinue)
        if ($ideFiles.Count -ge 200) {
            Write-Verbose "WARNING: $ideName has $($ideFiles.Count) files -- scanning all but large dirs may slow the scan"
        }
        $ideFiles |
            ForEach-Object {
                $rel = $_.FullName.Replace("$RepoDir\", '').Replace("$RepoDir/", '')
                $content = Get-FileContent $_.FullName
                if (-not $content) { return }

                $findingCount += Test-FileForSignatures $_.FullName $rel

                # StakingGame UUID
                if ($content.Contains($STAKING_UUID)) {
                    Add-RepoFinding $rel 'StakingGame weaponized template UUID found' 'HIGH'
                    $findingCount++
                }

                # C2 domains
                foreach ($domain in $C2_DOMAINS) {
                    if ($content.Contains($domain)) {
                        Add-RepoFinding $rel "C2 domain reference ($domain)" 'HIGH'
                        $findingCount++
                    }
                }

                # Blockchain C2 addresses
                foreach ($addr in @($TRON_ADDR_1, $TRON_ADDR_2, $APTOS_HASH_1, $APTOS_HASH_2)) {
                    if ($content.Contains($addr)) {
                        Add-RepoFinding $rel "Blockchain C2 address ($addr)" 'HIGH'
                        $findingCount++
                    }
                }

                # curl|bash auto-execution
                if ($content -match '(curl|wget).*\|.*(bash|sh|powershell|cmd)') {
                    if ($content.Contains('folderOpen')) {
                        Add-RepoFinding $rel 'curl|bash with runOn:folderOpen auto-execution' 'HIGH'
                    } else {
                        Add-RepoFinding $rel 'curl|bash command in IDE config' 'MEDIUM'
                    }
                    $findingCount++
                }

                # TasksJacker URL-shape pattern: vercel.app/settings/(mac|linux|win)?flag=N
                if ($content -match 'vercel\.app/settings/(mac|linux|win)\?flag=') {
                    Add-RepoFinding $rel 'TasksJacker C2 URL pattern (vercel.app/settings/...)' 'HIGH'
                    $findingCount++
                }

                # node -e with suspicious payload
                if ($content -match 'node\s+-e' -and
                    ($content.Contains('global[') -or $content.Contains('child_process') -or $content.Contains('eval('))) {
                    Add-RepoFinding $rel 'node -e with suspicious payload in IDE config' 'HIGH'
                    $findingCount++
                }

                # Prompt injection (.claude / .cursor only)
                if ($ideName -eq '.claude' -or $ideName -eq '.cursor') {
                    if ($content -match '(ignore previous|ignore above|disregard|forget all|new instructions|you are now|act as|pretend)') {
                        Add-RepoFinding $rel 'Prompt injection pattern detected' 'HIGH'
                        $findingCount++
                    }
                    if ($content -match '(curl|wget|fetch|https?)://') {
                        Add-RepoFinding $rel 'External URL in agent config' 'MEDIUM'
                        $findingCount++
                    }
                }
            }
    }

    # --- Malicious npm packages in package.json ---
    Get-ChildItem $RepoDir -Recurse -Filter 'package.json' -File -Depth 4 -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notlike '*node_modules*' -and $_.FullName -notlike '*\.git\*' } |
        ForEach-Object {
            $rel = $_.FullName.Replace("$RepoDir\", '').Replace("$RepoDir/", '')
            $content = Get-FileContent $_.FullName

            foreach ($pkg in $MALICIOUS_NPM_PKGS) {
                if ($content.Contains("`"$pkg`"")) {
                    Add-RepoFinding $rel "Malicious npm dependency '$pkg'" 'HIGH'
                    $findingCount++
                }
            }

            # Suspicious tailwind packages
            $twMatches = [regex]::Matches($content, $TAILWIND_PKG_REGEX)
            foreach ($m in $twMatches) {
                $twPkg = $m.Groups[1].Value
                if ($twPkg -notin $TAILWIND_ALLOWLIST -and $twPkg -notlike '@tailwindcss/*') {
                    Add-RepoFinding $rel "Suspicious tailwind package '$twPkg'" 'MEDIUM'
                    $findingCount++
                }
            }
        }

    # --- ShoeVista template detection ---
    $clientPkg = Join-Path $RepoDir 'client\package.json'
    if ((Test-Path $clientPkg) -and (Test-FileContains $clientPkg 'tailwindcss-style-animate')) {
        Add-RepoFinding 'client/package.json' 'ShoeVista weaponized template (tailwindcss-style-animate)' 'HIGH'
        $findingCount++
    }

    # ShoeVista name variants in root package.json
    $rootPkg = Join-Path $RepoDir 'package.json'
    if (Test-Path $rootPkg) {
        $rootContent = Get-FileContent $rootPkg
        if ($rootContent -and $rootContent.Contains('"name"')) {
            foreach ($svName in $SHOEVISTA_NAMES) {
                if ($rootContent.Contains($svName)) {
                    $hasClientServer = (Test-Path (Join-Path $RepoDir 'client')) -and (Test-Path (Join-Path $RepoDir 'server'))
                    $hasMalDep = $rootContent.Contains('tailwindcss-style-animate')
                    if ($hasMalDep -or $hasClientServer) {
                        Add-RepoFinding 'package.json' "Possible ShoeVista weaponized template (name '$svName')" 'MEDIUM'
                        $findingCount++
                        break
                    }
                }
            }
        }
    }

    # --- node_modules installed package scan ---
    # Finds malicious packages actually installed on disk --catches transitive deps,
    # packages removed from package.json but still present, and monorepo layouts.
    foreach ($pkg in $MALICIOUS_NPM_PKGS) {
        $nmPkgFiles = Get-ChildItem $RepoDir -Recurse -Filter 'package.json' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.DirectoryName -match "(\\|/)node_modules(\\|/)$([regex]::Escape($pkg))$" }
        foreach ($nmPkg in $nmPkgFiles) {
            $nmDir = $nmPkg.DirectoryName
            $rel = $nmPkg.FullName.Replace("$RepoDir\", '').Replace("$RepoDir/", '')
            $payloadNote = ''
            $payloadFound = $false
            Get-ChildItem $nmDir -Recurse -Filter '*.js' -File -Depth 2 -ErrorAction SilentlyContinue |
                ForEach-Object {
                    if (-not $payloadFound) {
                        $jsContent = Get-FileContent $_.FullName
                        if ($jsContent) {
                            if ($jsContent.Contains($V1_MARKER)) {
                                $payloadNote = ' (payload confirmed --V1)'
                                $payloadFound = $true
                            } elseif ($jsContent.Contains($V2_MARKER)) {
                                $payloadNote = ' (payload confirmed --V2)'
                                $payloadFound = $true
                            }
                        }
                    }
                }
            Add-RepoFinding $rel "Malicious package installed: $pkg$payloadNote" 'HIGH'
            $findingCount++
            $nmParent = Split-Path $nmDir -Parent
            if (-not $script:CleanupNodeModules.Contains($nmParent)) {
                $null = $script:CleanupNodeModules.Add($nmParent)
            }
        }
    }

    # --- git grep across all branches (15s timeout) ---
    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if ($gitCmd -and (Test-Path (Join-Path $RepoDir '.git'))) {
        $gitPatterns = @($V1_MARKER, $V2_MARKER, $V1_DECODER, $V2_GLOBAL)
        foreach ($pattern in $gitPatterns) {
            try {
                $job = Start-Job -ScriptBlock {
                    param($repo, $pat)
                    Set-Location $repo
                    git grep -l $pat --all 2>$null
                } -ArgumentList $RepoDir, $pattern
                $result = $job | Wait-Job -Timeout 15 | Receive-Job 2>$null
                Remove-Job $job -Force -ErrorAction SilentlyContinue
                if ($result) {
                    foreach ($hit in $result) {
                        Add-RepoFinding "git grep" "Marker '$pattern' found in branch history: $hit" 'HIGH'
                        $findingCount++
                    }
                }
            } catch {}
        }
    }

    # --- Report for this repo ---
    if ($findingCount -gt 0) {
        Write-Host ''
        Write-Host "[INFECTED] $RepoDir" -ForegroundColor Red
        $script:InfectedRepos++
    } else {
        Write-Verbose "Clean: $RepoDir"
    }
    $script:CurrentRepoDir = ''
    return $findingCount
}

# =========================================================================
#  FULL-SYSTEM SCAN FUNCTIONS (Windows)
# =========================================================================

# -------------------------------------------------------------------------
# 1. Processes
# -------------------------------------------------------------------------
function Scan-Processes {
    Write-Section 'PROCESSES' 'Scanning running processes for suspicious activity...'

    $allProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Select-Object ProcessId, Name, CommandLine

    foreach ($proc in $allProcs) {
        $cmd = $proc.CommandLine
        if (-not $cmd) { continue }

        # node -e with PolinRider markers
        if ($cmd -match 'node\s+-e' -and
            ($cmd.Contains('global[') -or $cmd.Contains($V1_MARKER) -or $cmd.Contains($V2_MARKER) -or
             $cmd.Contains($V1_DECODER) -or $cmd.Contains($V2_GLOBAL) -or
             $cmd -match 'eval\(' -or $cmd.Contains('child_process'))) {
            Add-SystemFinding 'PROCESS' "Suspicious node -e process (PID $($proc.ProcessId)): likely PolinRider payload"
        }

        # Stage 4 Python credential stealer patterns
        if ($proc.Name -eq 'python.exe' -or $proc.Name -eq 'python3.exe' -or $proc.Name -eq 'pythonw.exe') {
            if ($cmd -match 'portalocker|tmp7A863DD1|_credentials|_sysenv|login_credentials|login_sysenv' -or
                $cmd -match 'taskkill.*chrome|taskkill.*firefox|taskkill.*msedge|taskkill.*brave' -or
                $cmd -match 'wmic\s+useraccount.*sid') {
                Add-SystemFinding 'PROCESS' "Suspicious Python stealer process (PID $($proc.ProcessId)): $($cmd.Substring(0, [math]::Min(120, $cmd.Length)))"
            }
        }

        # taskkill targeting browsers (stealer anti-forensics)
        if ($proc.Name -eq 'taskkill.exe' -and
            $cmd -match '(chrome|firefox|msedge|opera|brave|1password|bitwarden|dashlane|nordpass)\.exe') {
            Add-SystemFinding 'PROCESS' "Browser/credential process being killed (PID $($proc.ProcessId)): possible stealer activity"
        }

        # C2 / blockchain references in command line
        foreach ($domain in ($C2_DOMAINS + $BLOCKCHAIN_HOSTS)) {
            if ($cmd.Contains($domain)) {
                Add-SystemFinding 'PROCESS' "Process referencing C2 endpoint: $domain (PID $($proc.ProcessId))"
            }
        }
        foreach ($addr in @($TRON_ADDR_1, $TRON_ADDR_2, $APTOS_HASH_1, $APTOS_HASH_2)) {
            if ($cmd.Contains($addr)) {
                Add-SystemFinding 'PROCESS' "Process referencing blockchain C2: $addr (PID $($proc.ProcessId))"
            }
        }
    }
}

# -------------------------------------------------------------------------
# 2. Network connections
# -------------------------------------------------------------------------
function Scan-Network {
    Write-Section 'NETWORK' 'Checking active network connections to known C2 infrastructure...'

    # Resolve C2 domains to IPs so we can match against netstat/Get-NetTCPConnection output
    $c2IPs = @{}
    foreach ($domain in ($C2_DOMAINS + $BLOCKCHAIN_HOSTS)) {
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses($domain) | ForEach-Object { $_.IPAddressToString }
            foreach ($ip in $resolved) { $c2IPs[$ip] = $domain }
        } catch {
            Write-Verbose "Could not resolve $domain"
        }
    }
    $c2IPs[$STEALER_C2_IP] = 'credential-stealer-C2'

    # Try Get-NetTCPConnection (PowerShell 5.1+ on Windows 8+), fall back to netstat
    $tcpConns = $null
    try { $tcpConns = Get-NetTCPConnection -State Established -ErrorAction Stop } catch {}

    if ($tcpConns) {
        foreach ($conn in $tcpConns) {
            $remoteIP = $conn.RemoteAddress
            if ($c2IPs.ContainsKey($remoteIP)) {
                $label = $c2IPs[$remoteIP]
                Add-SystemFinding 'NETWORK' "Active connection to $label ($remoteIP) -- local port $($conn.LocalPort), PID $($conn.OwningProcess)"
            }
        }
    } else {
        $netOutput = netstat -ano 2>$null | Out-String
        if ($netOutput) {
            foreach ($ip in $c2IPs.Keys) {
                if ($netOutput.Contains($ip)) {
                    Add-SystemFinding 'NETWORK' "Active connection to $($c2IPs[$ip]) ($ip)"
                }
            }
        }
    }

    # DNS cache check
    $dnsCache = ipconfig /displaydns 2>$null | Out-String
    if ($dnsCache) {
        foreach ($domain in $C2_DOMAINS) {
            if ($dnsCache.Contains($domain)) {
                $null = $script:DnsC2Hits.Add($domain)
                Add-SystemFinding 'DNS-C2' "DNS cache entry for C2 domain: $domain"
            }
        }
        foreach ($domain in $BLOCKCHAIN_HOSTS) {
            if ($dnsCache.Contains($domain)) {
                $null = $script:DnsBlockchain.Add($domain)
                Add-SystemFinding 'DNS-BLOCKCHAIN' "DNS cache entry for blockchain C2: $domain (crypto wallet drainer)"
            }
        }
        if ($dnsCache.Contains('api.telegram.org')) {
            $null = $script:DnsExfil.Add('api.telegram.org')
            Add-SystemFinding 'DNS-EXFIL' 'DNS cache entry for Telegram API (data exfiltration channel)'
        }

        # Summary risk assessment when multiple DNS categories are hit
        $dnsCategories = 0
        if ($script:DnsC2Hits.Count -gt 0)     { $dnsCategories++ }
        if ($script:DnsBlockchain.Count -gt 0)  { $dnsCategories++ }
        if ($script:DnsExfil.Count -gt 0)       { $dnsCategories++ }

        if ($dnsCategories -ge 2) {
            Add-SystemFinding 'DNS-RISK' "HIGH RISK: DNS cache contains entries across $dnsCategories C2 categories -- indicates full attack chain execution"
        }
        if ($script:DnsBlockchain.Count -ge 3) {
            Add-SystemFinding 'DNS-RISK' 'CRITICAL: Multiple blockchain endpoints resolved -- Stage 4 crypto wallet drainer likely executed'
        }
    }
}

# -------------------------------------------------------------------------
# 3. Scheduled tasks
# -------------------------------------------------------------------------
function Test-ScheduledTaskAction ([string]$TaskName, [string]$ActionStr) {
    if (-not $ActionStr) { return }
    if ($ActionStr -match 'node\s+-e') {
        Add-SystemFinding 'SCHED-TASK' "Scheduled task executing node -e: $TaskName"
    }
    if ($ActionStr -match 'python(\.exe)?\s' -and
        ($ActionStr -match 'portalocker|tmp7A863DD1|credentials|sysenv|taskkill')) {
        Add-SystemFinding 'SCHED-TASK' "Scheduled task with stealer-like python execution: $TaskName"
    }
    if ($ActionStr -match '(curl|wget|Invoke-WebRequest|iwr|irm).*\|') {
        Add-SystemFinding 'SCHED-TASK' "Scheduled task with download-and-execute pattern: $TaskName"
    }
    if ($ActionStr -match 'vercel\.app/settings/(mac|linux|win)\?flag=') {
        Add-SystemFinding 'SCHED-TASK' "Scheduled task with TasksJacker URL pattern: $TaskName"
    }
    foreach ($domain in $C2_DOMAINS) {
        if ($ActionStr.Contains($domain)) {
            Add-SystemFinding 'SCHED-TASK' "Scheduled task referencing C2 domain: $TaskName ($domain)"
        }
    }
}

function Scan-ScheduledTasks {
    Write-Section 'SCHED-TASKS' 'Checking scheduled tasks for suspicious entries...'

    # Prefer Get-ScheduledTask (locale-independent), fall back to schtasks CSV
    $usedCmdlet = $false
    try {
        $scheduledTasks = Get-ScheduledTask -ErrorAction Stop
        $usedCmdlet = $true
        foreach ($st in $scheduledTasks) {
            $taskPath = "$($st.TaskPath)$($st.TaskName)"
            $actions = $st.Actions
            foreach ($act in $actions) {
                $actionStr = "$($act.Execute) $($act.Arguments)"
                Test-ScheduledTaskAction $taskPath $actionStr
            }
        }
    } catch {
        Write-Verbose 'Get-ScheduledTask not available, falling back to schtasks'
    }

    if (-not $usedCmdlet) {
        $csvLines = schtasks /query /fo CSV /v 2>$null
        if ($csvLines) {
            $tasks = $csvLines | ConvertFrom-Csv -ErrorAction SilentlyContinue
            foreach ($task in $tasks) {
                # Try known column names across locales
                $action = $null
                foreach ($col in @('Task To Run', 'TaskToRun', 'Aufgabe')) {
                    if ($task.PSObject.Properties[$col]) { $action = $task.$col; break }
                }
                if (-not $action) {
                    # Last resort: scan all property values
                    foreach ($prop in $task.PSObject.Properties) {
                        if ($prop.Value -match '(node|python|curl|wget|powershell)') {
                            $action = $prop.Value; break
                        }
                    }
                }
                $taskName = $task.TaskName
                if (-not $taskName) { $taskName = $task.PSObject.Properties | Select-Object -First 1 -ExpandProperty Value }
                Test-ScheduledTaskAction $taskName $action
            }
        }
    }
}

# -------------------------------------------------------------------------
# 4. Startup / Run keys
# -------------------------------------------------------------------------
function Scan-StartupRegistry {
    Write-Section 'REGISTRY' 'Checking startup registry keys...'

    $regPaths = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($regPath in $regPaths) {
        $props = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            $val = [string]$_.Value
            if ($val -match 'node\s+-e' -or $val.Contains($V1_MARKER) -or $val.Contains($V2_MARKER)) {
                Add-SystemFinding 'REGISTRY' "Suspicious startup entry '$($_.Name)' in $regPath"
            }
            foreach ($domain in $C2_DOMAINS) {
                if ($val.Contains($domain)) {
                    Add-SystemFinding 'REGISTRY' "Startup entry referencing C2: '$($_.Name)' ($domain)"
                }
            }
        }
    }
}

# -------------------------------------------------------------------------
# 4b. Windows Services
# -------------------------------------------------------------------------
function Scan-WindowsServices {
    Write-Section 'SERVICES' 'Checking Windows services for suspicious entries...'

    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.PathName -match 'python|node' }

    foreach ($svc in $services) {
        $pathName = $svc.PathName
        if (-not $pathName) { continue }

        if ($pathName -match 'node\s+-e' -or $pathName.Contains($V1_MARKER) -or $pathName.Contains($V2_MARKER)) {
            Add-SystemFinding 'SERVICE' "Suspicious service '$($svc.Name)': $pathName"
        }
        if ($pathName -match 'python' -and
            ($pathName -match 'portalocker|tmp7A863DD1|credentials|sysenv|taskkill')) {
            Add-SystemFinding 'SERVICE' "Stealer-like service '$($svc.Name)': $pathName"
        }
        foreach ($domain in $C2_DOMAINS) {
            if ($pathName.Contains($domain)) {
                Add-SystemFinding 'SERVICE' "Service referencing C2 '$($svc.Name)': $domain"
            }
        }
    }
}

# -------------------------------------------------------------------------
# 4c. PowerShell profiles
# -------------------------------------------------------------------------
function Scan-PSProfiles {
    Write-Section 'PS-PROFILES' 'Checking PowerShell profile scripts (all users)...'

    $profilePaths = @(
        $PROFILE.CurrentUserCurrentHost,
        $PROFILE.CurrentUserAllHosts,
        $PROFILE.AllUsersCurrentHost,
        $PROFILE.AllUsersAllHosts
    ) | Where-Object { $_ } | Select-Object -Unique

    # Add profile paths for all other users
    foreach ($userProfile in (Get-AllUserProfiles)) {
        $docsDir = Join-Path $userProfile 'Documents'
        $profilePaths += @(
            (Join-Path $docsDir 'PowerShell\Microsoft.PowerShell_profile.ps1'),
            (Join-Path $docsDir 'PowerShell\profile.ps1'),
            (Join-Path $docsDir 'WindowsPowerShell\Microsoft.PowerShell_profile.ps1'),
            (Join-Path $docsDir 'WindowsPowerShell\profile.ps1')
        )
    }
    $profilePaths = $profilePaths | Where-Object { $_ } | Select-Object -Unique

    foreach ($pp in $profilePaths) {
        if (-not (Test-Path $pp)) { continue }
        $content = Get-FileContent $pp
        if (-not $content) { continue }

        if ($content.Contains($V1_MARKER) -or $content.Contains($V2_MARKER) -or
            $content.Contains($V1_DECODER) -or $content.Contains($V2_GLOBAL)) {
            Add-SystemFinding 'PS-PROFILE' "PolinRider signature in PowerShell profile: $pp"
        }
        if ($content -match 'node\s+-e' -and
            ($content.Contains('global[') -or $content.Contains('child_process') -or $content.Contains('eval('))) {
            Add-SystemFinding 'PS-PROFILE' "Suspicious node -e in PowerShell profile: $pp"
        }
        foreach ($domain in ($C2_DOMAINS + $BLOCKCHAIN_HOSTS)) {
            if ($content.Contains($domain)) {
                Add-SystemFinding 'PS-PROFILE' "C2 domain in PowerShell profile: $pp ($domain)"
            }
        }
        foreach ($addr in @($TRON_ADDR_1, $TRON_ADDR_2, $APTOS_HASH_1, $APTOS_HASH_2)) {
            if ($content.Contains($addr)) {
                Add-SystemFinding 'PS-PROFILE' "Blockchain C2 address in PowerShell profile: $pp"
            }
        }
    }
}

# -------------------------------------------------------------------------
# 5. Stage 4 credential stealer artifacts
# -------------------------------------------------------------------------
function Scan-StealerArtifacts {
    Write-Section 'STEALER' 'Scanning for Stage 4 credential stealer artifacts (all users)...'

    foreach ($userProfile in (Get-AllUserProfiles)) {
        $userName = Split-Path $userProfile -Leaf
        Write-Verbose "Checking stealer artifacts for user: $userName"

        # Lock file
        $localAppData = Join-Path $userProfile 'AppData\Local'
        $lockFile = Join-Path $localAppData "Temp\$STEALER_LOCK_FILE"
        if (Test-Path $lockFile) {
            Add-SystemFinding 'STEALER' "Active stealer lock file found ($userName): $lockFile"
        }

        # .npm exfiltration staging directory
        $npmDir = Join-Path $userProfile '.npm'
        if (Test-Path $npmDir) {
            $credFiles = Get-ChildItem $npmDir -Recurse -Include '_credentials.json','login_credentials.json','_sysenv.json','login_sysenv.json','_sysenv.env','_info.json' -Force -ErrorAction SilentlyContinue
            foreach ($cf in $credFiles) {
                Add-SystemFinding 'STEALER' "Credential dump file ($userName): $($cf.FullName)"
            }

            $archives = Get-ChildItem $npmDir -Recurse -Filter '*#*.zip' -Force -ErrorAction SilentlyContinue
            foreach ($ar in $archives) {
                Add-SystemFinding 'STEALER' "Exfiltration archive ($userName): $($ar.FullName)"
            }

            $stealerFiles = Get-ChildItem $npmDir -Recurse -File -Force -Depth 4 -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -lt 1MB }
            foreach ($sf in $stealerFiles) {
                $sfContent = Get-FileContent $sf.FullName
                if (-not $sfContent) { continue }
                if ($sfContent.Contains($XOR_KEY_1) -or $sfContent.Contains($XOR_KEY_2)) {
                    Add-SystemFinding 'STEALER' "XOR decryption key found ($userName): $($sf.FullName)"
                }
            }

            $stealerDirs = Get-ChildItem $npmDir -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^\w+\$\w+_\d{6}_\d{6}$' }
            foreach ($sd in $stealerDirs) {
                $subDirs = Get-ChildItem $sd.FullName -Directory -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
                if ($subDirs -contains 'login' -or $subDirs -contains 'ext' -or $subDirs -contains 'login-db') {
                    Add-SystemFinding 'STEALER' "Credential stealer staging directory ($userName): $($sd.FullName)"
                }
            }
        }
    }

    $stealerCount = @($script:Findings | Where-Object { $_ -match '^\[STEALER\]' }).Count
    if ($stealerCount -gt 0) {
        $script:StealerArtifactsFound = $true
    }
}

# -------------------------------------------------------------------------
# 6. VS Code / Cursor extensions
# -------------------------------------------------------------------------
function Scan-VSCodeExtensions {
    Write-Section 'VSCODE' 'Scanning VS Code / Cursor extensions (all users)...'

    foreach ($userProfile in (Get-AllUserProfiles)) {
        $userName = Split-Path $userProfile -Leaf
        Write-Verbose "Checking VS Code/Cursor extensions for user: $userName"

        $extDirs = @(
            (Join-Path $userProfile '.vscode\extensions'),
            (Join-Path $userProfile '.cursor\extensions'),
            (Join-Path $userProfile '.vscode-insiders\extensions')
        )

        foreach ($extDir in $extDirs) {
            if (-not (Test-Path $extDir)) { continue }
            Write-Verbose "Scanning extensions in $extDir"

            $extFiles = @(Get-ChildItem $extDir -Recurse -Include '*.js','*.mjs' -File -Depth 4 -ErrorAction SilentlyContinue)
            if ($extFiles.Count -ge 2000) {
                Write-Verbose "WARNING: $extDir has $($extFiles.Count) JS files -- scanning all"
            }
            $extFiles | ForEach-Object {
                    $content = Get-FileContent $_.FullName
                    if ($content -and ($content.Contains($V1_MARKER) -or $content.Contains($V2_MARKER) -or
                        $content.Contains($V1_DECODER) -or $content.Contains($V2_GLOBAL))) {
                        Add-SystemFinding 'VSCODE-EXT' "Infected extension file ($userName): $($_.FullName)"
                    }
                }

            Get-ChildItem $extDir -Recurse -Filter 'package.json' -File -Depth 3 -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $content = Get-FileContent $_.FullName
                    foreach ($pkg in $MALICIOUS_NPM_PKGS) {
                        if ($content.Contains("`"$pkg`"")) {
                            Add-SystemFinding 'VSCODE-EXT' "Extension depends on malicious package '$pkg' ($userName): $($_.FullName)"
                        }
                    }
                }
        }

        # Agent config directories at user level (.claude, .cursor settings outside repos)
        $agentConfigDirs = @(
            (Join-Path $userProfile '.claude'),
            (Join-Path $userProfile '.cursor')
        )
        foreach ($agentDir in $agentConfigDirs) {
            if (-not (Test-Path $agentDir -PathType Container)) { continue }
            Write-Verbose "Scanning agent config: $agentDir"

            Get-ChildItem $agentDir -Recurse -File -Depth 3 -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $content = Get-FileContent $_.FullName
                    if (-not $content) { return }

                    if ($content.Contains($V1_MARKER) -or $content.Contains($V2_MARKER) -or
                        $content.Contains($V1_DECODER) -or $content.Contains($V2_GLOBAL)) {
                        Add-SystemFinding 'AGENT-CONFIG' "PolinRider signature ($userName): $($_.FullName)"
                    }
                    foreach ($domain in $C2_DOMAINS) {
                        if ($content.Contains($domain)) {
                            Add-SystemFinding 'AGENT-CONFIG' "C2 domain in agent config ($userName): $($_.FullName) ($domain)"
                        }
                    }
                    if ($content -match '(ignore previous|ignore above|disregard|forget all|new instructions|you are now|act as|pretend)') {
                        Add-SystemFinding 'AGENT-CONFIG' "Prompt injection pattern ($userName): $($_.FullName)"
                    }
                    if ($content -match '(curl|wget|Invoke-WebRequest|iwr|irm).*\|') {
                        Add-SystemFinding 'AGENT-CONFIG' "Download-and-execute pattern ($userName): $($_.FullName)"
                    }
                }
        }

        # Workspace tasks.json in VS Code storage
        $appDataRoaming = Join-Path $userProfile 'AppData\Roaming'
        $vsStorage = Join-Path $appDataRoaming 'Code\User\workspaceStorage'
        if (Test-Path $vsStorage) {
            Get-ChildItem $vsStorage -Recurse -Filter 'tasks.json' -File -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $content = Get-FileContent $_.FullName
                    if ($content.Contains($STAKING_UUID)) {
                        Add-SystemFinding 'VSCODE-TASKS' "StakingGame UUID in workspace tasks ($userName): $($_.FullName)"
                    }
                    foreach ($domain in $C2_DOMAINS) {
                        if ($content.Contains($domain)) {
                            Add-SystemFinding 'VSCODE-TASKS' "C2 domain in workspace tasks ($userName): $($_.FullName) ($domain)"
                        }
                    }
                }
        }
    }
}

# -------------------------------------------------------------------------
# 7. npm global packages
# -------------------------------------------------------------------------
function Scan-NpmGlobal {
    Write-Section 'NPM' 'Checking global npm packages...'

    $npmCmd = Get-Command npm -ErrorAction SilentlyContinue
    if (-not $npmCmd) {
        Write-Verbose 'npm not found, skipping'
        return
    }

    $npmList = npm list -g --depth=0 2>$null | Out-String
    if ($npmList) {
        foreach ($pkg in $MALICIOUS_NPM_PKGS) {
            if ($npmList.Contains($pkg)) {
                Add-SystemFinding 'NPM-GLOBAL' "Malicious global npm package installed: $pkg"
            }
        }

        $twMatches = [regex]::Matches($npmList, $TAILWIND_LIST_REGEX)
        foreach ($m in $twMatches) {
            $twPkg = $m.Groups[1].Value
            if ($twPkg -notin $TAILWIND_ALLOWLIST -and $twPkg -notlike '@tailwindcss/*') {
                Add-SystemFinding 'NPM-TAILWIND' "Global package contains 'tailwind' - review: $twPkg"
            }
        }
    }

    $npmRoot = npm root -g 2>$null
    if ($npmRoot -and (Test-Path $npmRoot)) {
        Get-ChildItem $npmRoot -Recurse -Filter 'package.json' -File -Depth 2 -ErrorAction SilentlyContinue |
            ForEach-Object {
                $content = Get-FileContent $_.FullName
                if ($content -match '"postinstall".*:\s*"(curl|wget|node -e|Invoke-WebRequest)') {
                    Add-SystemFinding 'NPM-GLOBAL' "Suspicious postinstall script: $($_.FullName)"
                }
                if ($content.Contains($V1_MARKER) -or $content.Contains($V2_MARKER)) {
                    Add-SystemFinding 'NPM-GLOBAL' "PolinRider signature in global package: $($_.FullName)"
                }
            }
    }
}

# -------------------------------------------------------------------------
# 8. Temp directories
# -------------------------------------------------------------------------
function Scan-TempDirs {
    Write-Section 'TEMP' 'Scanning temp directories for artifacts (all users)...'

    $tempDirs = @("$env:SystemRoot\Temp")
    foreach ($userProfile in (Get-AllUserProfiles)) {
        $userTemp = Join-Path $userProfile 'AppData\Local\Temp'
        if (Test-Path $userTemp) { $tempDirs += $userTemp }
    }
    $tempDirs = $tempDirs | Select-Object -Unique | Where-Object { Test-Path $_ }

    foreach ($tmpDir in $tempDirs) {
        Write-Verbose "Scanning $tmpDir"

        $tmpFiles = @(Get-ChildItem $tmpDir -Recurse -Include '*.js','*.bat','*.sh','*.mjs','*.ps1' -File -Depth 3 -ErrorAction SilentlyContinue)
        if ($tmpFiles.Count -ge 500) {
            Write-Verbose "WARNING: $tmpDir has $($tmpFiles.Count) script files -- scanning all"
        }
        $tmpFiles | ForEach-Object {
                if ($ScannerScriptPath -and $_.FullName -eq $ScannerScriptPath) { return }

                $content = Get-FileContent $_.FullName
                if (-not $content) { return }

                if ($content.Contains($V1_MARKER) -or $content.Contains($V2_MARKER) -or
                    $content.Contains($V1_DECODER) -or $content.Contains($V2_GLOBAL)) {
                    Add-SystemFinding 'TEMP' "PolinRider artifact in temp: $($_.FullName)"
                }

                if ($content.Contains($XOR_KEY_1) -or $content.Contains($XOR_KEY_2)) {
                    Add-SystemFinding 'TEMP' "XOR decryption key in temp file: $($_.FullName)"
                }

                foreach ($domain in $C2_DOMAINS) {
                    if ($content.Contains($domain)) {
                        Add-SystemFinding 'TEMP' "C2 domain in temp file: $($_.FullName) ($domain)"
                    }
                }
            }

        $propagation = Join-Path $tmpDir 'temp_auto_push.bat'
        if (Test-Path $propagation) {
            Add-SystemFinding 'TEMP' "Propagation script in temp: $propagation"
        }
    }
}

# -------------------------------------------------------------------------
# 9. Browser extensions
# -------------------------------------------------------------------------
function Scan-BrowserExtensions {
    Write-Section 'BROWSER' 'Scanning browser extension directories (all users)...'

    foreach ($userProfile in (Get-AllUserProfiles)) {
        $userName = Split-Path $userProfile -Leaf
        $localAppData = Join-Path $userProfile 'AppData\Local'
        $appDataRoaming = Join-Path $userProfile 'AppData\Roaming'

        $browserExtDirs = @(
            (Join-Path $localAppData 'Google\Chrome\User Data\Default\Extensions'),
            (Join-Path $localAppData 'BraveSoftware\Brave-Browser\User Data\Default\Extensions'),
            (Join-Path $localAppData 'Microsoft\Edge\User Data\Default\Extensions'),
            (Join-Path $appDataRoaming 'Mozilla\Firefox\Profiles')
        )

        foreach ($bDir in $browserExtDirs) {
            if (-not (Test-Path $bDir)) { continue }
            Write-Verbose "Scanning $bDir ($userName)"

            $bFiles = @(Get-ChildItem $bDir -Recurse -Include '*.js' -File -Depth 5 -ErrorAction SilentlyContinue)
            if ($bFiles.Count -ge 1000) {
                Write-Verbose "WARNING: $bDir has $($bFiles.Count) JS files -- scanning all"
            }
            $bFiles | ForEach-Object {
                    $content = Get-FileContent $_.FullName
                    if (-not $content) { return }

                    if ($content.Contains($V1_MARKER) -or $content.Contains($V2_MARKER) -or
                        $content.Contains($V1_DECODER) -or $content.Contains($V2_GLOBAL)) {
                        Add-SystemFinding 'BROWSER' "Infected browser extension file ($userName): $($_.FullName)"
                    }

                    foreach ($domain in $C2_DOMAINS) {
                        if ($content.Contains($domain)) {
                            Add-SystemFinding 'BROWSER' "Browser extension references C2 ($userName): $($_.FullName) ($domain)"
                        }
                    }
                }
        }
    }
}

# =========================================================================
#  AUTOMATED DNS INVESTIGATION & RISK ASSESSMENT
# =========================================================================

# -------------------------------------------------------------------------
# Automated DNS investigation: active connections, process inspection,
# stealer artifact check, and crypto wallet exposure assessment
# -------------------------------------------------------------------------
function Scan-DnsInvestigation {
    $totalDns = $script:DnsC2Hits.Count + $script:DnsBlockchain.Count + $script:DnsExfil.Count
    if ($totalDns -eq 0) { return }

    Write-Section 'DNS-INVESTIGATE' 'Performing automated DNS investigation...'

    # --- 1. Check active connections to C2 IPs ---
    Write-Host '  [1/4] Checking active outbound connections to C2 infrastructure...' -ForegroundColor Cyan

    $c2IPs = @{}
    foreach ($domain in ($C2_DOMAINS + $BLOCKCHAIN_HOSTS)) {
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses($domain) | ForEach-Object { $_.IPAddressToString }
            foreach ($ip in $resolved) { $c2IPs[$ip] = $domain }
        } catch {}
    }
    $c2IPs[$STEALER_C2_IP] = 'credential-stealer-C2'

    $tcpConns = $null
    try { $tcpConns = Get-NetTCPConnection -State Established -ErrorAction Stop } catch {}

    $activeC2Found = $false
    if ($tcpConns) {
        foreach ($conn in $tcpConns) {
            if ($c2IPs.ContainsKey($conn.RemoteAddress)) {
                $procName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).Name
                $detail = "LIVE connection to $($c2IPs[$conn.RemoteAddress]) ($($conn.RemoteAddress):$($conn.RemotePort)) -- PID $($conn.OwningProcess) ($procName)"
                $null = $script:ActiveC2Conns.Add($detail)
                Add-SystemFinding 'DNS-ACTIVE' $detail
                $activeC2Found = $true
            }
        }
    }
    if (-not $activeC2Found) {
        Write-Host '    No active C2 connections found (payload may have already completed)' -ForegroundColor Green
    }

    # --- 2. Inspect all external connections and their processes ---
    Write-Host '  [2/4] Inspecting all external connections and owning processes...' -ForegroundColor Cyan

    $privatePattern = '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|0\.0\.0\.0|fe80)'
    $externalConns = @()
    if ($tcpConns) {
        $externalConns = @($tcpConns | Where-Object {
            $_.State -eq 'Established' -and $_.RemoteAddress -notmatch $privatePattern
        })
    }

    $suspiciousConnProcs = @{}
    foreach ($conn in $externalConns) {
        $procId = $conn.OwningProcess
        if ($suspiciousConnProcs.ContainsKey($procId)) { continue }

        try {
            $procInfo = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction Stop
        } catch { continue }

        $cmdLine = $procInfo.CommandLine
        $exePath = $procInfo.ExecutablePath
        if (-not $cmdLine) { continue }

        $isSuspicious = $false
        $reason = ''

        if ($cmdLine -match 'node\s+-e' -and ($cmdLine.Contains('global[') -or $cmdLine.Contains('eval(') -or $cmdLine.Contains('child_process'))) {
            $isSuspicious = $true; $reason = 'node -e with PolinRider payload markers'
        }
        elseif ($cmdLine -match 'python' -and ($cmdLine -match 'portalocker|tmp7A863DD1|credentials|sysenv|taskkill')) {
            $isSuspicious = $true; $reason = 'Python stealer-like command'
        }
        elseif (-not $exePath -or -not (Test-Path $exePath)) {
            $isSuspicious = $true; $reason = 'Process executable path missing or invalid'
        }
        elseif ($exePath -match '\\Temp\\|\\tmp\\|\\AppData\\Local\\Temp\\') {
            $isSuspicious = $true; $reason = 'Running from temp directory'
        }

        if ($isSuspicious) {
            $suspiciousConnProcs[$procId] = $true
            $procName = $procInfo.Name
            $truncCmd = if ($cmdLine.Length -gt 150) { $cmdLine.Substring(0, 150) + '...' } else { $cmdLine }
            $null = $script:SuspiciousProcs.Add("PID $procId ($procName): $reason -- $truncCmd")
            Add-SystemFinding 'DNS-PROC' "Suspicious connected process PID $procId ($procName): $reason"
        }
    }

    if ($script:SuspiciousProcs.Count -eq 0) {
        Write-Host "    Inspected $($externalConns.Count) external connections -- no suspicious processes found" -ForegroundColor Green
    } else {
        Write-Host "    Found $($script:SuspiciousProcs.Count) suspicious connected process(es)" -ForegroundColor Red
    }

    # --- 3. Check stealer artifacts ---
    Write-Host '  [3/4] Checking stealer artifact status...' -ForegroundColor Cyan

    # If Scan-StealerArtifacts already ran (full scan), reuse its results to avoid double-counting.
    # If it hasn't run (quick scan), do a lightweight check here.
    $stealerFindings = @($script:Findings | Where-Object { $_ -match '^\[STEALER\]' })
    $stealerModuleRan = $script:ModuleStatus.Contains('StealerArtifacts')

    if ($stealerModuleRan) {
        if ($stealerFindings.Count -gt 0) {
            $script:StealerArtifactsFound = $true
            Write-Host "    Scan-StealerArtifacts found $($stealerFindings.Count) artifact(s) (see STEALER findings above)" -ForegroundColor Red
        } else {
            Write-Host '    No stealer artifacts found (stealer may not have deployed, or cleaned up after exfiltration)' -ForegroundColor Green
        }
    } else {
        Write-Host '    Stealer module did not run -- performing quick artifact check...' -ForegroundColor Yellow
        $quickStealerHits = 0
        foreach ($userProfile in (Get-AllUserProfiles)) {
            $userName = Split-Path $userProfile -Leaf
            $localAppData = Join-Path $userProfile 'AppData\Local'
            $lockFile = Join-Path $localAppData "Temp\$STEALER_LOCK_FILE"
            if (Test-Path $lockFile) {
                Add-SystemFinding 'STEALER' "Active stealer lock file ($userName): $lockFile"
                $quickStealerHits++
            }
            $npmDir = Join-Path $userProfile '.npm'
            if (Test-Path $npmDir) {
                $credFiles = @(Get-ChildItem $npmDir -Recurse -Include '_credentials.json','login_credentials.json','_sysenv.json','login_sysenv.json' -Force -Depth 4 -ErrorAction SilentlyContinue)
                foreach ($cf in $credFiles) {
                    Add-SystemFinding 'STEALER' "Credential dump ($userName): $($cf.FullName)"
                    $quickStealerHits++
                }
                $archives = @(Get-ChildItem $npmDir -Recurse -Filter '*#*.zip' -Force -Depth 4 -ErrorAction SilentlyContinue)
                foreach ($ar in $archives) {
                    Add-SystemFinding 'STEALER' "Exfiltration archive ($userName): $($ar.FullName)"
                    $quickStealerHits++
                }
            }
        }
        if ($quickStealerHits -gt 0) {
            $script:StealerArtifactsFound = $true
            Write-Host "    Found $quickStealerHits stealer artifact(s)" -ForegroundColor Red
        } else {
            Write-Host '    No stealer artifacts found (run -FullSystem for deeper check)' -ForegroundColor Green
        }
    }

    # --- 4. Check Windows Credential Manager for exposure ---
    Write-Host '  [4/4] Checking Windows Credential Manager exposure...' -ForegroundColor Cyan

    $credCount = 0
    $cmdkeyOutput = cmdkey /list 2>$null | Out-String
    if ($cmdkeyOutput) {
        $credCount = ([regex]::Matches($cmdkeyOutput, 'Target:')).Count
    }
    if ($credCount -gt 0) {
        Write-Host "    Windows Credential Manager contains $credCount stored credential(s) -- at risk if stealer executed" -ForegroundColor Yellow
    } else {
        Write-Host '    No stored credentials in Windows Credential Manager' -ForegroundColor Green
    }
}

# -------------------------------------------------------------------------
# Risk assessment: computes an overall risk score and prints a report
# -------------------------------------------------------------------------
function Write-RiskAssessment {
    $totalDns = $script:DnsC2Hits.Count + $script:DnsBlockchain.Count + $script:DnsExfil.Count
    if ($totalDns -eq 0 -and $script:InfectedRepos -eq 0 -and $script:SystemFindings -eq 0) { return }

    Write-Host ''
    Write-Host '================================================' -ForegroundColor White
    Write-Host '  RISK ASSESSMENT' -ForegroundColor White
    Write-Host '================================================' -ForegroundColor White
    Write-Host ''

    # --- Compute risk score (0-100) ---
    $score = 0
    $factors = [System.Collections.ArrayList]::new()

    # DNS C2 domains
    if ($script:DnsC2Hits.Count -gt 0) {
        $pts = [math]::Min($script:DnsC2Hits.Count * 5, 20)
        $score += $pts
        $null = $factors.Add("  +$pts  C2 domains in DNS cache ($($script:DnsC2Hits.Count) domain(s))")
    }

    # Blockchain endpoints
    if ($script:DnsBlockchain.Count -gt 0) {
        $pts = [math]::Min($script:DnsBlockchain.Count * 8, 25)
        $score += $pts
        $null = $factors.Add("  +$pts  Blockchain drainer endpoints resolved ($($script:DnsBlockchain.Count) endpoint(s))")
    }

    # Exfiltration channels
    if ($script:DnsExfil.Count -gt 0) {
        $score += 15
        $null = $factors.Add("  +15  Data exfiltration channel (Telegram API) contacted")
    }

    # Active C2 connections
    if ($script:ActiveC2Conns.Count -gt 0) {
        $score += 25
        $null = $factors.Add("  +25  LIVE active connection(s) to C2 infrastructure")
    }

    # Suspicious processes
    if ($script:SuspiciousProcs.Count -gt 0) {
        $pts = [math]::Min($script:SuspiciousProcs.Count * 10, 20)
        $score += $pts
        $null = $factors.Add("  +$pts  Suspicious connected process(es) ($($script:SuspiciousProcs.Count) found)")
    }

    # Stealer artifacts
    if ($script:StealerArtifactsFound) {
        $score += 20
        $null = $factors.Add("  +20  Credential stealer artifacts found on disk")
    }

    # Infected repos
    if ($script:InfectedRepos -gt 0) {
        $pts = [math]::Min($script:InfectedRepos * 5, 15)
        $score += $pts
        $null = $factors.Add("  +$pts  Infected repository/repositories ($($script:InfectedRepos) repo(s))")
    }

    # Other system findings (excluding DNS-* and STEALER categories already scored above)
    $otherFindings = @($script:Findings | Where-Object {
        $_ -notmatch '^\[(DNS-|STEALER)'
    }).Count
    if ($otherFindings -gt 0) {
        $pts = [math]::Min($otherFindings * 3, 15)
        $score += $pts
        $null = $factors.Add("  +$pts  Other system findings ($otherFindings finding(s))")
    }

    $score = [math]::Min($score, 100)
    $script:RiskScore = $score

    # --- Risk level ---
    $level = 'LOW'
    if ($score -ge 70) {
        $level = 'CRITICAL'
        $color = 'Red'
        $bar = '[##########]'
    } elseif ($score -ge 50) {
        $level = 'HIGH'
        $color = 'Red'
        $filled = [math]::Floor($score / 10)
        $bar = '[' + ('#' * $filled) + ('-' * (10 - $filled)) + ']'
    } elseif ($score -ge 30) {
        $level = 'MEDIUM'
        $color = 'Yellow'
        $filled = [math]::Floor($score / 10)
        $bar = '[' + ('#' * $filled) + ('-' * (10 - $filled)) + ']'
    } else {
        $level = 'LOW'
        $color = 'Green'
        $filled = [math]::Floor($score / 10)
        $bar = '[' + ('#' * $filled) + ('-' * (10 - $filled)) + ']'
    }

    $script:RiskLevel = $level
    Write-Host "  Risk Level:  $level ($score/100)  $bar" -ForegroundColor $color
    Write-Host ''
    Write-Host '  Scoring factors:' -ForegroundColor White
    foreach ($f in $factors) { Write-Host $f -ForegroundColor $color }
    Write-Host ''

    # --- Impact assessment ---
    Write-Host '  Impact assessment:' -ForegroundColor White

    if ($script:ActiveC2Conns.Count -gt 0) {
        Write-Host '    [ACTIVE]  C2 communication is happening RIGHT NOW -- disconnect from network immediately' -ForegroundColor Red
    }

    if ($script:DnsBlockchain.Count -gt 0) {
        Write-Host '    [CRYPTO]  Crypto wallet drainer contacted -- check wallets from a clean device:' -ForegroundColor Red
        $chainsReported = @{}
        foreach ($bh in $script:DnsBlockchain) {
            switch -Wildcard ($bh) {
                '*trongrid*'   { if (-not $chainsReported['tron'])  { Write-Host '              - Tron (TRX): tronscan.org'; $chainsReported['tron'] = $true } }
                '*aptoslabs*'  { if (-not $chainsReported['aptos']) { Write-Host '              - Aptos (APT): explorer.aptoslabs.com'; $chainsReported['aptos'] = $true } }
                '*binance*'    { if (-not $chainsReported['bsc'])   { Write-Host '              - BSC (BNB): bscscan.com'; $chainsReported['bsc'] = $true } }
                '*publicnode*' { if (-not $chainsReported['bsc'])   { Write-Host '              - BSC (BNB): bscscan.com'; $chainsReported['bsc'] = $true } }
            }
        }
    }

    if ($script:DnsExfil.Count -gt 0 -or $script:StealerArtifactsFound) {
        Write-Host '    [CREDS]   Credentials likely exfiltrated -- rotate ALL passwords, tokens, API keys' -ForegroundColor Red
    }

    if ($script:DnsC2Hits.Count -gt 0 -and -not $script:StealerArtifactsFound -and $script:DnsBlockchain.Count -eq 0) {
        Write-Host '    [C2]      C2 contacted but no stealer artifacts or blockchain hits found' -ForegroundColor Yellow
        Write-Host '              Payload may have been blocked, or stealer cleaned up after itself' -ForegroundColor Yellow
    }

    if ($script:SuspiciousProcs.Count -gt 0) {
        Write-Host '    [PROCS]   Suspicious processes found with external connections:' -ForegroundColor Red
        foreach ($sp in $script:SuspiciousProcs) {
            Write-Host "              $sp" -ForegroundColor Red
        }
    }

    # --- Recommended actions based on score ---
    Write-Host ''
    Write-Host '  Recommended actions:' -ForegroundColor White

    if ($score -ge 70) {
        Write-Host '    1. DISCONNECT from the network immediately' -ForegroundColor Red
        Write-Host '    2. Check crypto wallets from a DIFFERENT clean device' -ForegroundColor Red
        Write-Host '    3. Assume ALL saved credentials are compromised' -ForegroundColor Red
        Write-Host '    4. Rotate ALL passwords, tokens, SSH keys, API keys from a clean device' -ForegroundColor Red
        Write-Host '    5. Revoke all active sessions (GitHub, cloud, email)' -ForegroundColor Red
        Write-Host '    6. Clear Windows Credential Manager: cmdkey /list' -ForegroundColor Red
        Write-Host '    7. Run full cleanup (see REMEDIATION STEPS below)' -ForegroundColor Red
        Write-Host '    8. Flush DNS cache after cleanup: ipconfig /flushdns' -ForegroundColor Red
        Write-Host '    9. Re-scan to verify cleanup and check for re-infection' -ForegroundColor Red
    } elseif ($score -ge 50) {
        Write-Host '    1. Disconnect from the network as a precaution'
        Write-Host '    2. Rotate all credentials and API keys from a clean device'
        Write-Host '    3. Check crypto wallets if applicable'
        Write-Host '    4. Run full cleanup (see REMEDIATION STEPS below)'
        Write-Host '    5. Flush DNS: ipconfig /flushdns'
        Write-Host '    6. Re-scan to verify'
    } elseif ($score -ge 30) {
        Write-Host '    1. Investigate DNS cache entries -- they may be from browsing malicious repos'
        Write-Host '    2. Rotate credentials as a precaution'
        Write-Host '    3. Clean any infected repos found'
        Write-Host '    4. Flush DNS: ipconfig /flushdns'
        Write-Host '    5. Re-scan in 24 hours'
    } else {
        Write-Host '    1. Review findings and clean any infected repos'
        Write-Host '    2. Flush DNS: ipconfig /flushdns'
        Write-Host '    3. Re-scan periodically'
    }

    Write-Host ''
}

# =========================================================================
#  REMEDIATION
# =========================================================================
function Write-ScanCoverage {
    if ($script:ModuleStatus.Count -eq 0) { return }

    $failed = @($script:ModuleStatus.GetEnumerator() | Where-Object { $_.Value.Status -ne 'OK' })
    $passed = @($script:ModuleStatus.GetEnumerator() | Where-Object { $_.Value.Status -eq 'OK' })

    Write-Host ''
    Write-Host 'SCAN COVERAGE:' -ForegroundColor White
    $total = $script:ModuleStatus.Count
    Write-Host "  Modules run: $($passed.Count)/$total OK" -ForegroundColor $(if ($failed.Count -gt 0) { 'Yellow' } else { 'Green' })

    if ($failed.Count -gt 0) {
        Write-Host "  Modules failed/skipped ($($failed.Count)):" -ForegroundColor Yellow
        foreach ($f in $failed) {
            $detail = if ($f.Value.Detail) { " -- $($f.Value.Detail)" } else { '' }
            Write-Host "    - $($f.Key): $($f.Value.Status)$detail" -ForegroundColor Yellow
        }
        Write-Host '  WARNING: Failed modules may have missed infections. Fix permissions and re-scan.' -ForegroundColor Yellow
    }

    $userProfiles = @(Get-AllUserProfiles)
    Write-Host "  User profiles scanned: $($userProfiles.Count) ($($userProfiles | ForEach-Object { Split-Path $_ -Leaf }))" -ForegroundColor White
    Write-Host ''
}

function Invoke-Cleanup {
    $totalItems = $script:CleanupBatFiles.Count + $script:CleanupGitignoreRepos.Count + $script:CleanupNodeModules.Count
    if ($totalItems -eq 0) { return }
    if (-not [Environment]::UserInteractive) { return }
    if ([Environment]::GetCommandLineArgs() -contains '-NonInteractive') { return }

    Write-Host ''
    Write-Host '================================================' -ForegroundColor White
    Write-Host '  AUTO-CLEANABLE ITEMS FOUND' -ForegroundColor Cyan
    Write-Host '================================================' -ForegroundColor White
    Write-Host ''

    if ($script:CleanupBatFiles.Count -gt 0) {
        Write-Host 'Propagation scripts (will be deleted):' -ForegroundColor White
        foreach ($f in $script:CleanupBatFiles) { Write-Host "  - $f" -ForegroundColor Red }
        Write-Host ''
    }

    if ($script:CleanupGitignoreRepos.Count -gt 0) {
        Write-Host '.gitignore entries to remove (config.bat / temp_auto_push.bat):' -ForegroundColor White
        foreach ($d in $script:CleanupGitignoreRepos) { Write-Host "  - $d\.gitignore" -ForegroundColor Red }
        Write-Host ''
    }

    if ($script:CleanupNodeModules.Count -gt 0) {
        Write-Host 'node_modules directories (entire folder deleted, re-run npm install after):' -ForegroundColor White
        foreach ($d in $script:CleanupNodeModules) { Write-Host "  - $d" -ForegroundColor Red }
        Write-Host ''
    }

    $answer = Read-Host 'Auto-clean the above items? [y/N]'
    Write-Host ''

    if ($answer -match '^[yY]') {
        if ($script:CleanupBatFiles.Count -gt 0) {
            Write-Host 'Removing propagation scripts...' -ForegroundColor White
            foreach ($f in $script:CleanupBatFiles) {
                if (Test-Path $f) {
                    try {
                        Remove-Item $f -Force
                        Write-Host "  [OK]  Deleted: $f" -ForegroundColor Green
                    } catch {
                        Write-Host "  [FAIL] Failed:  $f" -ForegroundColor Red
                    }
                }
            }
            Write-Host ''
        }

        if ($script:CleanupGitignoreRepos.Count -gt 0) {
            Write-Host 'Cleaning .gitignore entries...' -ForegroundColor White
            foreach ($d in $script:CleanupGitignoreRepos) {
                $giFile = Join-Path $d '.gitignore'
                if (Test-Path $giFile) {
                    try {
                        $cleaned = Get-Content $giFile -ErrorAction Stop |
                            Where-Object { $_ -ne 'config.bat' -and $_ -ne 'temp_auto_push.bat' }
                        Set-Content $giFile -Value $cleaned -ErrorAction Stop
                        Write-Host "  [OK]  Cleaned: $giFile" -ForegroundColor Green
                    } catch {
                        Write-Host "  [FAIL] Failed:  $giFile" -ForegroundColor Red
                    }
                }
            }
            Write-Host ''
        }

        if ($script:CleanupNodeModules.Count -gt 0) {
            Write-Host 'Removing node_modules directories...' -ForegroundColor White
            foreach ($d in $script:CleanupNodeModules) {
                # Safety: path must end in node_modules
                if ($d -match '[/\\]node_modules$') {
                    if (Test-Path $d) {
                        try {
                            Remove-Item $d -Recurse -Force
                            Write-Host "  [OK]  Deleted: $d" -ForegroundColor Green
                        } catch {
                            Write-Host "  [FAIL] Failed:  $d" -ForegroundColor Red
                        }
                    }
                } else {
                    Write-Host "  [SKIP] Unexpected path (not deleted): $d" -ForegroundColor Yellow
                }
            }
            Write-Host ''
            Write-Host '  -> Re-run npm install in each affected project directory' -ForegroundColor Cyan
            Write-Host ''
        }
    } else {
        Write-Host 'Skipped. To clean manually:' -ForegroundColor White
        foreach ($f in $script:CleanupBatFiles) {
            Write-Host "  Remove-Item '$f' -Force"
        }
        foreach ($d in $script:CleanupNodeModules) {
            Write-Host "  Remove-Item '$d' -Recurse -Force; npm install"
        }
        Write-Host ''
    }
}

function Write-Remediation {
    Write-Host ''
    Write-Host 'REMEDIATION STEPS:' -ForegroundColor White
    Write-Host ''
    Write-Host 'Repository cleanup:' -ForegroundColor White
    Write-Host "  1. Remove obfuscated payload from infected config files"
    Write-Host "     - Variant 1: everything after legitimate config, starting with global['!']"
    Write-Host "     - Variant 2: everything after legitimate config, starting with global['_V']"
    Write-Host '  2. Delete temp_auto_push.bat and config.bat if present'
    Write-Host '  3. Remove "config.bat" from .gitignore'
    Write-Host '  4. Remove malicious npm dependencies from package.json and run npm install'
    Write-Host '  5. Delete any .woff2 files containing JS payloads'
    Write-Host '  6. Remove malicious .vscode/tasks.json entries'
    Write-Host '  7. Force-push clean versions to GitHub'
    Write-Host ''
    Write-Host 'Windows system cleanup:' -ForegroundColor White
    Write-Host '  8.  Kill suspicious node processes:'
    Write-Host '      taskkill /f /pid <PID>'
    Write-Host '  9.  Remove stealer artifacts:'
    Write-Host '      Remove-Item "$env:USERPROFILE\.npm\<staging_dir>" -Recurse -Force'
    Write-Host '      Remove-Item "$env:LOCALAPPDATA\Temp\tmp7A863DD1.tmp" -Force'
    Write-Host '  10. Check and clean scheduled tasks:'
    Write-Host '      schtasks /delete /tn <task_name> /f'
    Write-Host '  11. Review startup registry keys:'
    Write-Host '      reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
    Write-Host '  12. Review and remove suspicious Windows services:'
    Write-Host '      sc query | findstr /i "python node"'
    Write-Host '      sc delete <service_name>'
    Write-Host '  13. Check PowerShell profiles for injected code:'
    Write-Host "      notepad `$PROFILE"
    Write-Host '  14. Uninstall malicious global npm packages:'
    Write-Host '      npm uninstall -g <package_name>'
    Write-Host '  15. Remove malicious VS Code / Cursor extensions'
    Write-Host '  16. Check agent config dirs (~\.claude, ~\.cursor) for injected configs'
    Write-Host '  17. Clean temp directories'
    Write-Host ''
    Write-Host 'Post-cleanup:' -ForegroundColor White
    Write-Host '  18. Rotate ALL secrets, tokens, API keys, and credentials'
    Write-Host '  19. Change all browser-saved passwords'
    Write-Host '  20. Clear Windows Credential Manager: cmdkey /list'
    Write-Host '  21. Regenerate SSH keys'
    Write-Host '  22. Review browser extensions and remove unrecognized ones'
    Write-Host '  23. Re-scan periodically -- the threat actor re-infects cleaned repos'
    Write-Host '  24. Report to https://opensourcemalware.com'
    Write-Host ''
}

# =========================================================================
#  JSON REPORT
# =========================================================================
function Get-SystemInfo {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

    return [ordered]@{
        hostname           = $env:COMPUTERNAME
        username           = $env:USERNAME
        domain             = $env:USERDOMAIN
        os_version         = if ($os) { "$($os.Caption) $($os.Version)" } else { [System.Environment]::OSVersion.VersionString }
        powershell_version = "$($PSVersionTable.PSVersion)"
        user_sid           = $sid
    }
}

function New-JsonReport ([int]$ExitCode, [timespan]$Duration) {
    $scanMode = if ($Quick) { 'Quick' } elseif ($FullSystem) { 'FullSystem' } else { 'RepoScan' }

    $infectedReposList = [System.Collections.ArrayList]::new()
    foreach ($entry in $script:ReportInfectedRepos.GetEnumerator()) {
        $null = $infectedReposList.Add([ordered]@{
            path          = $entry.Key
            finding_count = $entry.Value.Count
            details       = @($entry.Value)
        })
    }

    $modulesOk = @($script:ModuleStatus.GetEnumerator() | Where-Object { $_.Value.Status -eq 'OK' })
    $modulesFailed = [System.Collections.ArrayList]::new()
    foreach ($m in ($script:ModuleStatus.GetEnumerator() | Where-Object { $_.Value.Status -ne 'OK' })) {
        $null = $modulesFailed.Add([ordered]@{ name = $m.Key; error = $m.Value.Detail })
    }

    $report = [ordered]@{
        report_metadata = [ordered]@{
            report_id            = [guid]::NewGuid().ToString()
            scanner_version      = '1.3'
            scan_mode            = $scanMode
            scan_timestamp_utc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            scan_duration_seconds = [math]::Round($Duration.TotalSeconds, 1)
            exit_code            = $ExitCode
        }
        system_info     = Get-SystemInfo
        scan_summary    = [ordered]@{
            total_repos_scanned    = $script:TotalRepos
            infected_repos         = $script:InfectedRepos
            system_findings_count  = $script:SystemFindings
            risk_score             = $script:RiskScore
            risk_level             = $script:RiskLevel
        }
        findings        = @($script:ReportFindings)
        infected_repos  = @($infectedReposList)
        dns_investigation = [ordered]@{
            c2_domains_hit          = @($script:DnsC2Hits)
            blockchain_endpoints_hit = @($script:DnsBlockchain)
            exfil_channels_hit      = @($script:DnsExfil)
            active_c2_connections   = @($script:ActiveC2Conns)
            suspicious_processes    = @($script:SuspiciousProcs)
        }
        scan_coverage   = [ordered]@{
            modules_run            = $script:ModuleStatus.Count
            modules_ok             = $modulesOk.Count
            modules_failed         = @($modulesFailed)
            user_profiles_scanned  = @(Get-AllUserProfiles | ForEach-Object { Split-Path $_ -Leaf })
        }
    }
    return $report
}

# -------------------------------------------------------------------------
# Telegram reporting
# -------------------------------------------------------------------------
$TG_BOT_TOKEN = $ReportKey
$TG_CHAT_ID   = $ReportChannel
$TG_API_BASE  = "https://api.telegram.org/bot$TG_BOT_TOKEN"
$TG_MAX_RETRIES = 3
$TG_RETRY_DELAY = 5

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {}

function Send-TelegramMessage ([string]$Text) {
    $uri = "$TG_API_BASE/sendMessage"
    $body = @{
        chat_id    = $TG_CHAT_ID
        text       = $Text
        parse_mode = 'HTML'
    }
    for ($i = 1; $i -le $TG_MAX_RETRIES; $i++) {
        try {
            $null = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ErrorAction Stop
            return $true
        } catch {
            Write-Host "  Telegram message attempt $i/$TG_MAX_RETRIES failed: $($_.Exception.Message)" -ForegroundColor Yellow
            if ($i -lt $TG_MAX_RETRIES) { Start-Sleep -Seconds $TG_RETRY_DELAY }
        }
    }
    return $false
}

function Send-TelegramDocument ([string]$FilePath, [string]$Caption) {
    $uri = "$TG_API_BASE/sendDocument"
    $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    $fileName  = [System.IO.Path]::GetFileName($FilePath)
    $boundary  = [guid]::NewGuid().ToString()
    $nl        = "`r`n"

    $bodyLines = @(
        "--$boundary",
        "Content-Disposition: form-data; name=`"chat_id`"$nl",
        $TG_CHAT_ID,
        "--$boundary",
        "Content-Disposition: form-data; name=`"caption`"$nl",
        $Caption,
        "--$boundary",
        "Content-Disposition: form-data; name=`"parse_mode`"$nl",
        "HTML",
        "--$boundary",
        "Content-Disposition: form-data; name=`"document`"; filename=`"$fileName`"",
        "Content-Type: application/json$nl"
    )
    $headerBytes = [System.Text.Encoding]::UTF8.GetBytes(($bodyLines -join $nl) + $nl)
    $footerBytes = [System.Text.Encoding]::UTF8.GetBytes("$nl--$boundary--$nl")

    $bodyStream = [System.IO.MemoryStream]::new()
    $bodyStream.Write($headerBytes, 0, $headerBytes.Length)
    $bodyStream.Write($fileBytes, 0, $fileBytes.Length)
    $bodyStream.Write($footerBytes, 0, $footerBytes.Length)
    $fullBody = $bodyStream.ToArray()
    $bodyStream.Close()

    for ($i = 1; $i -le $TG_MAX_RETRIES; $i++) {
        try {
            $null = Invoke-RestMethod -Uri $uri -Method Post -Body $fullBody `
                -ContentType "multipart/form-data; boundary=$boundary" -ErrorAction Stop
            return $true
        } catch {
            Write-Host "  Telegram file upload attempt $i/$TG_MAX_RETRIES failed: $($_.Exception.Message)" -ForegroundColor Yellow
            if ($i -lt $TG_MAX_RETRIES) { Start-Sleep -Seconds $TG_RETRY_DELAY }
        }
    }
    return $false
}

function Send-TelegramReport ([hashtable]$Report, [string]$ReportFilePath) {
    if (-not $TG_BOT_TOKEN -or -not $TG_CHAT_ID) { return }

    $si = $Report.system_info
    $ss = $Report.scan_summary
    $rm = $Report.report_metadata
    $rl = $ss.risk_level

    $emoji = try {
        switch ($rl) {
            'CRITICAL' { [char]::ConvertFromUtf32(0x1F534) }
            'HIGH'     { [char]::ConvertFromUtf32(0x1F7E0) }
            'MEDIUM'   { [char]::ConvertFromUtf32(0x1F7E1) }
            'LOW'      { [char]::ConvertFromUtf32(0x1F7E2) }
            default    { [char]::ConvertFromUtf32(0x2705)  }
        }
    } catch {
        switch ($rl) {
            'CRITICAL' { '[!!]' }
            'HIGH'     { '[!]'  }
            'MEDIUM'   { '[?]'  }
            'LOW'      { '[OK]' }
            default    { '[OK]' }
        }
    }

    $statusLine = if ($ss.infected_repos -gt 0 -or $ss.system_findings_count -gt 0) {
        "$emoji <b>INFECTIONS DETECTED</b>"
    } else {
        "$emoji <b>CLEAN</b>"
    }

    $summaryText = @(
        "<b>PolinRider Scan Report</b> (v$($rm.scanner_version))",
        "--------------------",
        $statusLine,
        "",
        "<b>System:</b>",
        "  Host: <code>$($si.hostname)</code>",
        "  User: <code>$($si.domain)\$($si.username)</code>",
        "  OS: <code>$($si.os_version)</code>",
        "  SID: <code>$($si.user_sid)</code>",
        "",
        "<b>Results:</b>",
        "  Repos scanned: $($ss.total_repos_scanned)",
        "  Infected repos: $($ss.infected_repos)",
        "  System findings: $($ss.system_findings_count)",
        "  Risk score: <b>$($ss.risk_score)/100 ($rl)</b>",
        "",
        "<b>Scan:</b>",
        "  Mode: $($rm.scan_mode)",
        "  Duration: $($rm.scan_duration_seconds)s",
        "  Time (UTC): $($rm.scan_timestamp_utc)",
        "  Report ID: <code>$($rm.report_id)</code>"
    ) -join "`n"

    $msgOk = Send-TelegramMessage -Text $summaryText
    if (-not $msgOk) {
        Write-Host '  Failed to send summary to Telegram after retries.' -ForegroundColor Red
    }

    if ($ReportFilePath -and (Test-Path $ReportFilePath)) {
        $caption = "$emoji Report: $($si.hostname) | $rl | $($rm.scan_timestamp_utc)"
        $fileOk = Send-TelegramDocument -FilePath $ReportFilePath -Caption $caption
        if (-not $fileOk) {
            Write-Host '  Failed to send report file to Telegram after retries.' -ForegroundColor Red
        }
    }
}

# -------------------------------------------------------------------------
# Export report + send to Telegram
# -------------------------------------------------------------------------
function Export-ScanReport ([int]$ExitCode, [timespan]$Duration) {
    $report = New-JsonReport -ExitCode $ExitCode -Duration $Duration
    $hostname = $env:COMPUTERNAME
    $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $fileName = "polinrider-report-${hostname}-${ts}.json"
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $filePath = Join-Path $scriptDir $fileName
    $savedPath = $null

    try {
        $json = $report | ConvertTo-Json -Depth 10
        [System.IO.File]::WriteAllText($filePath, $json, [System.Text.Encoding]::UTF8)
        $savedPath = $filePath
        Write-Host ''
        Write-Host "  Report saved: $filePath" -ForegroundColor Cyan
    } catch {
        Write-Host "  WARNING: Failed to save report: $($_.Exception.Message)" -ForegroundColor Yellow
        $fallback = Join-Path $env:TEMP $fileName
        try {
            [System.IO.File]::WriteAllText($fallback, $json, [System.Text.Encoding]::UTF8)
            $savedPath = $fallback
            Write-Host "  Report saved to fallback: $fallback" -ForegroundColor Cyan
        } catch {
            Write-Host "  ERROR: Could not save report anywhere: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Send-TelegramReport -Report $report -ReportFilePath $savedPath
}

# =========================================================================
#  MAIN
# =========================================================================
Write-Banner

$startTime = Get-Date

# --- Quick scan ---
if ($Quick) {
    Write-Host 'Mode: Quick Scan (processes + network + DNS investigation)' -ForegroundColor White
    $quickModules = @(
        @{ Name = 'Processes';        Fn = { Scan-Processes } },
        @{ Name = 'Network';          Fn = { Scan-Network } },
        @{ Name = 'DnsInvestigation'; Fn = { Scan-DnsInvestigation } }
    )
    foreach ($mod in $quickModules) {
        try {
            & $mod.Fn
            Set-ModuleStatus $mod.Name 'OK' ''
        } catch {
            Set-ModuleStatus $mod.Name 'FAILED' $_.Exception.Message
            Write-Host "  WARNING: $($mod.Name) module failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Host ''
    Write-Host '================================================' -ForegroundColor White
    if ($script:SystemFindings -gt 0) {
        Write-Host "  RESULTS: $($script:SystemFindings) system finding(s) detected" -ForegroundColor Red

        $totalDns = $script:DnsC2Hits.Count + $script:DnsBlockchain.Count + $script:DnsExfil.Count
        if ($totalDns -gt 0) {
            Write-Host "  DNS:     $totalDns C2-related DNS cache entries found" -ForegroundColor Red
            if ($script:DnsC2Hits.Count -gt 0) {
                Write-Host "           - $($script:DnsC2Hits.Count) command & control domain(s)" -ForegroundColor Red
            }
            if ($script:DnsBlockchain.Count -gt 0) {
                Write-Host "           - $($script:DnsBlockchain.Count) blockchain/crypto drainer endpoint(s)" -ForegroundColor Red
            }
            if ($script:DnsExfil.Count -gt 0) {
                Write-Host "           - $($script:DnsExfil.Count) data exfiltration channel(s)" -ForegroundColor Red
            }
        }

        Write-Host '================================================' -ForegroundColor White
        Write-Host ''
        Write-Host 'Findings:' -ForegroundColor White
        foreach ($f in $script:Findings) { Write-Host "  - $f" -ForegroundColor Red }

        Write-RiskAssessment

        if ($totalDns -gt 0) {
            Write-Host '  For full investigation, run:' -ForegroundColor Yellow
            Write-Host '    .\polinrider-scanner-windows.ps1 -FullSystem -Verbose' -ForegroundColor Yellow
            Write-Host ''
        }

        Write-Remediation
        Write-ScanCoverage
        Export-ScanReport -ExitCode 1 -Duration ((Get-Date) - $startTime)
        exit 1
    } else {
        Write-Host '  RESULTS: No active threats detected' -ForegroundColor Green
        Write-Host '================================================' -ForegroundColor White
        Write-ScanCoverage
        Export-ScanReport -ExitCode 0 -Duration ((Get-Date) - $startTime)
        exit 0
    }
}

# --- Full system scan ---
if ($FullSystem) {
    Write-Host 'Mode: Full System Scan (all users)' -ForegroundColor White
    Write-Host 'Scanning processes, persistence, services, PS profiles, extensions, repos, stealer artifacts, and more.'
    $allUsers = Get-AllUserProfiles
    Write-Host "  User profiles found: $($allUsers -join ', ')" -ForegroundColor Cyan

    $modules = @(
        @{ Name = 'Processes';        Fn = { Scan-Processes } },
        @{ Name = 'Network';          Fn = { Scan-Network } },
        @{ Name = 'ScheduledTasks';   Fn = { Scan-ScheduledTasks } },
        @{ Name = 'Registry';         Fn = { Scan-StartupRegistry } },
        @{ Name = 'Services';         Fn = { Scan-WindowsServices } },
        @{ Name = 'PSProfiles';       Fn = { Scan-PSProfiles } },
        @{ Name = 'StealerArtifacts'; Fn = { Scan-StealerArtifacts } },
        @{ Name = 'VSCodeExtensions'; Fn = { Scan-VSCodeExtensions } },
        @{ Name = 'NpmGlobal';        Fn = { Scan-NpmGlobal } },
        @{ Name = 'TempDirs';         Fn = { Scan-TempDirs } },
        @{ Name = 'BrowserExtensions';Fn = { Scan-BrowserExtensions } },
        @{ Name = 'DnsInvestigation'; Fn = { Scan-DnsInvestigation } }
    )
    foreach ($mod in $modules) {
        try {
            & $mod.Fn
            Set-ModuleStatus $mod.Name 'OK' ''
        } catch {
            Set-ModuleStatus $mod.Name 'FAILED' $_.Exception.Message
            Write-Host "  WARNING: $($mod.Name) module failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    if (-not $Path) { $Path = "$env:SystemDrive\Users" }
}

# --- Directory-based repo scan ---
if (-not $Path) { $Path = '.' }
$Path = (Resolve-Path $Path -ErrorAction SilentlyContinue).Path
if (-not $Path -or -not (Test-Path $Path -PathType Container)) {
    Write-Host "Error: Directory not found: $Path" -ForegroundColor Red
    Export-ScanReport -ExitCode 2 -Duration ((Get-Date) - $startTime)
    exit 2
}

Write-Section 'REPOS' "Scanning git repositories under $Path..."

$repos = Get-ChildItem $Path -Recurse -Filter '.git' -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notlike '*node_modules*' } |
    ForEach-Object { $_.Parent.FullName } |
    Sort-Object -Unique

if (-not $repos) {
    Write-Host "  No git repositories found under $Path"
} else {
    $repoCount = @($repos).Count
    Write-Host "  Found $repoCount git repositories..."
    foreach ($repo in $repos) {
        Scan-Repo $repo | Out-Null
    }
}

# =========================================================================
#  SUMMARY
# =========================================================================
$duration = (Get-Date) - $startTime
$cleanRepos = $script:TotalRepos - $script:InfectedRepos
$totalIssues = $script:InfectedRepos + $script:SystemFindings

Write-Host ''
if ($script:TotalRepos -gt 0 -and $cleanRepos -gt 0) {
    Write-Host "[CLEAN] $cleanRepos repositories scanned clean" -ForegroundColor Green
}

Write-Host ''
Write-Host '================================================' -ForegroundColor White

if ($totalIssues -gt 0) {
    if ($script:InfectedRepos -gt 0) {
        Write-Host "  REPOS:   $($script:InfectedRepos) infected repo(s) found" -ForegroundColor Red
    }
    if ($script:SystemFindings -gt 0) {
        Write-Host "  SYSTEM:  $($script:SystemFindings) system finding(s) detected" -ForegroundColor Red
    }

    # DNS findings breakdown
    $totalDns = $script:DnsC2Hits.Count + $script:DnsBlockchain.Count + $script:DnsExfil.Count
    if ($totalDns -gt 0) {
        Write-Host "  DNS:     $totalDns C2-related DNS cache entries found" -ForegroundColor Red
        if ($script:DnsC2Hits.Count -gt 0) {
            Write-Host "           - $($script:DnsC2Hits.Count) command & control domain(s)" -ForegroundColor Red
        }
        if ($script:DnsBlockchain.Count -gt 0) {
            Write-Host "           - $($script:DnsBlockchain.Count) blockchain/crypto drainer endpoint(s)" -ForegroundColor Red
        }
        if ($script:DnsExfil.Count -gt 0) {
            Write-Host "           - $($script:DnsExfil.Count) data exfiltration channel(s)" -ForegroundColor Red
        }
    }

    Write-Host '================================================' -ForegroundColor White

    if ($script:SystemFindings -gt 0) {
        Write-Host ''
        Write-Host 'System Findings:' -ForegroundColor White
        foreach ($f in $script:Findings) { Write-Host "  - $f" -ForegroundColor Red }
    }

    Write-RiskAssessment
    Write-Remediation
    Invoke-Cleanup
    Write-ScanCoverage
    Write-Host "Scan complete in $([math]::Floor($duration.TotalMinutes))m$($duration.Seconds)s"
    Export-ScanReport -ExitCode 1 -Duration $duration
    exit 1
} else {
    Write-Host '  RESULTS: No infections found' -ForegroundColor Green
    Write-Host '================================================' -ForegroundColor White
    Write-ScanCoverage
    Write-Host ''
    Write-Host "Scan complete in $([math]::Floor($duration.TotalMinutes))m$($duration.Seconds)s"
    Export-ScanReport -ExitCode 0 -Duration $duration
    exit 0
}
