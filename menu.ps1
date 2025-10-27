<#
    Menu principal PowerShell Tools Panel for Windows

    Permet de lancer facilement les scripts des répertoires:
    - sameer/
    - script_alex/
    - script_jimmy/

    Fonctionnalités:
    - Menu interactif avec couleurs
    - Détection de la commande PowerShell disponible (pwsh/powershell)
    - Journalisation dans logs/menu.log
    - Sous-menu par contributeur avec détection dynamique des scripts
    - Possibilité de passer des arguments libres au script sélectionné

    Auteur: Équipe (Jimmy, Sameer, Alex)
    Version: 1.0
#>

param(
    [switch]$NoLogo
)

$ErrorActionPreference = 'Stop'

$script:RootPath = $PSScriptRoot
$script:LogsDir = Join-Path $script:RootPath 'logs'
$script:LogFile = Join-Path $script:LogsDir 'menu.log'

function Ensure-LogsDir {
    if (-not (Test-Path $script:LogsDir)) {
        New-Item -Path $script:LogsDir -ItemType Directory | Out-Null
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','SUCCESS','WARNING','ERROR')][string]$Level = 'INFO'
    )
    Ensure-LogsDir
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$timestamp] [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $line
    switch ($Level) {
        'INFO'    { Write-Host $Message -ForegroundColor Cyan }
        'SUCCESS' { Write-Host $Message -ForegroundColor Green }
        'WARNING' { Write-Host $Message -ForegroundColor Yellow }
        'ERROR'   { Write-Host $Message -ForegroundColor Red }
    }
}

# Animations de confort (spinner, barre de progression, décompte)
function Show-Spinner {
    param([string]$Text = 'Chargement', [int]$Seconds = 2)
    $frames = @('|','/','-','\\')
    $end = (Get-Date).AddSeconds($Seconds)
    $i = 0
    while ((Get-Date) -lt $end) {
        Write-Host ("`r$Text " + $frames[$i % $frames.Length]) -NoNewline -ForegroundColor Yellow
        Start-Sleep -Milliseconds 120
        $i++
    }
    Write-Host "`r$Text ✓       " -ForegroundColor Green
}

function Show-ProgressBar {
    param([string]$Text = 'Préparation', [int]$Steps = 20, [int]$DelayMs = 60)
    for ($i=1; $i -le $Steps; $i++) {
        $bar = ('#' * $i).PadRight($Steps,'-')
        $pct = [int](($i/$Steps)*100)
        Write-Host ("`r$Text [${bar}] ${pct}%") -NoNewline -ForegroundColor Cyan
        Start-Sleep -Milliseconds $DelayMs
    }
    Write-Host ''
}

function Show-Countdown {
    param([int]$Seconds = 3, [string]$Text = 'Décompte')
    for ($s=$Seconds; $s -ge 1; $s--) {
        Write-Host ("`r${Text}: ${s} ") -NoNewline -ForegroundColor Magenta
        Start-Sleep -Seconds 1
    }
    Write-Host "`r${Text}: GO!   " -ForegroundColor Green
}

function Get-PowerShellCommand {
    if (Get-Command -Name pwsh -ErrorAction SilentlyContinue) {
        return 'pwsh'
    }
    return 'powershell'
}

function Quote-ForCmd {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    # Mettre entre guillemets si l'argument contient des espaces
    if ($Text -match '\s') { return '"' + $Text.Replace('"','\"') + '"' }
    return $Text
}

function Run-Script {
    param(
        [Parameter(Mandatory=$true)][string]$ScriptPath,
        [string]$RawArgs
    )

    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        Write-Log "Script introuvable: $ScriptPath" -Level 'ERROR'
        return
    }

    $psCmd = Get-PowerShellCommand
    $quotedScript = Quote-ForCmd $ScriptPath
    $argList = "-NoProfile -ExecutionPolicy Bypass -File $quotedScript"
    if ($RawArgs) { $argList = "$argList $RawArgs" }

    Write-Log "Lancement: $psCmd $argList" -Level 'INFO'
    Show-Spinner -Text 'Préparation' -Seconds 1
    try {
        Start-Process -FilePath $psCmd -ArgumentList $argList -Wait -NoNewWindow
        Write-Log "Exécution terminée pour $ScriptPath" -Level 'SUCCESS'
        Show-ProgressBar -Text 'Retour au menu' -Steps 15 -DelayMs 40
    } catch {
        Write-Log "Erreur d'exécution: $($_.Exception.Message)" -Level 'ERROR'
    }
}

function Get-ContributorFolder {
    param([ValidateSet('sameer','script_alex','script_jimmy')][string]$Name)
    return Join-Path $script:RootPath $Name
}

function List-Scripts {
    param([string]$Folder)
    if (-not (Test-Path -LiteralPath $Folder)) { return @() }
    Get-ChildItem -Path $Folder -Filter '*.ps1' -File | Sort-Object Name
}

function Show-Header {
    if ($NoLogo) { return }
    Clear-Host
    Write-Host '╔══════════════════════════════════════════╗' -ForegroundColor DarkCyan
    Write-Host '║   PowerShell Tools Panel for Windows     ║' -ForegroundColor Cyan
    Write-Host '╚══════════════════════════════════════════╝' -ForegroundColor DarkCyan
    Write-Host "Racine: $script:RootPath" -ForegroundColor Gray
    Write-Host "Logs:   $script:LogFile" -ForegroundColor Gray
    Write-Host ''
}

function Show-ContributorMenu {
    param([ValidateSet('sameer','script_alex','script_jimmy')][string]$Contributor)

    $folder = Get-ContributorFolder -Name $Contributor
    if (-not (Test-Path -LiteralPath $folder)) {
        Write-Log "Dossier introuvable: $folder" -Level 'ERROR'
        return
    }

    do {
        Clear-Host
        Write-Host "=== Scripts: $Contributor ===" -ForegroundColor Cyan
        $scripts = List-Scripts -Folder $folder
        if ($scripts.Count -eq 0) {
            Write-Host 'Aucun script disponible.' -ForegroundColor Yellow
            Read-Host 'Entrée pour revenir'
            return
        }

        $i = 1
        foreach ($s in $scripts) {
            Write-Host ("{0}. {1}" -f $i, $s.Name) -ForegroundColor White
            $i++
        }
        Write-Host '0. Retour' -ForegroundColor Red
        Write-Host ''

        $choice = Read-Host 'Sélectionnez un script à exécuter'
        if ($choice -eq '0') { return }

        if ($choice -match '^[0-9]+$' -and [int]$choice -ge 1 -and [int]$choice -le $scripts.Count) {
            $selected = $scripts[[int]$choice - 1]
            Write-Host "Script sélectionné: $($selected.FullName)" -ForegroundColor Yellow
            $args = Read-Host 'Arguments supplémentaires (laisser vide si aucun)'
            Run-Script -ScriptPath $selected.FullName -RawArgs $args
            Read-Host 'Appuyez sur Entrée pour continuer'
        } else {
            Write-Host 'Choix invalide.' -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    } while ($true)
}

function Show-MainMenu {
    do {
        Show-Header
        Write-Host '────────── Options ──────────' -ForegroundColor DarkCyan
        Write-Host '1. Scripts de Sameer' -ForegroundColor White
        Write-Host '2. Scripts d''Alex' -ForegroundColor White
        Write-Host '3. Scripts de Jimmy' -ForegroundColor White
        Write-Host '4. Lancer un script par chemin' -ForegroundColor White
        Write-Host '5. Mini Jeux' -ForegroundColor White
        Write-Host '0. Quitter' -ForegroundColor Red
        Write-Host '──────────────────────────────' -ForegroundColor DarkCyan
        Write-Host ''

        $choice = Read-Host 'Votre choix'
        switch ($choice) {
            '1' { Show-ContributorMenu -Contributor 'sameer' }
            '2' { Show-ContributorMenu -Contributor 'script_alex' }
            '3' { Show-ContributorMenu -Contributor 'script_jimmy' }
            '4' {
                $path = Read-Host 'Chemin complet du script (.ps1)'
                if (-not $path) { continue }
                $args = Read-Host 'Arguments supplémentaires (laisser vide si aucun)'
                Run-Script -ScriptPath $path -RawArgs $args
                Read-Host 'Appuyez sur Entrée pour continuer'
            }
            '5' {
                $miniPath = Join-Path $script:RootPath 'mini_jeu/mini_jeu.ps1'
                if (-not (Test-Path -LiteralPath $miniPath)) {
                    Write-Host 'Mini Jeux non disponible.' -ForegroundColor Red
                    Start-Sleep -Seconds 1
                } else {
                    Show-Countdown -Seconds 3 -Text 'Ouverture des Mini Jeux dans'
                    Run-Script -ScriptPath $miniPath -RawArgs ''
                }
            }
            '0' { Write-Log 'Fermeture du menu.' -Level 'INFO'; Show-Countdown -Seconds 3 -Text 'Fermeture dans'; return }
            default {
                Write-Host 'Choix invalide.' -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

# Entrée
try {
    Ensure-LogsDir
    Write-Log '=== Démarrage du menu principal ===' -Level 'INFO'
    Show-MainMenu
    Write-Log '=== Fin du menu principal ===' -Level 'SUCCESS'
} catch {
    Write-Log "Erreur critique: $($_.Exception.Message)" -Level 'ERROR'
    exit 1
}