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
    try {
        Start-Process -FilePath $psCmd -ArgumentList $argList -Wait -NoNewWindow
        Write-Log "Exécution terminée pour $ScriptPath" -Level 'SUCCESS'
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
    Write-Host '==========================================' -ForegroundColor DarkCyan
    Write-Host '  PowerShell Tools Panel for Windows' -ForegroundColor Cyan
    Write-Host '==========================================' -ForegroundColor DarkCyan
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
        Write-Host '1. Scripts de Sameer' -ForegroundColor White
        Write-Host '2. Scripts d''Alex' -ForegroundColor White
        Write-Host '3. Scripts de Jimmy' -ForegroundColor White
        Write-Host '4. Lancer un script par chemin' -ForegroundColor White
        Write-Host '5. Space Invader' -ForegroundColor White
        Write-Host '0. Quitter' -ForegroundColor Red
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
                $spacePath = Join-Path $script:RootPath 'space_invader/space_invader.ps1'
                if (-not (Test-Path -LiteralPath $spacePath)) {
                    Write-Host 'Space Invader non disponible.' -ForegroundColor Red
                    Start-Sleep -Seconds 1
                } else {
                    Run-Script -ScriptPath $spacePath -RawArgs ''
                }
            }
            '0' { Write-Log 'Fermeture du menu.' -Level 'INFO'; return }
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