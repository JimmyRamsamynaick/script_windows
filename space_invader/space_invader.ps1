<#
    Space Invader Menu (Console)

    Affiche un menu style Space Invader avec deux options:
    1) Jouer au jeu (lance game.ps1)
    0) Revenir en arrière (quitter)

    Exécution:
    pwsh -NoProfile -ExecutionPolicy Bypass -File .\space_invader\space_invader.ps1
#>

param(
    [switch]$NoLogo
)

$ErrorActionPreference = 'Stop'

$script:Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:GamePath = Join-Path $script:Root 'game.ps1'

function Write-AsciiTitle {
    Clear-Host
    if ($NoLogo) { return }
    $lines = @(
        '   ___                     _                     ',
        '  / __|  _ _  _ _  ___  __| |  __ _  _ _   ___  ',
        " | (__  | '_|| '_|/ -_)/ _` | / _` || '_| / -_)",
        '  \___| |_|  |_|  \___|\__,_| \__,_||_|   \___| ',
        '',
        '           =============[ SPACE INVADER ]============='
    )
    foreach ($l in $lines) { Write-Host $l -ForegroundColor Cyan }
    Write-Host ''
}

function Get-PowerShellCommand {
    if (Get-Command -Name pwsh -ErrorAction SilentlyContinue) { return 'pwsh' }
    return 'powershell'
}

function Run-Game {
    if (-not (Test-Path -LiteralPath $script:GamePath)) {
        Write-Host "Jeu introuvable: $script:GamePath" -ForegroundColor Red
        Read-Host 'Appuyez sur Entrée pour revenir'
        return
    }
    $ps = Get-PowerShellCommand
    Start-Process -FilePath $ps -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$script:GamePath`"" -Wait -NoNewWindow
}

function Show-Menu {
    do {
        Write-AsciiTitle
        Write-Host '1. Jouer' -ForegroundColor White
        Write-Host '0. Revenir en arrière' -ForegroundColor Red
        Write-Host ''
        $choice = Read-Host 'Votre choix'
        switch ($choice) {
            '1' { Run-Game }
            '0' { Write-Host 'Retour...' -ForegroundColor Yellow; return }
            default { Write-Host 'Choix invalide.' -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

try {
    Show-Menu
} catch {
    Write-Host "Erreur: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}