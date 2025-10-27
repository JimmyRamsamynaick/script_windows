<#
    Mini-Jeux (Console)

    Sous-menu pour plusieurs mini-jeux:
    1) Snake
    2) Space Invader
    3) Nombre Mystère
    0) Revenir en arrière

    Exécution:
    pwsh -NoProfile -ExecutionPolicy Bypass -File .\mini_jeu\mini_jeu.ps1
#>

param(
    [switch]$NoLogo
)

$ErrorActionPreference = 'Stop'

$script:Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:SnakePath = Join-Path $script:Root 'snake.ps1'
$script:InvaderPath = Join-Path $script:Root 'space_invader.ps1'
$script:GuessPath = Join-Path $script:Root 'guess.ps1'

function Get-PowerShellCommand {
    if (Get-Command -Name pwsh -ErrorAction SilentlyContinue) { return 'pwsh' }
    return 'powershell'
}

function Show-Spinner {
    param([string]$Text='Chargement',[int]$Seconds=2)
    $frames=@('|','/','-','\\')
    $end=[DateTime]::UtcNow.AddSeconds($Seconds)
    Write-Host $Text -ForegroundColor Yellow
    while([DateTime]::UtcNow -lt $end){
        foreach($f in $frames){
            Write-Host ("`r${Text} ${f}   ") -NoNewline -ForegroundColor Yellow
            Start-Sleep -Milliseconds 120
        }
    }
    Write-Host ("`r${Text} ✔   ") -ForegroundColor Green
}

function Show-Countdown {
    param([int]$Seconds=3,[string]$Text='Démarrage dans')
    for($s=$Seconds;$s -ge 1;$s--){
        Write-Host ("`r${Text}: ${s} ") -NoNewline -ForegroundColor Magenta
        Start-Sleep -Seconds 1
    }
    Write-Host "`r${Text}: GO!   " -ForegroundColor Green
}

function Write-Title {
    Clear-Host
    if($NoLogo){return}
    $lines=@(
        '╔════════════════════════════════════════════════════════════╗',
        '║                      Panneau des Mini-Jeux                  ║',
        '╚════════════════════════════════════════════════════════════╝',
        ''
    )
    foreach($l in $lines){ Write-Host $l -ForegroundColor Cyan }
}

function Run-Child([string]$path){
    if(-not (Test-Path -LiteralPath $path)){
        Write-Host "Script introuvable: $path" -ForegroundColor Red
        Read-Host 'Appuyez sur Entrée pour revenir'
        return
    }
    try{
        # Exécution inline pour une meilleure capture des entrées clavier
        & $path
    }catch{
        Write-Host "Erreur lors de l'exécution: $($_.Exception.Message)" -ForegroundColor Red
        Read-Host 'Appuyez sur Entrée pour revenir'
    }
}

function Show-Menu {
    do{
        Write-Title
        Write-Host '────────── Options ──────────' -ForegroundColor DarkCyan
        Write-Host '1. Snake' -ForegroundColor White
        Write-Host '2. Space Invader' -ForegroundColor White
        Write-Host '3. Nombre Mystère' -ForegroundColor White
        Write-Host '0. Revenir en arrière' -ForegroundColor Red
        Write-Host '──────────────────────────────' -ForegroundColor DarkCyan
        Write-Host ''
        $choice=Read-Host 'Votre choix'
        switch($choice){
            '1' { Show-Countdown -Seconds 3 -Text 'Lancement de Snake dans'; Show-Spinner -Text 'Chargement de Snake' -Seconds 2; Run-Child $script:SnakePath }
            '2' { Show-Countdown -Seconds 3 -Text 'Lancement de Space Invader dans'; Show-Spinner -Text 'Chargement de Space Invader' -Seconds 2; Run-Child $script:InvaderPath }
            '3' { Show-Countdown -Seconds 2 -Text 'Ouverture du jeu Nombre Mystère'; Run-Child $script:GuessPath }
            '0' { Show-Countdown -Seconds 3 -Text 'Retour au menu principal dans'; return }
            default { Write-Host 'Choix invalide.' -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    }while($true)
}

try { Show-Menu } catch { Write-Host "Erreur: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }