<#
.SYNOPSIS
    Mise à jour automatisée des paquets système Windows

.DESCRIPTION
    Ce script automatise la mise à jour des paquets et logiciels sur Windows via :
    - Windows Update (mises à jour système)
    - Chocolatey (gestionnaire de paquets)
    - Winget (gestionnaire Microsoft)
    - PowerShell Gallery (modules PowerShell)
    - Mise à jour manuelle de logiciels spécifiques

.PARAMETER UpdateSource
    Source de mise à jour: All, WindowsUpdate, Chocolatey, Winget, PowerShell

.PARAMETER AutoApprove
    Approuver automatiquement toutes les mises à jour sans confirmation

.PARAMETER ExcludePackages
    Liste des paquets à exclure des mises à jour

.PARAMETER LogPath
    Chemin pour le fichier de log des mises à jour

.PARAMETER RebootIfRequired
    Redémarrer automatiquement si nécessaire après les mises à jour

.PARAMETER CheckOnly
    Vérifier les mises à jour disponibles sans les installer

.EXAMPLE
    .\majPackages.ps1
    Mise à jour interactive de tous les gestionnaires

.EXAMPLE
    .\majPackages.ps1 -UpdateSource Chocolatey -AutoApprove
    Mise à jour automatique via Chocolatey uniquement

.EXAMPLE
    .\majPackages.ps1 -CheckOnly
    Vérification des mises à jour disponibles sans installation

.NOTES
    Auteur: Sameer
    Date: 28/10/2025
    Version: 1.0
    Prérequis: Droits administrateur, gestionnaires de paquets installés
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "WindowsUpdate", "Chocolatey", "Winget", "PowerShell")]
    [string]$UpdateSource = "All",
    
    [Parameter(Mandatory=$false)]
    [switch]$AutoApprove,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludePackages = @(),
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$RebootIfRequired,
    
    [Parameter(Mandatory=$false)]
    [switch]$CheckOnly
)

# Configuration
$ErrorActionPreference = "Continue"
$VerbosePreference = "Continue"

# Variables globales
$script:UpdateLog = @()
$script:UpdatesInstalled = 0
$script:UpdatesAvailable = 0
$script:RebootRequired = $false

# Fonctions utilitaires
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $color = switch($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "INFO"  { "Green" }
        "SUCCESS" { "Cyan" }
        default { "White" }
    }
    
    Write-Host $logEntry -ForegroundColor $color
    $script:UpdateLog += $logEntry
}

function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-PackageManager {
    param([string]$Manager)
    
    switch ($Manager) {
        "Chocolatey" {
            if (-not (Get-Command "choco" -ErrorAction SilentlyContinue)) {
                Write-Log "Installation de Chocolatey..." -Level "INFO"
                try {
                    Set-ExecutionPolicy Bypass -Scope Process -Force
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
                    Write-Log "✅ Chocolatey installé avec succès" -Level "SUCCESS"
                    return $true
                }
                catch {
                    Write-Log "Erreur lors de l'installation de Chocolatey: $($_.Exception.Message)" -Level "ERROR"
                    return $false
                }
            }
            return $true
        }
        
        "Winget" {
            if (-not (Get-Command "winget" -ErrorAction SilentlyContinue)) {
                Write-Log "Winget non disponible. Installation via Microsoft Store requise." -Level "WARN"
                return $false
            }
            return $true
        }
        
        "PSWindowsUpdate" {
            if (-not (Get-Module -ListAvailable -Name "PSWindowsUpdate")) {
                Write-Log "Installation du module PSWindowsUpdate..." -Level "INFO"
                try {
                    Install-Module -Name PSWindowsUpdate -Force -AllowClobber
                    Write-Log "✅ Module PSWindowsUpdate installé" -Level "SUCCESS"
                    return $true
                }
                catch {
                    Write-Log "Erreur lors de l'installation de PSWindowsUpdate: $($_.Exception.Message)" -Level "ERROR"
                    return $false
                }
            }
            return $true
        }
    }
    return $false
}

function Update-WindowsSystem {
    Write-Log "=== Mise à jour Windows Update ===" -Level "SUCCESS"
    
    try {
        # Vérifier et installer le module PSWindowsUpdate
        if (-not (Install-PackageManager -Manager "PSWindowsUpdate")) {
            Write-Log "Impossible d'installer PSWindowsUpdate, utilisation de Windows Update classique" -Level "WARN"
            return
        }
        
        Import-Module PSWindowsUpdate -Force
        
        # Vérifier les mises à jour disponibles
        Write-Log "Recherche des mises à jour Windows..."
        $updates = Get-WUList -MicrosoftUpdate
        
        if ($updates.Count -eq 0) {
            Write-Log "✅ Aucune mise à jour Windows disponible" -Level "SUCCESS"
            return
        }
        
        Write-Log "Mises à jour disponibles: $($updates.Count)"
        $script:UpdatesAvailable += $updates.Count
        
        # Afficher les mises à jour
        foreach ($update in $updates) {
            Write-Log "  - $($update.Title) ($($update.Size) MB)"
        }
        
        if ($CheckOnly) {
            Write-Log "Mode vérification uniquement - Installation ignorée" -Level "INFO"
            return
        }
        
        # Demander confirmation si pas en mode auto
        if (-not $AutoApprove) {
            $response = Read-Host "Installer ces mises à jour ? (o/N)"
            if ($response -ne 'o' -and $response -ne 'O') {
                Write-Log "Installation annulée par l'utilisateur" -Level "INFO"
                return
            }
        }
        
        # Installer les mises à jour
        Write-Log "Installation des mises à jour Windows..."
        $installResult = Install-WUUpdates -MicrosoftUpdate -AcceptAll -AutoReboot:$RebootIfRequired
        
        $script:UpdatesInstalled += $installResult.Count
        Write-Log "✅ $($installResult.Count) mises à jour Windows installées" -Level "SUCCESS"
        
        # Vérifier si un redémarrage est requis
        if (Get-WURebootStatus -Silent) {
            $script:RebootRequired = $true
            Write-Log "⚠️  Redémarrage requis pour finaliser les mises à jour" -Level "WARN"
        }
    }
    catch {
        Write-Log "Erreur lors de la mise à jour Windows: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Update-ChocolateyPackages {
    Write-Log "=== Mise à jour Chocolatey ===" -Level "SUCCESS"
    
    if (-not (Install-PackageManager -Manager "Chocolatey")) {
        Write-Log "Chocolatey non disponible, ignoré" -Level "WARN"
        return
    }
    
    try {
        # Mettre à jour Chocolatey lui-même
        Write-Log "Mise à jour de Chocolatey..."
        & choco upgrade chocolatey -y
        
        # Lister les paquets obsolètes
        Write-Log "Recherche des paquets Chocolatey obsolètes..."
        $outdatedOutput = & choco outdated --limit-output
        
        if (-not $outdatedOutput) {
            Write-Log "✅ Tous les paquets Chocolatey sont à jour" -Level "SUCCESS"
            return
        }
        
        $outdatedPackages = $outdatedOutput | ForEach-Object {
            $parts = $_ -split '\|'
            if ($parts.Count -ge 3) {
                [PSCustomObject]@{
                    Name = $parts[0]
                    CurrentVersion = $parts[1]
                    AvailableVersion = $parts[2]
                }
            }
        } | Where-Object { $_.Name -notin $ExcludePackages }
        
        if (-not $outdatedPackages) {
            Write-Log "✅ Aucun paquet Chocolatey à mettre à jour (après exclusions)" -Level "SUCCESS"
            return
        }
        
        Write-Log "Paquets Chocolatey obsolètes: $($outdatedPackages.Count)"
        $script:UpdatesAvailable += $outdatedPackages.Count
        
        foreach ($package in $outdatedPackages) {
            Write-Log "  - $($package.Name): $($package.CurrentVersion) → $($package.AvailableVersion)"
        }
        
        if ($CheckOnly) {
            Write-Log "Mode vérification uniquement - Installation ignorée" -Level "INFO"
            return
        }
        
        # Demander confirmation si pas en mode auto
        if (-not $AutoApprove) {
            $response = Read-Host "Mettre à jour ces paquets Chocolatey ? (o/N)"
            if ($response -ne 'o' -and $response -ne 'O') {
                Write-Log "Mise à jour annulée par l'utilisateur" -Level "INFO"
                return
            }
        }
        
        # Mettre à jour tous les paquets
        Write-Log "Mise à jour des paquets Chocolatey..."
        $excludeArgs = if ($ExcludePackages.Count -gt 0) { "--except=`"$($ExcludePackages -join ',')`"" } else { "" }
        
        if ($AutoApprove) {
            & choco upgrade all -y $excludeArgs
        } else {
            & choco upgrade all $excludeArgs
        }
        
        $script:UpdatesInstalled += $outdatedPackages.Count
        Write-Log "✅ Paquets Chocolatey mis à jour" -Level "SUCCESS"
    }
    catch {
        Write-Log "Erreur lors de la mise à jour Chocolatey: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Update-WingetPackages {
    Write-Log "=== Mise à jour Winget ===" -Level "SUCCESS"
    
    if (-not (Install-PackageManager -Manager "Winget")) {
        Write-Log "Winget non disponible, ignoré" -Level "WARN"
        return
    }
    
    try {
        # Lister les mises à jour disponibles
        Write-Log "Recherche des mises à jour Winget..."
        $upgradeOutput = & winget upgrade --include-unknown
        
        # Parser la sortie pour extraire les paquets
        $lines = $upgradeOutput -split "`n" | Where-Object { $_ -match "^\S+\s+\S+\s+\S+\s+\S+" }
        
        if ($lines.Count -le 1) {  # Header line only
            Write-Log "✅ Tous les paquets Winget sont à jour" -Level "SUCCESS"
            return
        }
        
        $outdatedPackages = @()
        foreach ($line in $lines[1..($lines.Count-1)]) {  # Skip header
            if ($line -match "^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)") {
                $packageName = $matches[1]
                if ($packageName -notin $ExcludePackages) {
                    $outdatedPackages += [PSCustomObject]@{
                        Name = $packageName
                        Id = $matches[2]
                        CurrentVersion = $matches[3]
                        AvailableVersion = $matches[4]
                    }
                }
            }
        }
        
        if ($outdatedPackages.Count -eq 0) {
            Write-Log "✅ Aucun paquet Winget à mettre à jour (après exclusions)" -Level "SUCCESS"
            return
        }
        
        Write-Log "Paquets Winget obsolètes: $($outdatedPackages.Count)"
        $script:UpdatesAvailable += $outdatedPackages.Count
        
        foreach ($package in $outdatedPackages) {
            Write-Log "  - $($package.Name): $($package.CurrentVersion) → $($package.AvailableVersion)"
        }
        
        if ($CheckOnly) {
            Write-Log "Mode vérification uniquement - Installation ignorée" -Level "INFO"
            return
        }
        
        # Demander confirmation si pas en mode auto
        if (-not $AutoApprove) {
            $response = Read-Host "Mettre à jour ces paquets Winget ? (o/N)"
            if ($response -ne 'o' -and $response -ne 'O') {
                Write-Log "Mise à jour annulée par l'utilisateur" -Level "INFO"
                return
            }
        }
        
        # Mettre à jour les paquets un par un
        Write-Log "Mise à jour des paquets Winget..."
        foreach ($package in $outdatedPackages) {
            try {
                Write-Log "Mise à jour: $($package.Name)..."
                if ($AutoApprove) {
                    & winget upgrade --id $package.Id --silent --accept-source-agreements --accept-package-agreements
                } else {
                    & winget upgrade --id $package.Id --interactive
                }
                $script:UpdatesInstalled++
            }
            catch {
                Write-Log "Erreur mise à jour $($package.Name): $($_.Exception.Message)" -Level "WARN"
            }
        }
        
        Write-Log "✅ Paquets Winget mis à jour" -Level "SUCCESS"
    }
    catch {
        Write-Log "Erreur lors de la mise à jour Winget: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Update-PowerShellModules {
    Write-Log "=== Mise à jour des modules PowerShell ===" -Level "SUCCESS"
    
    try {
        # Lister les modules obsolètes
        Write-Log "Recherche des modules PowerShell obsolètes..."
        $installedModules = Get-InstalledModule
        $outdatedModules = @()
        
        foreach ($module in $installedModules) {
            if ($module.Name -notin $ExcludePackages) {
                try {
                    $onlineVersion = Find-Module -Name $module.Name -ErrorAction SilentlyContinue
                    if ($onlineVersion -and ([version]$onlineVersion.Version -gt [version]$module.Version)) {
                        $outdatedModules += [PSCustomObject]@{
                            Name = $module.Name
                            CurrentVersion = $module.Version
                            AvailableVersion = $onlineVersion.Version
                        }
                    }
                }
                catch {
                    Write-Verbose "Impossible de vérifier $($module.Name): $($_.Exception.Message)"
                }
            }
        }
        
        if ($outdatedModules.Count -eq 0) {
            Write-Log "✅ Tous les modules PowerShell sont à jour" -Level "SUCCESS"
            return
        }
        
        Write-Log "Modules PowerShell obsolètes: $($outdatedModules.Count)"
        $script:UpdatesAvailable += $outdatedModules.Count
        
        foreach ($module in $outdatedModules) {
            Write-Log "  - $($module.Name): $($module.CurrentVersion) → $($module.AvailableVersion)"
        }
        
        if ($CheckOnly) {
            Write-Log "Mode vérification uniquement - Installation ignorée" -Level "INFO"
            return
        }
        
        # Demander confirmation si pas en mode auto
        if (-not $AutoApprove) {
            $response = Read-Host "Mettre à jour ces modules PowerShell ? (o/N)"
            if ($response -ne 'o' -and $response -ne 'O') {
                Write-Log "Mise à jour annulée par l'utilisateur" -Level "INFO"
                return
            }
        }
        
        # Mettre à jour les modules
        Write-Log "Mise à jour des modules PowerShell..."
        foreach ($module in $outdatedModules) {
            try {
                Write-Log "Mise à jour: $($module.Name)..."
                Update-Module -Name $module.Name -Force
                $script:UpdatesInstalled++
            }
            catch {
                Write-Log "Erreur mise à jour $($module.Name): $($_.Exception.Message)" -Level "WARN"
            }
        }
        
        Write-Log "✅ Modules PowerShell mis à jour" -Level "SUCCESS"
    }
    catch {
        Write-Log "Erreur lors de la mise à jour des modules PowerShell: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Show-UpdateSummary {
    Write-Log "=== RÉSUMÉ DES MISES À JOUR ===" -Level "SUCCESS"
    Write-Log "Mises à jour disponibles: $script:UpdatesAvailable"
    Write-Log "Mises à jour installées: $script:UpdatesInstalled"
    
    if ($script:RebootRequired) {
        Write-Log "⚠️  REDÉMARRAGE REQUIS pour finaliser les mises à jour" -Level "WARN"
        
        if ($RebootIfRequired -and -not $CheckOnly) {
            Write-Log "Redémarrage automatique dans 60 secondes..." -Level "WARN"
            Start-Sleep -Seconds 60
            Restart-Computer -Force
        }
    }
    
    if ($CheckOnly) {
        Write-Log "ℹ️  Mode vérification uniquement - Aucune installation effectuée" -Level "INFO"
    }
}

function Export-UpdateLog {
    if ($LogPath) {
        try {
            $script:UpdateLog | Out-File -FilePath $LogPath -Encoding UTF8
            Write-Log "Log exporté vers: $LogPath" -Level "SUCCESS"
        }
        catch {
            Write-Log "Erreur lors de l'export du log: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

# Script principal
try {
    Write-Log "🔄 Début des mises à jour système - Source: $UpdateSource" -Level "SUCCESS"
    
    # Vérifier les droits administrateur
    if (-not (Test-AdminRights)) {
        Write-Log "⚠️  Droits administrateur recommandés pour certaines mises à jour" -Level "WARN"
    }
    
    if ($CheckOnly) {
        Write-Log "ℹ️  MODE VÉRIFICATION UNIQUEMENT - Aucune installation ne sera effectuée" -Level "INFO"
    }
    
    Write-Log "Paramètres:"
    Write-Log "  - Source: $UpdateSource"
    Write-Log "  - Approbation automatique: $AutoApprove"
    Write-Log "  - Paquets exclus: $($ExcludePackages -join ', ')"
    Write-Log "  - Redémarrage auto: $RebootIfRequired"
    
    # Exécuter les mises à jour selon la source
    switch ($UpdateSource) {
        "All" {
            Update-WindowsSystem
            Update-ChocolateyPackages
            Update-WingetPackages
            Update-PowerShellModules
        }
        "WindowsUpdate" {
            Update-WindowsSystem
        }
        "Chocolatey" {
            Update-ChocolateyPackages
        }
        "Winget" {
            Update-WingetPackages
        }
        "PowerShell" {
            Update-PowerShellModules
        }
    }
    
    # Résumé
    Show-UpdateSummary
    
    # Export du log
    Export-UpdateLog
    
    Write-Log "Mises à jour terminées avec succès" -Level "SUCCESS"
}
catch {
    Write-Log "Erreur lors des mises à jour: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}