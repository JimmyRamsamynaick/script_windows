<#
.SYNOPSIS
    Nettoyage automatique de fichiers temporaires et inutiles sur Windows

.DESCRIPTION
    Ce script effectue un nettoyage complet du système Windows en supprimant :
    - Fichiers temporaires Windows (%TEMP%, %TMP%)
    - Cache des navigateurs (Chrome, Firefox, Edge)
    - Corbeille Windows
    - Fichiers de logs anciens
    - Cache Windows Update
    - Fichiers de prévisualisation
    - Historique et cookies (optionnel)

.PARAMETER Mode
    Mode de nettoyage: Quick (rapide), Full (complet), Custom (personnalisé)

.PARAMETER IncludeBrowserData
    Inclure les données des navigateurs (historique, cookies, cache)

.PARAMETER OlderThanDays
    Supprimer uniquement les fichiers plus anciens que X jours (défaut: 7)

.PARAMETER ExcludePaths
    Chemins à exclure du nettoyage

.PARAMETER LogPath
    Chemin pour le fichier de log du nettoyage

.PARAMETER WhatIf
    Mode simulation - affiche ce qui serait supprimé sans le faire

.EXAMPLE
    .\cleanFiles.ps1
    Nettoyage rapide standard

.EXAMPLE
    .\cleanFiles.ps1 -Mode Full -IncludeBrowserData -OlderThanDays 30
    Nettoyage complet incluant les données navigateur de plus de 30 jours

.EXAMPLE
    .\cleanFiles.ps1 -WhatIf
    Simulation du nettoyage sans suppression

.NOTES
    Auteur: Sameer
    Date: 28/10/2025
    Version: 1.0
    Prérequis: Droits administrateur recommandés
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Quick", "Full", "Custom")]
    [string]$Mode = "Quick",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeBrowserData,
    
    [Parameter(Mandatory=$false)]
    [int]$OlderThanDays = 7,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludePaths = @(),
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Configuration
$ErrorActionPreference = "Continue"
$VerbosePreference = "Continue"

# Variables globales
$script:TotalSpaceFreed = 0
$script:FilesDeleted = 0
$script:FoldersDeleted = 0
$script:CleanupLog = @()

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
    $script:CleanupLog += $logEntry
}

function Get-FolderSize {
    param([string]$Path)
    try {
        if (Test-Path $Path) {
            $size = (Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | 
                    Measure-Object -Property Length -Sum).Sum
            return [math]::Round($size / 1MB, 2)
        }
        return 0
    }
    catch {
        return 0
    }
}

function Remove-FilesOlderThan {
    param(
        [string]$Path,
        [int]$Days,
        [string]$Description,
        [string[]]$Extensions = @("*")
    )
    
    if (-not (Test-Path $Path)) {
        Write-Log "Chemin non trouvé: $Path" -Level "WARN"
        return
    }
    
    $cutoffDate = (Get-Date).AddDays(-$Days)
    $initialSize = Get-FolderSize -Path $Path
    
    Write-Log "Nettoyage: $Description ($Path)"
    
    try {
        foreach ($ext in $Extensions) {
            $files = Get-ChildItem -Path $Path -Filter "*.$ext" -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -lt $cutoffDate -and $_.FullName -notin $ExcludePaths }
            
            foreach ($file in $files) {
                try {
                    if ($WhatIf) {
                        Write-Log "  [SIMULATION] Suppression: $($file.FullName) ($([math]::Round($file.Length/1KB, 2)) KB)" -Level "INFO"
                    } else {
                        $fileSize = $file.Length
                        Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                        $script:TotalSpaceFreed += $fileSize
                        $script:FilesDeleted++
                        Write-Verbose "Supprimé: $($file.FullName)"
                    }
                }
                catch {
                    Write-Log "  Erreur suppression fichier: $($file.FullName) - $($_.Exception.Message)" -Level "WARN"
                }
            }
        }
        
        # Suppression des dossiers vides
        $emptyFolders = Get-ChildItem -Path $Path -Recurse -Directory -ErrorAction SilentlyContinue |
                       Where-Object { (Get-ChildItem -Path $_.FullName -ErrorAction SilentlyContinue).Count -eq 0 }
        
        foreach ($folder in $emptyFolders) {
            try {
                if ($WhatIf) {
                    Write-Log "  [SIMULATION] Suppression dossier vide: $($folder.FullName)" -Level "INFO"
                } else {
                    Remove-Item -Path $folder.FullName -Force -ErrorAction Stop
                    $script:FoldersDeleted++
                    Write-Verbose "Dossier vide supprimé: $($folder.FullName)"
                }
            }
            catch {
                Write-Log "  Erreur suppression dossier: $($folder.FullName) - $($_.Exception.Message)" -Level "WARN"
            }
        }
        
        $finalSize = Get-FolderSize -Path $Path
        $spaceFreed = $initialSize - $finalSize
        
        if ($spaceFreed -gt 0) {
            Write-Log "  ✅ Espace libéré: $spaceFreed MB" -Level "SUCCESS"
        }
    }
    catch {
        Write-Log "Erreur lors du nettoyage de $Path : $($_.Exception.Message)" -Level "ERROR"
    }
}

function Clear-WindowsTemp {
    Write-Log "=== Nettoyage des fichiers temporaires Windows ===" -Level "SUCCESS"
    
    # Dossiers temporaires système
    $tempPaths = @(
        $env:TEMP,
        $env:TMP,
        "$env:WINDIR\Temp",
        "$env:LOCALAPPDATA\Temp"
    )
    
    foreach ($tempPath in $tempPaths) {
        if ($tempPath) {
            Remove-FilesOlderThan -Path $tempPath -Days $OlderThanDays -Description "Fichiers temporaires ($tempPath)"
        }
    }
    
    # Fichiers de prévisualisation
    $thumbsPath = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
    if (Test-Path $thumbsPath) {
        Remove-FilesOlderThan -Path $thumbsPath -Days $OlderThanDays -Description "Cache de prévisualisation" -Extensions @("db")
    }
}

function Clear-RecycleBin {
    Write-Log "=== Vidage de la corbeille ===" -Level "SUCCESS"
    
    try {
        if ($WhatIf) {
            $recycleBinSize = (Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue | 
                             Measure-Object -Property Length -Sum).Sum
            Write-Log "[SIMULATION] Vidage corbeille: $([math]::Round($recycleBinSize/1MB, 2)) MB" -Level "INFO"
        } else {
            # Utilisation de l'API Windows pour vider la corbeille
            Add-Type -TypeDefinition @"
                using System;
                using System.Runtime.InteropServices;
                public class RecycleBin {
                    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
                    public static extern int SHEmptyRecycleBin(IntPtr hwnd, string pszRootPath, int dwFlags);
                }
"@
            $result = [RecycleBin]::SHEmptyRecycleBin([IntPtr]::Zero, $null, 0x00000001)
            if ($result -eq 0) {
                Write-Log "✅ Corbeille vidée avec succès" -Level "SUCCESS"
            } else {
                Write-Log "Erreur lors du vidage de la corbeille (Code: $result)" -Level "WARN"
            }
        }
    }
    catch {
        Write-Log "Erreur lors du vidage de la corbeille: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Clear-BrowserCache {
    if (-not $IncludeBrowserData) {
        Write-Log "Nettoyage des navigateurs ignoré (utilisez -IncludeBrowserData)" -Level "INFO"
        return
    }
    
    Write-Log "=== Nettoyage du cache des navigateurs ===" -Level "SUCCESS"
    
    # Chrome
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
    if (Test-Path $chromePath) {
        Remove-FilesOlderThan -Path $chromePath -Days $OlderThanDays -Description "Cache Google Chrome"
    }
    
    # Firefox
    $firefoxProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxProfiles) {
        $profiles = Get-ChildItem -Path $firefoxProfiles -Directory
        foreach ($profile in $profiles) {
            $cachePath = Join-Path $profile.FullName "cache2"
            if (Test-Path $cachePath) {
                Remove-FilesOlderThan -Path $cachePath -Days $OlderThanDays -Description "Cache Firefox ($($profile.Name))"
            }
        }
    }
    
    # Edge
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
    if (Test-Path $edgePath) {
        Remove-FilesOlderThan -Path $edgePath -Days $OlderThanDays -Description "Cache Microsoft Edge"
    }
}

function Clear-WindowsLogs {
    Write-Log "=== Nettoyage des logs Windows ===" -Level "SUCCESS"
    
    $logPaths = @(
        "$env:WINDIR\Logs",
        "$env:WINDIR\System32\LogFiles",
        "$env:LOCALAPPDATA\Microsoft\Windows\WebCache"
    )
    
    foreach ($logPath in $logPaths) {
        if (Test-Path $logPath) {
            Remove-FilesOlderThan -Path $logPath -Days $OlderThanDays -Description "Logs système ($logPath)" -Extensions @("log", "etl", "tmp")
        }
    }
}

function Clear-WindowsUpdate {
    Write-Log "=== Nettoyage du cache Windows Update ===" -Level "SUCCESS"
    
    try {
        if ($WhatIf) {
            Write-Log "[SIMULATION] Arrêt du service Windows Update" -Level "INFO"
            Write-Log "[SIMULATION] Nettoyage du cache SoftwareDistribution" -Level "INFO"
        } else {
            # Arrêter le service Windows Update
            Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
            
            # Nettoyer le cache
            $updateCachePath = "$env:WINDIR\SoftwareDistribution\Download"
            if (Test-Path $updateCachePath) {
                Remove-FilesOlderThan -Path $updateCachePath -Days $OlderThanDays -Description "Cache Windows Update"
            }
            
            # Redémarrer le service
            Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
            Write-Log "✅ Service Windows Update redémarré" -Level "SUCCESS"
        }
    }
    catch {
        Write-Log "Erreur lors du nettoyage Windows Update: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Clear-SystemCache {
    Write-Log "=== Nettoyage du cache système ===" -Level "SUCCESS"
    
    # DNS Cache
    try {
        if ($WhatIf) {
            Write-Log "[SIMULATION] Vidage du cache DNS" -Level "INFO"
        } else {
            Clear-DnsClientCache
            Write-Log "✅ Cache DNS vidé" -Level "SUCCESS"
        }
    }
    catch {
        Write-Log "Erreur lors du vidage du cache DNS: $($_.Exception.Message)" -Level "WARN"
    }
    
    # Prefetch
    $prefetchPath = "$env:WINDIR\Prefetch"
    if (Test-Path $prefetchPath) {
        Remove-FilesOlderThan -Path $prefetchPath -Days $OlderThanDays -Description "Fichiers Prefetch" -Extensions @("pf")
    }
}

function Show-CleanupSummary {
    Write-Log "=== RÉSUMÉ DU NETTOYAGE ===" -Level "SUCCESS"
    Write-Log "Fichiers supprimés: $script:FilesDeleted"
    Write-Log "Dossiers supprimés: $script:FoldersDeleted"
    Write-Log "Espace total libéré: $([math]::Round($script:TotalSpaceFreed / 1MB, 2)) MB"
    
    if ($WhatIf) {
        Write-Log "⚠️  Mode simulation activé - Aucune suppression effectuée" -Level "WARN"
    }
}

function Export-CleanupLog {
    if ($LogPath) {
        try {
            $script:CleanupLog | Out-File -FilePath $LogPath -Encoding UTF8
            Write-Log "Log exporté vers: $LogPath" -Level "SUCCESS"
        }
        catch {
            Write-Log "Erreur lors de l'export du log: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

# Script principal
try {
    Write-Log "🧹 Début du nettoyage système - Mode: $Mode" -Level "SUCCESS"
    
    if ($WhatIf) {
        Write-Log "⚠️  MODE SIMULATION ACTIVÉ - Aucune suppression ne sera effectuée" -Level "WARN"
    }
    
    Write-Log "Paramètres:"
    Write-Log "  - Mode: $Mode"
    Write-Log "  - Fichiers plus anciens que: $OlderThanDays jours"
    Write-Log "  - Inclure données navigateur: $IncludeBrowserData"
    Write-Log "  - Chemins exclus: $($ExcludePaths -join ', ')"
    
    # Nettoyage selon le mode
    switch ($Mode) {
        "Quick" {
            Clear-WindowsTemp
            Clear-RecycleBin
        }
        "Full" {
            Clear-WindowsTemp
            Clear-RecycleBin
            Clear-BrowserCache
            Clear-WindowsLogs
            Clear-SystemCache
        }
        "Custom" {
            # Interface interactive pour le mode personnalisé
            Write-Host "`nMode personnalisé - Sélectionnez les nettoyages à effectuer:" -ForegroundColor Yellow
            
            $choices = @(
                @{Name="Fichiers temporaires"; Action={Clear-WindowsTemp}},
                @{Name="Corbeille"; Action={Clear-RecycleBin}},
                @{Name="Cache navigateurs"; Action={Clear-BrowserCache}},
                @{Name="Logs Windows"; Action={Clear-WindowsLogs}},
                @{Name="Cache Windows Update"; Action={Clear-WindowsUpdate}},
                @{Name="Cache système"; Action={Clear-SystemCache}}
            )
            
            for ($i = 0; $i -lt $choices.Count; $i++) {
                $response = Read-Host "Effectuer: $($choices[$i].Name) ? (o/N)"
                if ($response -eq 'o' -or $response -eq 'O') {
                    & $choices[$i].Action
                }
            }
        }
    }
    
    # Nettoyage Windows Update en mode Full uniquement
    if ($Mode -eq "Full") {
        Clear-WindowsUpdate
    }
    
    # Résumé
    Show-CleanupSummary
    
    # Export du log
    Export-CleanupLog
    
    Write-Log "Nettoyage système terminé avec succès" -Level "SUCCESS"
}
catch {
    Write-Log "Erreur lors du nettoyage: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}