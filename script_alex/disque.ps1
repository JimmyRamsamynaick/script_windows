<#
.SYNOPSIS
    Vérification et rapport de l'espace disque sur Windows

.DESCRIPTION
    Ce script analyse l'utilisation de l'espace disque sur tous les lecteurs du système.
    Il fournit des rapports détaillés, des alertes pour les espaces faibles,
    et peut générer des recommandations de nettoyage.

    Fonctionnalités :
    - Analyse de tous les lecteurs locaux
    - Calcul des pourcentages d'utilisation
    - Alertes configurables pour espace faible
    - Analyse des dossiers volumineux
    - Recommandations de nettoyage
    - Export des rapports en CSV/HTML
    - Historique des mesures

.PARAMETER AlertThreshold
    Seuil d'alerte en pourcentage d'espace libre (défaut: 10%)

.PARAMETER IncludeNetworkDrives
    Inclure les lecteurs réseau dans l'analyse

.PARAMETER DetailedAnalysis
    Effectuer une analyse détaillée des dossiers volumineux

.PARAMETER ExportFormat
    Format d'export du rapport: None, CSV, HTML, JSON

.PARAMETER OutputPath
    Chemin de sortie pour les rapports exportés

.PARAMETER ShowRecommendations
    Afficher les recommandations de nettoyage

.PARAMETER HistoryDays
    Nombre de jours d'historique à conserver (défaut: 30)

.EXAMPLE
    .\disque.ps1
    Analyse de base de tous les lecteurs locaux

.EXAMPLE
    .\disque.ps1 -AlertThreshold 5 -DetailedAnalysis
    Analyse détaillée avec seuil d'alerte à 5%

.EXAMPLE
    .\disque.ps1 -ExportFormat HTML -OutputPath "C:\Reports"
    Génère un rapport HTML dans le dossier spécifié

.NOTES
    Auteur: Alex
    Date: 28/10/2025
    Version: 1.0
    
    Prérequis:
    - PowerShell 5.1 ou supérieur
    - Droits de lecture sur les lecteurs à analyser
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, HelpMessage="Seuil d'alerte en pourcentage d'espace libre")]
    [ValidateRange(1, 50)]
    [int]$AlertThreshold = 10,
    
    [Parameter(Mandatory=$false, HelpMessage="Inclure les lecteurs réseau")]
    [switch]$IncludeNetworkDrives,
    
    [Parameter(Mandatory=$false, HelpMessage="Analyse détaillée des dossiers")]
    [switch]$DetailedAnalysis,
    
    [Parameter(Mandatory=$false, HelpMessage="Format d'export")]
    [ValidateSet("None", "CSV", "HTML", "JSON")]
    [string]$ExportFormat = "None",
    
    [Parameter(Mandatory=$false, HelpMessage="Chemin de sortie pour les rapports")]
    [string]$OutputPath = ".",
    
    [Parameter(Mandatory=$false, HelpMessage="Afficher les recommandations")]
    [switch]$ShowRecommendations,
    
    [Parameter(Mandatory=$false, HelpMessage="Jours d'historique à conserver")]
    [ValidateRange(1, 365)]
    [int]$HistoryDays = 30
)

# Configuration
$ErrorActionPreference = "Stop"
$script:ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
$script:LogPath = Join-Path $OutputPath "$($script:ScriptName)_$(Get-Date -Format 'yyyyMMdd').log"

# Fonctions utilitaires
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
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
    
    try {
        $logEntry | Out-File -FilePath $script:LogPath -Append -Encoding UTF8
    }
    catch {
        Write-Warning "Impossible d'écrire dans le log: $($_.Exception.Message)"
    }
}

function Format-FileSize {
    param([long]$Size)
    
    $units = @("B", "KB", "MB", "GB", "TB", "PB")
    $unitIndex = 0
    $sizeValue = [double]$Size
    
    while ($sizeValue -ge 1024 -and $unitIndex -lt ($units.Length - 1)) {
        $sizeValue /= 1024
        $unitIndex++
    }
    
    return "{0:N2} {1}" -f $sizeValue, $units[$unitIndex]
}

function Get-DiskInfo {
    Write-Log "Collecte des informations sur les disques..."
    
    try {
        $driveTypes = @{
            2 = "Lecteur amovible"
            3 = "Disque dur local"
            4 = "Lecteur réseau"
            5 = "CD-ROM"
            6 = "RAM Disk"
        }
        
        $filter = if ($IncludeNetworkDrives) { 
            { $_.DriveType -in @(2, 3, 4) } 
        } else { 
            { $_.DriveType -eq 3 } 
        }
        
        $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object $filter
        $diskInfo = @()
        
        foreach ($drive in $drives) {
            $freeSpacePercent = if ($drive.Size -gt 0) { 
                [math]::Round(($drive.FreeSpace / $drive.Size) * 100, 2) 
            } else { 0 }
            
            $usedSpace = $drive.Size - $drive.FreeSpace
            $usedSpacePercent = if ($drive.Size -gt 0) { 
                [math]::Round(($usedSpace / $drive.Size) * 100, 2) 
            } else { 0 }
            
            $status = if ($freeSpacePercent -le $AlertThreshold) { "CRITIQUE" }
                     elseif ($freeSpacePercent -le ($AlertThreshold * 2)) { "ATTENTION" }
                     else { "OK" }
            
            $diskInfo += [PSCustomObject]@{
                Lecteur = $drive.DeviceID
                Label = $drive.VolumeName
                Type = $driveTypes[$drive.DriveType]
                TailleTotal = Format-FileSize $drive.Size
                TailleTotalBytes = $drive.Size
                EspaceUtilise = Format-FileSize $usedSpace
                EspaceUtiliseBytes = $usedSpace
                EspaceLibre = Format-FileSize $drive.FreeSpace
                EspaceLibreBytes = $drive.FreeSpace
                PourcentageUtilise = $usedSpacePercent
                PourcentageLibre = $freeSpacePercent
                Statut = $status
                SystemeDeFichiers = $drive.FileSystem
            }
        }
        
        Write-Log "Informations collectées pour $($diskInfo.Count) lecteur(s)" -Level "SUCCESS"
        return $diskInfo
    }
    catch {
        Write-Log "Erreur lors de la collecte des informations disque: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Get-LargestFolders {
    param(
        [string]$DriveLetter,
        [int]$TopCount = 10
    )
    
    Write-Log "Analyse des dossiers volumineux sur $DriveLetter..."
    
    try {
        $rootPath = "$DriveLetter\"
        $folders = @()
        
        # Obtenir les dossiers de premier niveau
        $topLevelFolders = Get-ChildItem -Path $rootPath -Directory -ErrorAction SilentlyContinue
        
        foreach ($folder in $topLevelFolders) {
            try {
                $size = (Get-ChildItem -Path $folder.FullName -Recurse -File -ErrorAction SilentlyContinue | 
                        Measure-Object -Property Length -Sum).Sum
                
                if ($size -gt 0) {
                    $folders += [PSCustomObject]@{
                        Chemin = $folder.FullName
                        Nom = $folder.Name
                        Taille = Format-FileSize $size
                        TailleBytes = $size
                        NombreFichiers = (Get-ChildItem -Path $folder.FullName -Recurse -File -ErrorAction SilentlyContinue).Count
                    }
                }
            }
            catch {
                Write-Log "Impossible d'analyser le dossier $($folder.FullName): $($_.Exception.Message)" -Level "WARN"
            }
        }
        
        $topFolders = $folders | Sort-Object TailleBytes -Descending | Select-Object -First $TopCount
        Write-Log "Analyse terminée: $($topFolders.Count) dossiers analysés" -Level "SUCCESS"
        
        return $topFolders
    }
    catch {
        Write-Log "Erreur lors de l'analyse des dossiers: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Get-CleanupRecommendations {
    param([array]$DiskInfo)
    
    Write-Log "Génération des recommandations de nettoyage..."
    
    $recommendations = @()
    
    # Dossiers temporaires Windows
    $tempPaths = @(
        @{Path = "$env:TEMP"; Description = "Fichiers temporaires utilisateur"},
        @{Path = "$env:WINDIR\Temp"; Description = "Fichiers temporaires système"},
        @{Path = "$env:WINDIR\Prefetch"; Description = "Fichiers de préchargement"},
        @{Path = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"; Description = "Cache Internet Explorer"},
        @{Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"; Description = "Cache Google Chrome"},
        @{Path = "$env:APPDATA\Mozilla\Firefox\Profiles\*\cache2"; Description = "Cache Firefox"}
    )
    
    foreach ($path in $tempPaths) {
        try {
            if (Test-Path $path.Path) {
                $size = (Get-ChildItem -Path $path.Path -Recurse -File -ErrorAction SilentlyContinue | 
                        Measure-Object -Property Length -Sum).Sum
                
                if ($size -gt 100MB) {  # Seulement si > 100MB
                    $recommendations += [PSCustomObject]@{
                        Type = "Nettoyage"
                        Chemin = $path.Path
                        Description = $path.Description
                        TailleEstimee = Format-FileSize $size
                        TailleBytes = $size
                        Priorite = if ($size -gt 1GB) { "Haute" } elseif ($size -gt 500MB) { "Moyenne" } else { "Basse" }
                    }
                }
            }
        }
        catch {
            # Ignorer les erreurs d'accès
        }
    }
    
    # Recommandations pour les disques critiques
    foreach ($disk in ($DiskInfo | Where-Object { $_.Statut -eq "CRITIQUE" })) {
        $recommendations += [PSCustomObject]@{
            Type = "Alerte"
            Chemin = $disk.Lecteur
            Description = "Espace disque critique - Action immédiate requise"
            TailleEstimee = "N/A"
            TailleBytes = 0
            Priorite = "Critique"
        }
    }
    
    Write-Log "Recommandations générées: $($recommendations.Count)" -Level "SUCCESS"
    return $recommendations | Sort-Object TailleBytes -Descending
}

function Export-Report {
    param(
        [array]$DiskInfo,
        [array]$DetailedInfo = @(),
        [array]$Recommendations = @(),
        [string]$Format,
        [string]$OutputPath
    )
    
    if ($Format -eq "None") { return }
    
    Write-Log "Export du rapport en format $Format..."
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $baseFileName = "rapport_disque_$timestamp"
    
    try {
        switch ($Format) {
            "CSV" {
                $csvPath = Join-Path $OutputPath "$baseFileName.csv"
                $DiskInfo | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                Write-Log "Rapport CSV exporté: $csvPath" -Level "SUCCESS"
            }
            
            "JSON" {
                $jsonPath = Join-Path $OutputPath "$baseFileName.json"
                $reportData = @{
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    DiskInfo = $DiskInfo
                    DetailedInfo = $DetailedInfo
                    Recommendations = $Recommendations
                }
                $reportData | ConvertTo-Json -Depth 3 | Out-File -FilePath $jsonPath -Encoding UTF8
                Write-Log "Rapport JSON exporté: $jsonPath" -Level "SUCCESS"
            }
            
            "HTML" {
                $htmlPath = Join-Path $OutputPath "$baseFileName.html"
                $html = Generate-HTMLReport -DiskInfo $DiskInfo -DetailedInfo $DetailedInfo -Recommendations $Recommendations
                $html | Out-File -FilePath $htmlPath -Encoding UTF8
                Write-Log "Rapport HTML exporté: $htmlPath" -Level "SUCCESS"
            }
        }
    }
    catch {
        Write-Log "Erreur lors de l'export: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Generate-HTMLReport {
    param(
        [array]$DiskInfo,
        [array]$DetailedInfo,
        [array]$Recommendations
    )
    
    $html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'Analyse Disque - $(Get-Date -Format 'dd/MM/yyyy HH:mm')</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1, h2 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #007acc; color: white; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-attention { color: #ffc107; font-weight: bold; }
        .status-critique { color: #dc3545; font-weight: bold; }
        .progress-bar { width: 100%; height: 20px; background-color: #e9ecef; border-radius: 10px; overflow: hidden; }
        .progress-fill { height: 100%; transition: width 0.3s ease; }
        .progress-ok { background-color: #28a745; }
        .progress-attention { background-color: #ffc107; }
        .progress-critique { background-color: #dc3545; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .summary-card { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #007acc; }
        .summary-card h3 { margin-top: 0; color: #007acc; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 Rapport d'Analyse Disque</h1>
        <p><strong>Généré le:</strong> $(Get-Date -Format 'dd/MM/yyyy à HH:mm:ss')</p>
        <p><strong>Ordinateur:</strong> $env:COMPUTERNAME</p>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Nombre de lecteurs</h3>
                <p style="font-size: 2em; margin: 0; color: #007acc;">$($DiskInfo.Count)</p>
            </div>
            <div class="summary-card">
                <h3>Espace total</h3>
                <p style="font-size: 1.5em; margin: 0;">$(Format-FileSize ($DiskInfo | Measure-Object TailleTotalBytes -Sum).Sum)</p>
            </div>
            <div class="summary-card">
                <h3>Espace libre</h3>
                <p style="font-size: 1.5em; margin: 0;">$(Format-FileSize ($DiskInfo | Measure-Object EspaceLibreBytes -Sum).Sum)</p>
            </div>
            <div class="summary-card">
                <h3>Alertes</h3>
                <p style="font-size: 2em; margin: 0; color: #dc3545;">$(($DiskInfo | Where-Object { $_.Statut -ne "OK" }).Count)</p>
            </div>
        </div>

        <h2>📋 Détail des Lecteurs</h2>
        <table>
            <thead>
                <tr>
                    <th>Lecteur</th>
                    <th>Label</th>
                    <th>Type</th>
                    <th>Taille Total</th>
                    <th>Espace Utilisé</th>
                    <th>Espace Libre</th>
                    <th>Utilisation</th>
                    <th>Statut</th>
                </tr>
            </thead>
            <tbody>
"@

    foreach ($disk in $DiskInfo) {
        $statusClass = switch ($disk.Statut) {
            "OK" { "status-ok" }
            "ATTENTION" { "status-attention" }
            "CRITIQUE" { "status-critique" }
        }
        
        $progressClass = switch ($disk.Statut) {
            "OK" { "progress-ok" }
            "ATTENTION" { "progress-attention" }
            "CRITIQUE" { "progress-critique" }
        }
        
        $html += @"
                <tr>
                    <td><strong>$($disk.Lecteur)</strong></td>
                    <td>$($disk.Label)</td>
                    <td>$($disk.Type)</td>
                    <td>$($disk.TailleTotal)</td>
                    <td>$($disk.EspaceUtilise)</td>
                    <td>$($disk.EspaceLibre)</td>
                    <td>
                        <div class="progress-bar">
                            <div class="progress-fill $progressClass" style="width: $($disk.PourcentageUtilise)%"></div>
                        </div>
                        $($disk.PourcentageUtilise)%
                    </td>
                    <td><span class="$statusClass">$($disk.Statut)</span></td>
                </tr>
"@
    }

    $html += @"
            </tbody>
        </table>
"@

    if ($Recommendations.Count -gt 0) {
        $html += @"
        <h2>💡 Recommandations</h2>
        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Chemin</th>
                    <th>Taille Estimée</th>
                    <th>Priorité</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($rec in $Recommendations) {
            $html += @"
                <tr>
                    <td>$($rec.Type)</td>
                    <td>$($rec.Description)</td>
                    <td><code>$($rec.Chemin)</code></td>
                    <td>$($rec.TailleEstimee)</td>
                    <td>$($rec.Priorite)</td>
                </tr>
"@
        }
        
        $html += @"
            </tbody>
        </table>
"@
    }

    $html += @"
        <hr style="margin: 40px 0;">
        <p style="text-align: center; color: #666; font-size: 0.9em;">
            Rapport généré par le script disque.ps1 - Alex © 2025
        </p>
    </div>
</body>
</html>
"@

    return $html
}

function Show-DiskSummary {
    param([array]$DiskInfo)
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "📊 RÉSUMÉ DE L'ANALYSE DISQUE" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor Cyan
    
    $totalSpace = ($DiskInfo | Measure-Object TailleTotalBytes -Sum).Sum
    $totalFree = ($DiskInfo | Measure-Object EspaceLibreBytes -Sum).Sum
    $totalUsed = $totalSpace - $totalFree
    
    Write-Host "🖥️  Ordinateur: $env:COMPUTERNAME" -ForegroundColor Green
    Write-Host "📅 Date: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -ForegroundColor Green
    Write-Host "💾 Nombre de lecteurs analysés: $($DiskInfo.Count)" -ForegroundColor Green
    Write-Host ""
    Write-Host "📊 ESPACE GLOBAL:" -ForegroundColor Yellow
    Write-Host "   Total: $(Format-FileSize $totalSpace)" -ForegroundColor White
    Write-Host "   Utilisé: $(Format-FileSize $totalUsed) ($([math]::Round(($totalUsed/$totalSpace)*100,1))%)" -ForegroundColor White
    Write-Host "   Libre: $(Format-FileSize $totalFree) ($([math]::Round(($totalFree/$totalSpace)*100,1))%)" -ForegroundColor White
    
    # Alertes
    $criticalDisks = $DiskInfo | Where-Object { $_.Statut -eq "CRITIQUE" }
    $warningDisks = $DiskInfo | Where-Object { $_.Statut -eq "ATTENTION" }
    
    if ($criticalDisks.Count -gt 0) {
        Write-Host "`n🚨 ALERTES CRITIQUES:" -ForegroundColor Red
        foreach ($disk in $criticalDisks) {
            Write-Host "   $($disk.Lecteur) - $($disk.PourcentageLibre)% libre ($($disk.EspaceLibre))" -ForegroundColor Red
        }
    }
    
    if ($warningDisks.Count -gt 0) {
        Write-Host "`n⚠️  ALERTES ATTENTION:" -ForegroundColor Yellow
        foreach ($disk in $warningDisks) {
            Write-Host "   $($disk.Lecteur) - $($disk.PourcentageLibre)% libre ($($disk.EspaceLibre))" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
}

# Script principal
try {
    Write-Log "🚀 Début de l'analyse disque" -Level "SUCCESS"
    Write-Log "Seuil d'alerte: $AlertThreshold% | Analyse détaillée: $DetailedAnalysis | Export: $ExportFormat"
    
    # Collecte des informations disque
    $diskInfo = Get-DiskInfo
    
    # Affichage du résumé
    Show-DiskSummary -DiskInfo $diskInfo
    
    # Affichage détaillé
    Write-Host "`n📋 DÉTAIL PAR LECTEUR:" -ForegroundColor Cyan
    $diskInfo | Format-Table -Property Lecteur, Label, Type, TailleTotal, EspaceUtilise, EspaceLibre, PourcentageLibre, Statut -AutoSize
    
    # Analyse détaillée si demandée
    $detailedInfo = @()
    if ($DetailedAnalysis) {
        Write-Host "`n🔍 ANALYSE DÉTAILLÉE DES DOSSIERS VOLUMINEUX:" -ForegroundColor Cyan
        foreach ($disk in ($diskInfo | Where-Object { $_.Type -eq "Disque dur local" })) {
            $driveLetter = $disk.Lecteur.Replace(":", "")
            Write-Host "`n--- Lecteur $($disk.Lecteur) ---" -ForegroundColor Yellow
            
            $largeFolders = Get-LargestFolders -DriveLetter $driveLetter -TopCount 10
            if ($largeFolders.Count -gt 0) {
                $largeFolders | Format-Table -Property Nom, Taille, NombreFichiers -AutoSize
                $detailedInfo += $largeFolders
            } else {
                Write-Host "Aucun dossier volumineux trouvé ou accès refusé" -ForegroundColor Gray
            }
        }
    }
    
    # Recommandations si demandées
    $recommendations = @()
    if ($ShowRecommendations) {
        Write-Host "`n💡 RECOMMANDATIONS DE NETTOYAGE:" -ForegroundColor Cyan
        $recommendations = Get-CleanupRecommendations -DiskInfo $diskInfo
        
        if ($recommendations.Count -gt 0) {
            $recommendations | Format-Table -Property Type, Description, TailleEstimee, Priorite -AutoSize
        } else {
            Write-Host "Aucune recommandation de nettoyage disponible" -ForegroundColor Green
        }
    }
    
    # Export si demandé
    if ($ExportFormat -ne "None") {
        Export-Report -DiskInfo $diskInfo -DetailedInfo $detailedInfo -Recommendations $recommendations -Format $ExportFormat -OutputPath $OutputPath
    }
    
    Write-Log "✅ Analyse terminée avec succès" -Level "SUCCESS"
    
    # Résumé final
    $criticalCount = ($diskInfo | Where-Object { $_.Statut -eq "CRITIQUE" }).Count
    $warningCount = ($diskInfo | Where-Object { $_.Statut -eq "ATTENTION" }).Count
    
    if ($criticalCount -gt 0) {
        Write-Host "`n🚨 ACTION REQUISE: $criticalCount lecteur(s) en état critique!" -ForegroundColor Red
        exit 2
    } elseif ($warningCount -gt 0) {
        Write-Host "`n⚠️  SURVEILLANCE: $warningCount lecteur(s) nécessitent une attention" -ForegroundColor Yellow
        exit 1
    } else {
        Write-Host "`n✅ Tous les lecteurs sont en bon état" -ForegroundColor Green
        exit 0
    }
}
catch {
    Write-Log "Erreur fatale: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Ligne: $($_.InvocationInfo.ScriptLineNumber)" -Level "ERROR"
    exit 1
}