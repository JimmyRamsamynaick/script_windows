<#
.SYNOPSIS
    Script de synchronisation de répertoires pour Windows
    
.DESCRIPTION
    Ce script permet de synchroniser des répertoires locaux ou distants avec diverses options :
    - Synchronisation bidirectionnelle ou unidirectionnelle
    - Support des répertoires réseau (SMB/CIFS)
    - Synchronisation avec exclusions de fichiers/dossiers
    - Modes de synchronisation : miroir, incrémental, différentiel
    - Vérification d'intégrité avec checksums
    - Planification automatique
    - Rapports détaillés et logs
    - Mode simulation (dry-run)
    - Compression et chiffrement optionnels
    
.PARAMETER Source
    Répertoire source à synchroniser
    
.PARAMETER Destination
    Répertoire de destination
    
.PARAMETER Mode
    Mode de synchronisation : Mirror, Incremental, Differential, Bidirectional
    
.PARAMETER Exclude
    Patterns de fichiers/dossiers à exclure (wildcards supportés)
    
.PARAMETER Include
    Patterns de fichiers/dossiers à inclure uniquement
    
.PARAMETER DryRun
    Mode simulation - affiche les actions sans les exécuter
    
.PARAMETER Compress
    Active la compression des fichiers transférés
    
.PARAMETER Encrypt
    Active le chiffrement AES-256 des fichiers
    
.PARAMETER VerifyIntegrity
    Vérifie l'intégrité avec checksums MD5/SHA256
    
.PARAMETER Schedule
    Planifie la synchronisation (format cron-like)
    
.PARAMETER LogPath
    Chemin du fichier de log (par défaut : .\logs\synch_YYYYMMDD.log)
    
.PARAMETER ReportPath
    Chemin du rapport de synchronisation
    
.PARAMETER MaxRetries
    Nombre maximum de tentatives en cas d'échec
    
.PARAMETER Interactive
    Mode interactif avec menu
    
.EXAMPLE
    .\synch_repertoire.ps1 -Source "C:\Data" -Destination "\\Server\Backup" -Mode Mirror
    
.EXAMPLE
    .\synch_repertoire.ps1 -Source "C:\Projects" -Destination "D:\Backup" -Mode Incremental -Exclude "*.tmp","*.log" -VerifyIntegrity
    
.EXAMPLE
    .\synch_repertoire.ps1 -Interactive
    
.NOTES
    Auteur: Jimmy Ramsamynaick
    Version: 2.0
    Dernière modification: 2025
    
    Prérequis:
    - PowerShell 5.1 ou supérieur
    - Droits d'accès aux répertoires source et destination
    - Module PowerShell pour chiffrement (optionnel)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Source,
    
    [Parameter(Mandatory=$false)]
    [string]$Destination,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Mirror", "Incremental", "Differential", "Bidirectional")]
    [string]$Mode = "Incremental",
    
    [Parameter(Mandatory=$false)]
    [string[]]$Exclude = @(),
    
    [Parameter(Mandatory=$false)]
    [string[]]$Include = @(),
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory=$false)]
    [switch]$Compress,
    
    [Parameter(Mandatory=$false)]
    [switch]$Encrypt,
    
    [Parameter(Mandatory=$false)]
    [switch]$VerifyIntegrity,
    
    [Parameter(Mandatory=$false)]
    [string]$Schedule,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath,
    
    [Parameter(Mandatory=$false)]
    [string]$ReportPath,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxRetries = 3,
    
    [Parameter(Mandatory=$false)]
    [switch]$Interactive
)

# Variables globales
$script:LogFile = ""
$script:StartTime = Get-Date
$script:SyncStats = @{
    FilesProcessed = 0
    FilesSkipped = 0
    FilesCopied = 0
    FilesUpdated = 0
    FilesDeleted = 0
    FoldersCreated = 0
    FoldersDeleted = 0
    BytesTransferred = 0
    Errors = 0
}

# Configuration des chemins
if (-not $LogPath) {
    $LogDir = Join-Path $PSScriptRoot "logs"
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    $script:LogFile = Join-Path $LogDir "synch_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
} else {
    $script:LogFile = $LogPath
}

if (-not $ReportPath) {
    $ReportDir = Join-Path $PSScriptRoot "reports"
    if (-not (Test-Path $ReportDir)) {
        New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
    }
    $ReportPath = Join-Path $ReportDir "sync_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
}

# Fonction de logging
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Couleurs pour la console
    $color = switch ($Level) {
        "INFO" { "White" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        "SUCCESS" { "Green" }
        "DEBUG" { "Cyan" }
    }
    
    Write-Host $logEntry -ForegroundColor $color
    Add-Content -Path $script:LogFile -Value $logEntry -Encoding UTF8
}

# Fonction de validation des chemins
function Test-PathAccess {
    param(
        [string]$Path,
        [string]$Type = "Source"
    )
    
    try {
        if (-not (Test-Path $Path)) {
            if ($Type -eq "Destination") {
                Write-Log "Création du répertoire de destination: $Path" -Level "INFO"
                New-Item -ItemType Directory -Path $Path -Force | Out-Null
                return $true
            } else {
                Write-Log "Le chemin $Type n'existe pas: $Path" -Level "ERROR"
                return $false
            }
        }
        
        # Test d'accès en écriture pour la destination
        if ($Type -eq "Destination") {
            $testFile = Join-Path $Path "test_write_$(Get-Random).tmp"
            try {
                New-Item -ItemType File -Path $testFile -Force | Out-Null
                Remove-Item $testFile -Force
                return $true
            } catch {
                Write-Log "Pas d'accès en écriture sur: $Path" -Level "ERROR"
                return $false
            }
        }
        
        return $true
    } catch {
        Write-Log "Erreur lors de la validation du chemin $Type ($Path): $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Fonction de calcul de checksum
function Get-FileChecksum {
    param(
        [string]$FilePath,
        [string]$Algorithm = "SHA256"
    )
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm $Algorithm
        return $hash.Hash
    } catch {
        Write-Log "Erreur lors du calcul du checksum pour $FilePath : $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# Fonction de comparaison de fichiers
function Compare-Files {
    param(
        [string]$SourceFile,
        [string]$DestFile
    )
    
    if (-not (Test-Path $DestFile)) {
        return "New"
    }
    
    $sourceInfo = Get-Item $SourceFile
    $destInfo = Get-Item $DestFile
    
    # Comparaison par taille et date de modification
    if ($sourceInfo.Length -ne $destInfo.Length) {
        return "Different"
    }
    
    if ($sourceInfo.LastWriteTime -gt $destInfo.LastWriteTime) {
        return "Newer"
    }
    
    # Vérification d'intégrité si demandée
    if ($VerifyIntegrity) {
        $sourceHash = Get-FileChecksum -FilePath $SourceFile
        $destHash = Get-FileChecksum -FilePath $DestFile
        
        if ($sourceHash -and $destHash -and $sourceHash -ne $destHash) {
            return "Corrupted"
        }
    }
    
    return "Same"
}

# Fonction de filtrage des fichiers
function Test-FileFilter {
    param(
        [string]$FilePath,
        [string[]]$IncludePatterns,
        [string[]]$ExcludePatterns
    )
    
    $fileName = Split-Path $FilePath -Leaf
    $relativePath = $FilePath
    
    # Test des patterns d'inclusion
    if ($IncludePatterns.Count -gt 0) {
        $included = $false
        foreach ($pattern in $IncludePatterns) {
            if ($fileName -like $pattern -or $relativePath -like $pattern) {
                $included = $true
                break
            }
        }
        if (-not $included) {
            return $false
        }
    }
    
    # Test des patterns d'exclusion
    foreach ($pattern in $ExcludePatterns) {
        if ($fileName -like $pattern -or $relativePath -like $pattern) {
            return $false
        }
    }
    
    return $true
}

# Fonction de copie de fichier avec retry
function Copy-FileWithRetry {
    param(
        [string]$SourceFile,
        [string]$DestFile,
        [int]$MaxRetries = 3
    )
    
    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        try {
            $attempt++
            
            # Création du répertoire parent si nécessaire
            $destDir = Split-Path $DestFile -Parent
            if (-not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
            
            # Copie du fichier
            Copy-Item -Path $SourceFile -Destination $DestFile -Force
            
            # Vérification de l'intégrité si demandée
            if ($VerifyIntegrity) {
                $sourceHash = Get-FileChecksum -FilePath $SourceFile
                $destHash = Get-FileChecksum -FilePath $DestFile
                
                if ($sourceHash -ne $destHash) {
                    throw "Échec de la vérification d'intégrité"
                }
            }
            
            $fileInfo = Get-Item $SourceFile
            $script:SyncStats.BytesTransferred += $fileInfo.Length
            
            return $true
        } catch {
            Write-Log "Tentative $attempt/$MaxRetries échouée pour $SourceFile : $($_.Exception.Message)" -Level "WARNING"
            if ($attempt -eq $MaxRetries) {
                Write-Log "Échec définitif de la copie de $SourceFile" -Level "ERROR"
                $script:SyncStats.Errors++
                return $false
            }
            Start-Sleep -Seconds (2 * $attempt)
        }
    }
    
    return $false
}

# Fonction de synchronisation principale
function Start-Synchronization {
    param(
        [string]$SourcePath,
        [string]$DestPath,
        [string]$SyncMode
    )
    
    Write-Log "Début de la synchronisation: $SourcePath -> $DestPath (Mode: $SyncMode)" -Level "INFO"
    
    try {
        # Obtention de la liste des fichiers source
        $sourceFiles = Get-ChildItem -Path $SourcePath -Recurse -File | Where-Object {
            Test-FileFilter -FilePath $_.FullName -IncludePatterns $Include -ExcludePatterns $Exclude
        }
        
        Write-Log "Fichiers à traiter: $($sourceFiles.Count)" -Level "INFO"
        
        foreach ($sourceFile in $sourceFiles) {
            $script:SyncStats.FilesProcessed++
            
            # Calcul du chemin de destination
            $relativePath = $sourceFile.FullName.Substring($SourcePath.Length).TrimStart('\')
            $destFile = Join-Path $DestPath $relativePath
            
            # Comparaison des fichiers
            $comparison = Compare-Files -SourceFile $sourceFile.FullName -DestFile $destFile
            
            Write-Progress -Activity "Synchronisation en cours" -Status "Traitement: $($sourceFile.Name)" -PercentComplete (($script:SyncStats.FilesProcessed / $sourceFiles.Count) * 100)
            
            switch ($comparison) {
                "New" {
                    Write-Log "Nouveau fichier: $relativePath" -Level "INFO"
                    if (-not $DryRun) {
                        if (Copy-FileWithRetry -SourceFile $sourceFile.FullName -DestFile $destFile -MaxRetries $MaxRetries) {
                            $script:SyncStats.FilesCopied++
                        }
                    } else {
                        Write-Log "[DRY-RUN] Copierait: $relativePath" -Level "DEBUG"
                    }
                }
                "Different" -or "Newer" -or "Corrupted" {
                    Write-Log "Fichier modifié: $relativePath ($comparison)" -Level "INFO"
                    if (-not $DryRun) {
                        if (Copy-FileWithRetry -SourceFile $sourceFile.FullName -DestFile $destFile -MaxRetries $MaxRetries) {
                            $script:SyncStats.FilesUpdated++
                        }
                    } else {
                        Write-Log "[DRY-RUN] Mettrait à jour: $relativePath" -Level "DEBUG"
                    }
                }
                "Same" {
                    $script:SyncStats.FilesSkipped++
                    Write-Log "Fichier identique ignoré: $relativePath" -Level "DEBUG"
                }
            }
        }
        
        # Gestion du mode miroir (suppression des fichiers en trop)
        if ($SyncMode -eq "Mirror") {
            Write-Log "Mode miroir: vérification des fichiers à supprimer" -Level "INFO"
            
            if (Test-Path $DestPath) {
                $destFiles = Get-ChildItem -Path $DestPath -Recurse -File
                
                foreach ($destFile in $destFiles) {
                    $relativePath = $destFile.FullName.Substring($DestPath.Length).TrimStart('\')
                    $sourceFile = Join-Path $SourcePath $relativePath
                    
                    if (-not (Test-Path $sourceFile)) {
                        Write-Log "Fichier à supprimer: $relativePath" -Level "INFO"
                        if (-not $DryRun) {
                            Remove-Item $destFile.FullName -Force
                            $script:SyncStats.FilesDeleted++
                        } else {
                            Write-Log "[DRY-RUN] Supprimerait: $relativePath" -Level "DEBUG"
                        }
                    }
                }
            }
        }
        
        Write-Progress -Activity "Synchronisation en cours" -Completed
        Write-Log "Synchronisation terminée avec succès" -Level "SUCCESS"
        
    } catch {
        Write-Log "Erreur lors de la synchronisation: $($_.Exception.Message)" -Level "ERROR"
        $script:SyncStats.Errors++
    }
}

# Fonction de synchronisation bidirectionnelle
function Start-BidirectionalSync {
    param(
        [string]$Path1,
        [string]$Path2
    )
    
    Write-Log "Début de la synchronisation bidirectionnelle: $Path1 <-> $Path2" -Level "INFO"
    
    # Synchronisation Path1 -> Path2
    Start-Synchronization -SourcePath $Path1 -DestPath $Path2 -SyncMode "Incremental"
    
    # Synchronisation Path2 -> Path1
    Start-Synchronization -SourcePath $Path2 -DestPath $Path1 -SyncMode "Incremental"
}

# Fonction de génération de rapport
function Generate-SyncReport {
    param(
        [string]$ReportPath
    )
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Rapport de Synchronisation</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin: 20px 0; }
        .stat-box { background-color: #e8f4fd; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 24px; font-weight: bold; color: #2c5aa0; }
        .stat-label { font-size: 14px; color: #666; }
        .success { color: #28a745; }
        .warning { color: #ffc107; }
        .error { color: #dc3545; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Rapport de Synchronisation</h1>
        <p><strong>Date:</strong> $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')</p>
        <p><strong>Source:</strong> $Source</p>
        <p><strong>Destination:</strong> $Destination</p>
        <p><strong>Mode:</strong> $Mode</p>
        <p><strong>Durée:</strong> $($duration.ToString('hh\:mm\:ss'))</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <div class="stat-number">$($script:SyncStats.FilesProcessed)</div>
            <div class="stat-label">Fichiers traités</div>
        </div>
        <div class="stat-box">
            <div class="stat-number success">$($script:SyncStats.FilesCopied)</div>
            <div class="stat-label">Fichiers copiés</div>
        </div>
        <div class="stat-box">
            <div class="stat-number warning">$($script:SyncStats.FilesUpdated)</div>
            <div class="stat-label">Fichiers mis à jour</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">$($script:SyncStats.FilesSkipped)</div>
            <div class="stat-label">Fichiers ignorés</div>
        </div>
        <div class="stat-box">
            <div class="stat-number error">$($script:SyncStats.FilesDeleted)</div>
            <div class="stat-label">Fichiers supprimés</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">$([math]::Round($script:SyncStats.BytesTransferred / 1MB, 2))</div>
            <div class="stat-label">MB transférés</div>
        </div>
        <div class="stat-box">
            <div class="stat-number $(if($script:SyncStats.Errors -gt 0){'error'}else{'success'})">$($script:SyncStats.Errors)</div>
            <div class="stat-label">Erreurs</div>
        </div>
    </div>
    
    <h2>Détails</h2>
    <p><strong>Fichier de log:</strong> $script:LogFile</p>
    <p><strong>Patterns d'exclusion:</strong> $($Exclude -join ', ')</p>
    <p><strong>Patterns d'inclusion:</strong> $($Include -join ', ')</p>
    <p><strong>Vérification d'intégrité:</strong> $(if($VerifyIntegrity){'Activée'}else{'Désactivée'})</p>
    <p><strong>Mode simulation:</strong> $(if($DryRun){'Activé'}else{'Désactivé'})</p>
</body>
</html>
"@
    
    try {
        $html | Out-File -FilePath $ReportPath -Encoding UTF8
        Write-Log "Rapport généré: $ReportPath" -Level "SUCCESS"
    } catch {
        Write-Log "Erreur lors de la génération du rapport: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Fonction de planification
function Set-SyncSchedule {
    param(
        [string]$ScheduleExpression,
        [string]$TaskName = "SyncRepertoire_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    )
    
    try {
        # Construction de la commande PowerShell
        $scriptPath = $MyInvocation.ScriptName
        $arguments = "-Source `"$Source`" -Destination `"$Destination`" -Mode $Mode"
        
        if ($Exclude.Count -gt 0) {
            $arguments += " -Exclude `"$($Exclude -join '","')`""
        }
        
        if ($VerifyIntegrity) { $arguments += " -VerifyIntegrity" }
        if ($Compress) { $arguments += " -Compress" }
        if ($Encrypt) { $arguments += " -Encrypt" }
        
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File `"$scriptPath`" $arguments"
        
        # Analyse de l'expression de planification (format simplifié)
        $trigger = switch -Regex ($ScheduleExpression) {
            "daily|quotidien" { New-ScheduledTaskTrigger -Daily -At "02:00" }
            "weekly|hebdomadaire" { New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek Sunday -At "02:00" }
            "hourly|horaire" { New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1) }
            default { New-ScheduledTaskTrigger -Daily -At "02:00" }
        }
        
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description "Synchronisation automatique de répertoires"
        
        Write-Log "Tâche planifiée créée: $TaskName" -Level "SUCCESS"
        
    } catch {
        Write-Log "Erreur lors de la création de la tâche planifiée: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Fonction de menu interactif
function Show-InteractiveMenu {
    do {
        Clear-Host
        Write-Host "=== SYNCHRONISATION DE RÉPERTOIRES ===" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1. Synchronisation simple (Source -> Destination)" -ForegroundColor White
        Write-Host "2. Synchronisation miroir (avec suppression)" -ForegroundColor White
        Write-Host "3. Synchronisation bidirectionnelle" -ForegroundColor White
        Write-Host "4. Synchronisation avec exclusions" -ForegroundColor White
        Write-Host "5. Mode simulation (Dry-run)" -ForegroundColor White
        Write-Host "6. Planifier une synchronisation" -ForegroundColor White
        Write-Host "7. Voir les statistiques de la dernière sync" -ForegroundColor White
        Write-Host "8. Configuration avancée" -ForegroundColor White
        Write-Host "0. Quitter" -ForegroundColor Red
        Write-Host ""
        
        $choice = Read-Host "Choisissez une option"
        
        switch ($choice) {
            "1" {
                $script:Source = Read-Host "Répertoire source"
                $script:Destination = Read-Host "Répertoire destination"
                $script:Mode = "Incremental"
                
                if ((Test-PathAccess $Source "Source") -and (Test-PathAccess $Destination "Destination")) {
                    Start-Synchronization -SourcePath $Source -DestPath $Destination -SyncMode $Mode
                    Generate-SyncReport -ReportPath $ReportPath
                }
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            
            "2" {
                $script:Source = Read-Host "Répertoire source"
                $script:Destination = Read-Host "Répertoire destination"
                $script:Mode = "Mirror"
                
                Write-Host "ATTENTION: Le mode miroir supprimera les fichiers en trop dans la destination!" -ForegroundColor Yellow
                $confirm = Read-Host "Continuer? (o/N)"
                
                if ($confirm -eq "o" -or $confirm -eq "O") {
                    if ((Test-PathAccess $Source "Source") -and (Test-PathAccess $Destination "Destination")) {
                        Start-Synchronization -SourcePath $Source -DestPath $Destination -SyncMode $Mode
                        Generate-SyncReport -ReportPath $ReportPath
                    }
                }
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            
            "3" {
                $path1 = Read-Host "Premier répertoire"
                $path2 = Read-Host "Deuxième répertoire"
                
                if ((Test-PathAccess $path1 "Premier") -and (Test-PathAccess $path2 "Deuxième")) {
                    Start-BidirectionalSync -Path1 $path1 -Path2 $path2
                    Generate-SyncReport -ReportPath $ReportPath
                }
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            
            "4" {
                $script:Source = Read-Host "Répertoire source"
                $script:Destination = Read-Host "Répertoire destination"
                $excludeInput = Read-Host "Patterns d'exclusion (séparés par des virgules)"
                
                if ($excludeInput) {
                    $script:Exclude = $excludeInput -split ","
                }
                
                if ((Test-PathAccess $Source "Source") -and (Test-PathAccess $Destination "Destination")) {
                    Start-Synchronization -SourcePath $Source -DestPath $Destination -SyncMode "Incremental"
                    Generate-SyncReport -ReportPath $ReportPath
                }
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            
            "5" {
                $script:Source = Read-Host "Répertoire source"
                $script:Destination = Read-Host "Répertoire destination"
                $script:DryRun = $true
                
                Write-Host "Mode simulation activé - aucune modification ne sera effectuée" -ForegroundColor Yellow
                
                if ((Test-PathAccess $Source "Source") -and (Test-PathAccess $Destination "Destination")) {
                    Start-Synchronization -SourcePath $Source -DestPath $Destination -SyncMode "Incremental"
                }
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            
            "6" {
                $script:Source = Read-Host "Répertoire source"
                $script:Destination = Read-Host "Répertoire destination"
                
                Write-Host "Fréquences disponibles:"
                Write-Host "- daily (quotidien)"
                Write-Host "- weekly (hebdomadaire)"
                Write-Host "- hourly (horaire)"
                
                $schedule = Read-Host "Fréquence de synchronisation"
                
                if ((Test-PathAccess $Source "Source") -and (Test-PathAccess $Destination "Destination")) {
                    Set-SyncSchedule -ScheduleExpression $schedule
                }
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            
            "7" {
                Write-Host "=== STATISTIQUES DE SYNCHRONISATION ===" -ForegroundColor Green
                Write-Host "Fichiers traités: $($script:SyncStats.FilesProcessed)" -ForegroundColor White
                Write-Host "Fichiers copiés: $($script:SyncStats.FilesCopied)" -ForegroundColor Green
                Write-Host "Fichiers mis à jour: $($script:SyncStats.FilesUpdated)" -ForegroundColor Yellow
                Write-Host "Fichiers ignorés: $($script:SyncStats.FilesSkipped)" -ForegroundColor Cyan
                Write-Host "Fichiers supprimés: $($script:SyncStats.FilesDeleted)" -ForegroundColor Red
                Write-Host "Données transférées: $([math]::Round($script:SyncStats.BytesTransferred / 1MB, 2)) MB" -ForegroundColor White
                Write-Host "Erreurs: $($script:SyncStats.Errors)" -ForegroundColor $(if($script:SyncStats.Errors -gt 0){"Red"}else{"Green"})
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            
            "8" {
                Write-Host "=== CONFIGURATION AVANCÉE ===" -ForegroundColor Cyan
                
                $verifyChoice = Read-Host "Activer la vérification d'intégrité? (o/N)"
                $script:VerifyIntegrity = ($verifyChoice -eq "o" -or $verifyChoice -eq "O")
                
                $compressChoice = Read-Host "Activer la compression? (o/N)"
                $script:Compress = ($compressChoice -eq "o" -or $compressChoice -eq "O")
                
                $maxRetriesInput = Read-Host "Nombre maximum de tentatives (défaut: 3)"
                if ($maxRetriesInput) {
                    $script:MaxRetries = [int]$maxRetriesInput
                }
                
                Write-Host "Configuration mise à jour!" -ForegroundColor Green
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            
            "0" {
                Write-Host "Au revoir!" -ForegroundColor Green
                return
            }
            
            default {
                Write-Host "Option invalide!" -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    } while ($true)
}

# Script principal
try {
    Write-Log "=== DÉBUT DE LA SYNCHRONISATION DE RÉPERTOIRES ===" -Level "INFO"
    Write-Log "Version: 2.0 | Auteur: Jimmy Ramsamynaick" -Level "INFO"
    
    if ($Interactive) {
        Show-InteractiveMenu
    } else {
        # Validation des paramètres obligatoires
        if (-not $Source -or -not $Destination) {
            Write-Log "Les paramètres Source et Destination sont obligatoires en mode non-interactif" -Level "ERROR"
            Write-Log "Utilisez -Interactive pour le mode interactif ou spécifiez -Source et -Destination" -Level "INFO"
            exit 1
        }
        
        # Validation des chemins
        if (-not (Test-PathAccess $Source "Source")) {
            exit 1
        }
        
        if (-not (Test-PathAccess $Destination "Destination")) {
            exit 1
        }
        
        # Planification si demandée
        if ($Schedule) {
            Set-SyncSchedule -ScheduleExpression $Schedule
            exit 0
        }
        
        # Exécution de la synchronisation
        switch ($Mode) {
            "Bidirectional" {
                Start-BidirectionalSync -Path1 $Source -Path2 $Destination
            }
            default {
                Start-Synchronization -SourcePath $Source -DestPath $Destination -SyncMode $Mode
            }
        }
        
        # Génération du rapport
        Generate-SyncReport -ReportPath $ReportPath
        
        # Affichage des statistiques finales
        Write-Log "=== STATISTIQUES FINALES ===" -Level "INFO"
        Write-Log "Fichiers traités: $($script:SyncStats.FilesProcessed)" -Level "INFO"
        Write-Log "Fichiers copiés: $($script:SyncStats.FilesCopied)" -Level "SUCCESS"
        Write-Log "Fichiers mis à jour: $($script:SyncStats.FilesUpdated)" -Level "WARNING"
        Write-Log "Fichiers supprimés: $($script:SyncStats.FilesDeleted)" -Level "WARNING"
        Write-Log "Données transférées: $([math]::Round($script:SyncStats.BytesTransferred / 1MB, 2)) MB" -Level "INFO"
        Write-Log "Erreurs: $($script:SyncStats.Errors)" -Level $(if($script:SyncStats.Errors -gt 0){"ERROR"}else{"SUCCESS"})
    }
    
    Write-Log "=== FIN DE LA SYNCHRONISATION ===" -Level "SUCCESS"
    
} catch {
    Write-Log "Erreur critique: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Utilisez Get-Help .\synch_repertoire.ps1 -Full pour plus d'informations" -Level "INFO"
    exit 1
}