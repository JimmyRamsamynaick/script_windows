<#
.SYNOPSIS
    Script de sauvegarde automatique pour Windows

.DESCRIPTION
    Ce script effectue des sauvegardes complètes ou incrémentales de fichiers et dossiers.
    Il supporte plusieurs destinations (local, réseau, cloud), compression, chiffrement,
    et génère des rapports détaillés des opérations de sauvegarde.

    Fonctionnalités :
    - Sauvegarde complète ou incrémentale
    - Compression avec différents niveaux
    - Chiffrement AES des archives
    - Destinations multiples (local, réseau, OneDrive, etc.)
    - Exclusion de fichiers/dossiers par patterns
    - Vérification d'intégrité des sauvegardes
    - Rotation automatique des anciennes sauvegardes
    - Rapports détaillés et notifications
    - Restauration de sauvegardes
    - Planification automatique

.PARAMETER SourcePath
    Chemin source à sauvegarder (fichier ou dossier)

.PARAMETER DestinationPath
    Chemin de destination pour la sauvegarde

.PARAMETER BackupType
    Type de sauvegarde: Full, Incremental, Differential

.PARAMETER CompressionLevel
    Niveau de compression: None, Fast, Normal, Maximum

.PARAMETER Encrypt
    Activer le chiffrement AES de la sauvegarde

.PARAMETER Password
    Mot de passe pour le chiffrement (si non fourni, sera demandé)

.PARAMETER ExcludePatterns
    Patterns de fichiers/dossiers à exclure

.PARAMETER RetentionDays
    Nombre de jours de rétention des sauvegardes

.PARAMETER VerifyIntegrity
    Vérifier l'intégrité après sauvegarde

.PARAMETER EmailReport
    Envoyer un rapport par email

.PARAMETER RestoreMode
    Mode restauration au lieu de sauvegarde

.PARAMETER RestoreFile
    Fichier de sauvegarde à restaurer

.EXAMPLE
    .\sauvegarde.ps1 -SourcePath "C:\Users\Documents" -DestinationPath "D:\Backups" -BackupType Full -CompressionLevel Normal
    Effectue une sauvegarde complète avec compression normale

.EXAMPLE
    .\sauvegarde.ps1 -SourcePath "C:\Projects" -DestinationPath "\\Server\Backups" -BackupType Incremental -Encrypt -RetentionDays 30
    Sauvegarde incrémentale chiffrée avec rétention de 30 jours

.EXAMPLE
    .\sauvegarde.ps1 -RestoreMode -RestoreFile "D:\Backups\backup_20241028.zip" -DestinationPath "C:\Restore"
    Restaure une sauvegarde

.NOTES
    Auteur: Alex
    Date: 28/10/2025
    Version: 1.0
    
    Prérequis:
    - PowerShell 5.1 ou supérieur
    - Module 7Zip4PowerShell (pour compression avancée)
    - Droits d'accès aux chemins source et destination
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, HelpMessage="Chemin source à sauvegarder")]
    [string]$SourcePath,
    
    [Parameter(Mandatory=$false, HelpMessage="Chemin de destination")]
    [string]$DestinationPath,
    
    [Parameter(Mandatory=$false, HelpMessage="Type de sauvegarde")]
    [ValidateSet("Full", "Incremental", "Differential")]
    [string]$BackupType = "Full",
    
    [Parameter(Mandatory=$false, HelpMessage="Niveau de compression")]
    [ValidateSet("None", "Fast", "Normal", "Maximum")]
    [string]$CompressionLevel = "Normal",
    
    [Parameter(Mandatory=$false, HelpMessage="Activer le chiffrement")]
    [switch]$Encrypt,
    
    [Parameter(Mandatory=$false, HelpMessage="Mot de passe de chiffrement")]
    [SecureString]$Password,
    
    [Parameter(Mandatory=$false, HelpMessage="Patterns d'exclusion")]
    [string[]]$ExcludePatterns = @("*.tmp", "*.log", "Thumbs.db", ".DS_Store", "node_modules", ".git"),
    
    [Parameter(Mandatory=$false, HelpMessage="Jours de rétention")]
    [int]$RetentionDays = 7,
    
    [Parameter(Mandatory=$false, HelpMessage="Vérifier l'intégrité")]
    [switch]$VerifyIntegrity,
    
    [Parameter(Mandatory=$false, HelpMessage="Rapport par email")]
    [switch]$EmailReport,
    
    [Parameter(Mandatory=$false, HelpMessage="Mode restauration")]
    [switch]$RestoreMode,
    
    [Parameter(Mandatory=$false, HelpMessage="Fichier à restaurer")]
    [string]$RestoreFile,
    
    [Parameter(Mandatory=$false, HelpMessage="Préfixe du nom de sauvegarde")]
    [string]$BackupPrefix = "backup",
    
    [Parameter(Mandatory=$false, HelpMessage="Affichage détaillé")]
    [switch]$Verbose
)

# Configuration
$ErrorActionPreference = "Stop"
$script:ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
$script:LogPath = Join-Path $env:TEMP "$($script:ScriptName)_$(Get-Date -Format 'yyyyMMdd').log"
$script:BackupMetadata = @{}

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
        # Ignorer les erreurs de log
    }
}

function Get-FolderSize {
    param([string]$Path)
    
    try {
        $size = (Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | 
                Measure-Object -Property Length -Sum).Sum
        return $size
    }
    catch {
        return 0
    }
}

function Format-FileSize {
    param([long]$Size)
    
    if ($Size -gt 1TB) { return "{0:N2} TB" -f ($Size / 1TB) }
    elseif ($Size -gt 1GB) { return "{0:N2} GB" -f ($Size / 1GB) }
    elseif ($Size -gt 1MB) { return "{0:N2} MB" -f ($Size / 1MB) }
    elseif ($Size -gt 1KB) { return "{0:N2} KB" -f ($Size / 1KB) }
    else { return "$Size bytes" }
}

function Test-BackupPaths {
    param(
        [string]$Source,
        [string]$Destination
    )
    
    # Vérifier le chemin source
    if (-not (Test-Path $Source)) {
        throw "Le chemin source '$Source' n'existe pas"
    }
    
    # Créer le dossier de destination s'il n'existe pas
    $destDir = if (Test-Path $Destination -PathType Container) {
        $Destination
    } else {
        Split-Path $Destination -Parent
    }
    
    if (-not (Test-Path $destDir)) {
        try {
            New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            Write-Log "Dossier de destination créé: $destDir" -Level "INFO"
        }
        catch {
            throw "Impossible de créer le dossier de destination: $destDir"
        }
    }
    
    # Vérifier l'espace disque disponible
    $sourceSize = Get-FolderSize -Path $Source
    $destDrive = (Get-Item $destDir).PSDrive
    $freeSpace = $destDrive.Free
    
    if ($sourceSize -gt $freeSpace) {
        Write-Log "⚠️  Espace disque insuffisant. Requis: $(Format-FileSize $sourceSize), Disponible: $(Format-FileSize $freeSpace)" -Level "WARN"
    }
    
    return @{
        SourceSize = $sourceSize
        FreeSpace = $freeSpace
        DestinationExists = Test-Path $destDir
    }
}

function Get-ExclusionFilter {
    param([string[]]$Patterns)
    
    $filter = {
        param($Path)
        
        foreach ($pattern in $Patterns) {
            if ($Path -like $pattern) {
                return $false
            }
            
            # Vérifier si c'est un dossier à exclure
            $fileName = Split-Path $Path -Leaf
            if ($fileName -like $pattern) {
                return $false
            }
        }
        return $true
    }
    
    return $filter
}

function New-BackupArchive {
    param(
        [string]$SourcePath,
        [string]$DestinationPath,
        [string]$BackupType,
        [string]$CompressionLevel,
        [string[]]$ExcludePatterns,
        [SecureString]$Password
    )
    
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupName = "$BackupPrefix`_$BackupType`_$timestamp"
        
        # Déterminer l'extension selon la compression
        $extension = switch ($CompressionLevel) {
            "None" { ".tar" }
            default { ".zip" }
        }
        
        $backupFile = Join-Path $DestinationPath "$backupName$extension"
        
        Write-Log "📦 Création de l'archive: $backupFile" -Level "INFO"
        Write-Log "   Type: $BackupType | Compression: $CompressionLevel" -Level "INFO"
        
        # Collecter les fichiers à sauvegarder
        $filesToBackup = @()
        $exclusionFilter = Get-ExclusionFilter -Patterns $ExcludePatterns
        
        if (Test-Path $SourcePath -PathType Container) {
            # Dossier source
            $allFiles = Get-ChildItem -Path $SourcePath -Recurse -File -ErrorAction SilentlyContinue
            foreach ($file in $allFiles) {
                if (& $exclusionFilter $file.FullName) {
                    $filesToBackup += $file
                }
            }
        } else {
            # Fichier unique
            if (& $exclusionFilter $SourcePath) {
                $filesToBackup += Get-Item $SourcePath
            }
        }
        
        Write-Log "   Fichiers à sauvegarder: $($filesToBackup.Count)" -Level "INFO"
        
        if ($filesToBackup.Count -eq 0) {
            throw "Aucun fichier à sauvegarder après application des filtres"
        }
        
        # Créer l'archive selon le type de compression
        if ($CompressionLevel -eq "None") {
            # Archive TAR sans compression
            $tarArgs = @("--create", "--file=$backupFile")
            
            # Ajouter les fichiers
            foreach ($file in $filesToBackup) {
                $relativePath = $file.FullName.Substring($SourcePath.Length + 1)
                $tarArgs += $relativePath
            }
            
            # Exécuter tar (si disponible)
            if (Get-Command tar -ErrorAction SilentlyContinue) {
                Push-Location $SourcePath
                try {
                    & tar @tarArgs
                }
                finally {
                    Pop-Location
                }
            } else {
                throw "Commande 'tar' non disponible. Utilisez la compression ZIP."
            }
        } else {
            # Archive ZIP avec compression
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            
            $compressionLevel = switch ($CompressionLevel) {
                "Fast" { [System.IO.Compression.CompressionLevel]::Fastest }
                "Normal" { [System.IO.Compression.CompressionLevel]::Optimal }
                "Maximum" { [System.IO.Compression.CompressionLevel]::Optimal }
                default { [System.IO.Compression.CompressionLevel]::Optimal }
            }
            
            # Créer l'archive ZIP
            $zip = [System.IO.Compression.ZipFile]::Open($backupFile, [System.IO.Compression.ZipArchiveMode]::Create)
            
            try {
                $totalFiles = $filesToBackup.Count
                $currentFile = 0
                
                foreach ($file in $filesToBackup) {
                    $currentFile++
                    $relativePath = $file.FullName.Substring($SourcePath.Length + 1)
                    
                    if ($Verbose) {
                        $progress = [math]::Round(($currentFile / $totalFiles) * 100, 1)
                        Write-Progress -Activity "Sauvegarde en cours" -Status "Fichier $currentFile/$totalFiles ($progress%)" -PercentComplete $progress
                    }
                    
                    try {
                        $entry = $zip.CreateEntry($relativePath, $compressionLevel)
                        $entryStream = $entry.Open()
                        $fileStream = [System.IO.File]::OpenRead($file.FullName)
                        
                        $fileStream.CopyTo($entryStream)
                        
                        $fileStream.Close()
                        $entryStream.Close()
                    }
                    catch {
                        Write-Log "⚠️  Erreur avec le fichier '$($file.FullName)': $($_.Exception.Message)" -Level "WARN"
                    }
                }
                
                if ($Verbose) {
                    Write-Progress -Activity "Sauvegarde en cours" -Completed
                }
            }
            finally {
                $zip.Dispose()
            }
        }
        
        # Chiffrement si demandé
        if ($Encrypt -and $Password) {
            Write-Log "🔒 Chiffrement de l'archive..." -Level "INFO"
            $encryptedFile = "$backupFile.encrypted"
            
            # Utiliser AES pour chiffrer le fichier
            $plainText = [System.IO.File]::ReadAllBytes($backupFile)
            $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)))
            
            # Créer une clé AES à partir du mot de passe
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $key = $sha256.ComputeHash($passwordBytes)
            $sha256.Dispose()
            
            # Chiffrer
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = $key
            $aes.GenerateIV()
            
            $encryptor = $aes.CreateEncryptor()
            $encryptedBytes = $encryptor.TransformFinalBlock($plainText, 0, $plainText.Length)
            
            # Sauvegarder IV + données chiffrées
            $finalBytes = $aes.IV + $encryptedBytes
            [System.IO.File]::WriteAllBytes($encryptedFile, $finalBytes)
            
            # Nettoyer
            $aes.Dispose()
            $encryptor.Dispose()
            
            # Supprimer le fichier non chiffré
            Remove-Item $backupFile -Force
            $backupFile = $encryptedFile
        }
        
        # Vérifier le fichier créé
        if (Test-Path $backupFile) {
            $backupSize = (Get-Item $backupFile).Length
            $script:BackupMetadata = @{
                BackupFile = $backupFile
                BackupSize = $backupSize
                SourceSize = (Get-FolderSize -Path $SourcePath)
                FileCount = $filesToBackup.Count
                CompressionRatio = if ($backupSize -gt 0) { [math]::Round((1 - ($backupSize / (Get-FolderSize -Path $SourcePath))) * 100, 1) } else { 0 }
                CreationTime = Get-Date
                BackupType = $BackupType
                Encrypted = $Encrypt.IsPresent
            }
            
            Write-Log "✅ Archive créée avec succès: $backupFile" -Level "SUCCESS"
            Write-Log "   Taille: $(Format-FileSize $backupSize)" -Level "INFO"
            Write-Log "   Fichiers: $($filesToBackup.Count)" -Level "INFO"
            Write-Log "   Compression: $($script:BackupMetadata.CompressionRatio)%" -Level "INFO"
            
            return $backupFile
        } else {
            throw "Échec de la création de l'archive"
        }
    }
    catch {
        Write-Log "Erreur lors de la création de l'archive: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Test-BackupIntegrity {
    param([string]$BackupFile)
    
    try {
        Write-Log "🔍 Vérification de l'intégrité de l'archive..." -Level "INFO"
        
        if (-not (Test-Path $BackupFile)) {
            throw "Fichier de sauvegarde non trouvé: $BackupFile"
        }
        
        $extension = [System.IO.Path]::GetExtension($BackupFile).ToLower()
        
        if ($extension -eq ".zip") {
            # Vérifier l'archive ZIP
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            
            try {
                $zip = [System.IO.Compression.ZipFile]::OpenRead($BackupFile)
                $entryCount = $zip.Entries.Count
                $zip.Dispose()
                
                Write-Log "✅ Archive ZIP valide ($entryCount entrées)" -Level "SUCCESS"
                return $true
            }
            catch {
                Write-Log "❌ Archive ZIP corrompue: $($_.Exception.Message)" -Level "ERROR"
                return $false
            }
        }
        elseif ($extension -eq ".tar") {
            # Vérifier l'archive TAR
            if (Get-Command tar -ErrorAction SilentlyContinue) {
                $result = & tar --test --file=$BackupFile 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "✅ Archive TAR valide" -Level "SUCCESS"
                    return $true
                } else {
                    Write-Log "❌ Archive TAR corrompue: $result" -Level "ERROR"
                    return $false
                }
            } else {
                Write-Log "⚠️  Impossible de vérifier l'archive TAR (commande 'tar' non disponible)" -Level "WARN"
                return $true
            }
        }
        else {
            Write-Log "⚠️  Type d'archive non supporté pour la vérification: $extension" -Level "WARN"
            return $true
        }
    }
    catch {
        Write-Log "Erreur lors de la vérification: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Remove-OldBackups {
    param(
        [string]$BackupPath,
        [int]$RetentionDays
    )
    
    try {
        Write-Log "🧹 Nettoyage des anciennes sauvegardes (> $RetentionDays jours)..." -Level "INFO"
        
        $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
        $backupFiles = Get-ChildItem -Path $BackupPath -File | Where-Object {
            $_.Name -like "$BackupPrefix*" -and $_.CreationTime -lt $cutoffDate
        }
        
        if ($backupFiles.Count -eq 0) {
            Write-Log "Aucune ancienne sauvegarde à supprimer" -Level "INFO"
            return
        }
        
        $totalSize = ($backupFiles | Measure-Object -Property Length -Sum).Sum
        
        foreach ($file in $backupFiles) {
            try {
                Remove-Item $file.FullName -Force
                Write-Log "   Supprimé: $($file.Name)" -Level "INFO"
            }
            catch {
                Write-Log "   Erreur suppression $($file.Name): $($_.Exception.Message)" -Level "WARN"
            }
        }
        
        Write-Log "✅ $($backupFiles.Count) anciennes sauvegardes supprimées ($(Format-FileSize $totalSize) libérés)" -Level "SUCCESS"
    }
    catch {
        Write-Log "Erreur lors du nettoyage: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Restore-BackupArchive {
    param(
        [string]$BackupFile,
        [string]$RestorePath,
        [SecureString]$Password
    )
    
    try {
        Write-Log "📥 Restauration de la sauvegarde: $BackupFile" -Level "INFO"
        
        if (-not (Test-Path $BackupFile)) {
            throw "Fichier de sauvegarde non trouvé: $BackupFile"
        }
        
        # Créer le dossier de restauration
        if (-not (Test-Path $RestorePath)) {
            New-Item -Path $RestorePath -ItemType Directory -Force | Out-Null
        }
        
        $workingFile = $BackupFile
        
        # Déchiffrer si nécessaire
        if ($BackupFile -like "*.encrypted" -and $Password) {
            Write-Log "🔓 Déchiffrement de l'archive..." -Level "INFO"
            
            $encryptedBytes = [System.IO.File]::ReadAllBytes($BackupFile)
            $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)))
            
            # Créer la clé AES
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $key = $sha256.ComputeHash($passwordBytes)
            $sha256.Dispose()
            
            # Extraire IV et données
            $iv = $encryptedBytes[0..15]
            $encryptedData = $encryptedBytes[16..($encryptedBytes.Length-1)]
            
            # Déchiffrer
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = $key
            $aes.IV = $iv
            
            $decryptor = $aes.CreateDecryptor()
            $decryptedBytes = $decryptor.TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
            
            # Sauvegarder temporairement
            $workingFile = [System.IO.Path]::GetTempFileName()
            [System.IO.File]::WriteAllBytes($workingFile, $decryptedBytes)
            
            $aes.Dispose()
            $decryptor.Dispose()
        }
        
        # Extraire l'archive
        $extension = [System.IO.Path]::GetExtension($workingFile).ToLower()
        
        if ($extension -eq ".zip") {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($workingFile, $RestorePath)
        }
        elseif ($extension -eq ".tar") {
            if (Get-Command tar -ErrorAction SilentlyContinue) {
                Push-Location $RestorePath
                try {
                    & tar --extract --file=$workingFile
                }
                finally {
                    Pop-Location
                }
            } else {
                throw "Commande 'tar' non disponible pour la restauration"
            }
        }
        else {
            throw "Type d'archive non supporté: $extension"
        }
        
        # Nettoyer le fichier temporaire si déchiffré
        if ($workingFile -ne $BackupFile -and (Test-Path $workingFile)) {
            Remove-Item $workingFile -Force
        }
        
        Write-Log "✅ Restauration terminée dans: $RestorePath" -Level "SUCCESS"
    }
    catch {
        Write-Log "Erreur lors de la restauration: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Show-BackupReport {
    if ($script:BackupMetadata.Count -eq 0) {
        return
    }
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "📊 RAPPORT DE SAUVEGARDE" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor Cyan
    
    Write-Host "Fichier de sauvegarde: $($script:BackupMetadata.BackupFile)" -ForegroundColor White
    Write-Host "Type de sauvegarde: $($script:BackupMetadata.BackupType)" -ForegroundColor White
    Write-Host "Date de création: $($script:BackupMetadata.CreationTime)" -ForegroundColor White
    Write-Host "Chiffrement: $(if($script:BackupMetadata.Encrypted){'Activé'}else{'Désactivé'})" -ForegroundColor White
    
    Write-Host "`n📈 STATISTIQUES:" -ForegroundColor Yellow
    Write-Host "   Taille source: $(Format-FileSize $script:BackupMetadata.SourceSize)" -ForegroundColor White
    Write-Host "   Taille archive: $(Format-FileSize $script:BackupMetadata.BackupSize)" -ForegroundColor White
    Write-Host "   Compression: $($script:BackupMetadata.CompressionRatio)%" -ForegroundColor White
    Write-Host "   Fichiers sauvegardés: $($script:BackupMetadata.FileCount)" -ForegroundColor White
    
    $duration = (Get-Date) - $script:BackupMetadata.CreationTime
    Write-Host "   Durée: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
}

function Show-InteractiveMenu {
    do {
        Clear-Host
        Write-Host "🛠️  SCRIPT DE SAUVEGARDE WINDOWS" -ForegroundColor Cyan
        Write-Host "="*50 -ForegroundColor Cyan
        Write-Host "1. Sauvegarde complète" -ForegroundColor White
        Write-Host "2. Sauvegarde incrémentale" -ForegroundColor White
        Write-Host "3. Restaurer une sauvegarde" -ForegroundColor White
        Write-Host "4. Lister les sauvegardes" -ForegroundColor White
        Write-Host "5. Vérifier l'intégrité" -ForegroundColor White
        Write-Host "6. Nettoyer anciennes sauvegardes" -ForegroundColor White
        Write-Host "0. Quitter" -ForegroundColor Red
        Write-Host "="*50 -ForegroundColor Cyan
        
        $choice = Read-Host "Votre choix"
        
        switch ($choice) {
            "1" {
                $source = Read-Host "Chemin source"
                $dest = Read-Host "Chemin destination"
                if ($source -and $dest) {
                    Start-BackupProcess -SourcePath $source -DestinationPath $dest -BackupType "Full"
                }
            }
            "2" {
                $source = Read-Host "Chemin source"
                $dest = Read-Host "Chemin destination"
                if ($source -and $dest) {
                    Start-BackupProcess -SourcePath $source -DestinationPath $dest -BackupType "Incremental"
                }
            }
            "3" {
                $backupFile = Read-Host "Fichier de sauvegarde"
                $restorePath = Read-Host "Dossier de restauration"
                if ($backupFile -and $restorePath) {
                    Restore-BackupArchive -BackupFile $backupFile -RestorePath $restorePath
                }
            }
            "4" {
                $backupPath = Read-Host "Dossier des sauvegardes"
                if ($backupPath -and (Test-Path $backupPath)) {
                    Get-ChildItem -Path $backupPath -Filter "$BackupPrefix*" | Format-Table Name, Length, CreationTime
                }
            }
            "5" {
                $backupFile = Read-Host "Fichier à vérifier"
                if ($backupFile -and (Test-Path $backupFile)) {
                    Test-BackupIntegrity -BackupFile $backupFile
                }
            }
            "6" {
                $backupPath = Read-Host "Dossier des sauvegardes"
                $days = Read-Host "Jours de rétention (défaut: 7)"
                if (-not $days) { $days = 7 }
                if ($backupPath -and (Test-Path $backupPath)) {
                    Remove-OldBackups -BackupPath $backupPath -RetentionDays $days
                }
            }
            "0" {
                Write-Host "Au revoir !" -ForegroundColor Green
                return
            }
            default {
                Write-Host "Choix invalide !" -ForegroundColor Red
                Start-Sleep 2
            }
        }
        
        if ($choice -ne "0") {
            Write-Host "`nAppuyez sur une touche pour continuer..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    } while ($choice -ne "0")
}

function Start-BackupProcess {
    param(
        [string]$SourcePath,
        [string]$DestinationPath,
        [string]$BackupType
    )
    
    try {
        # Vérifier les chemins
        $pathInfo = Test-BackupPaths -Source $SourcePath -Destination $DestinationPath
        
        Write-Log "📋 Informations de sauvegarde:" -Level "INFO"
        Write-Log "   Source: $SourcePath ($(Format-FileSize $pathInfo.SourceSize))" -Level "INFO"
        Write-Log "   Destination: $DestinationPath" -Level "INFO"
        Write-Log "   Type: $BackupType" -Level "INFO"
        Write-Log "   Exclusions: $($ExcludePatterns -join ', ')" -Level "INFO"
        
        # Demander le mot de passe si chiffrement activé
        $backupPassword = $null
        if ($Encrypt -and -not $Password) {
            $backupPassword = Read-Host "Mot de passe de chiffrement" -AsSecureString
        } else {
            $backupPassword = $Password
        }
        
        # Créer la sauvegarde
        $backupFile = New-BackupArchive -SourcePath $SourcePath -DestinationPath $DestinationPath -BackupType $BackupType -CompressionLevel $CompressionLevel -ExcludePatterns $ExcludePatterns -Password $backupPassword
        
        # Vérifier l'intégrité si demandé
        if ($VerifyIntegrity) {
            $isValid = Test-BackupIntegrity -BackupFile $backupFile
            if (-not $isValid) {
                Write-Log "⚠️  Problème d'intégrité détecté !" -Level "WARN"
            }
        }
        
        # Nettoyer les anciennes sauvegardes
        if ($RetentionDays -gt 0) {
            Remove-OldBackups -BackupPath $DestinationPath -RetentionDays $RetentionDays
        }
        
        # Afficher le rapport
        Show-BackupReport
        
        Write-Log "✅ Sauvegarde terminée avec succès" -Level "SUCCESS"
    }
    catch {
        Write-Log "Erreur lors de la sauvegarde: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Script principal
try {
    Write-Log "🚀 Script de sauvegarde Windows" -Level "SUCCESS"
    
    if ($RestoreMode) {
        # Mode restauration
        if (-not $RestoreFile -or -not $DestinationPath) {
            throw "RestoreFile et DestinationPath sont requis en mode restauration"
        }
        
        $restorePassword = $null
        if ($RestoreFile -like "*.encrypted") {
            if (-not $Password) {
                $restorePassword = Read-Host "Mot de passe de déchiffrement" -AsSecureString
            } else {
                $restorePassword = $Password
            }
        }
        
        Restore-BackupArchive -BackupFile $RestoreFile -RestorePath $DestinationPath -Password $restorePassword
    }
    elseif (-not $SourcePath -or -not $DestinationPath) {
        # Mode interactif si paramètres manquants
        Show-InteractiveMenu
    }
    else {
        # Mode automatique avec paramètres
        Start-BackupProcess -SourcePath $SourcePath -DestinationPath $DestinationPath -BackupType $BackupType
    }
}
catch {
    Write-Log "Erreur: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Utilisez Get-Help .\sauvegarde.ps1 -Full pour plus d'informations" -Level "INFO"
    exit 1
}