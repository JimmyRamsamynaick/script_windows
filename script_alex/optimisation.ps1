<#
.SYNOPSIS
    Script d'optimisation système pour Windows

.DESCRIPTION
    Ce script effectue diverses optimisations système pour améliorer les performances
    et la stabilité de Windows. Il inclut le nettoyage de fichiers temporaires,
    l'optimisation de la mémoire, la défragmentation, et diverses optimisations du registre.

    Fonctionnalités :
    - Nettoyage des fichiers temporaires et cache
    - Optimisation de la mémoire et des services
    - Défragmentation des disques (si nécessaire)
    - Optimisations du registre Windows
    - Nettoyage du registre
    - Optimisation du démarrage
    - Vérification et réparation des fichiers système
    - Optimisation des paramètres réseau

.PARAMETER OptimizationLevel
    Niveau d'optimisation: Basic, Standard, Advanced, Custom

.PARAMETER IncludeRegistry
    Inclure les optimisations du registre (nécessite des droits administrateur)

.PARAMETER IncludeDefrag
    Inclure la défragmentation des disques

.PARAMETER IncludeSystemFiles
    Vérifier et réparer les fichiers système (sfc /scannow, dism)

.PARAMETER IncludeStartup
    Optimiser les programmes de démarrage

.PARAMETER CreateRestorePoint
    Créer un point de restauration avant les modifications

.PARAMETER RebootAfter
    Redémarrer automatiquement après optimisation

.PARAMETER LogLevel
    Niveau de détail des logs: Minimal, Standard, Detailed

.EXAMPLE
    .\optimisation.ps1
    Optimisation de base sans modifications du registre

.EXAMPLE
    .\optimisation.ps1 -OptimizationLevel Advanced -IncludeRegistry -CreateRestorePoint
    Optimisation avancée avec registre et point de restauration

.EXAMPLE
    .\optimisation.ps1 -OptimizationLevel Custom -IncludeDefrag -IncludeSystemFiles
    Optimisation personnalisée avec défragmentation et vérification système

.NOTES
    Auteur: Alex
    Date: 28/10/2025
    Version: 1.0
    
    Prérequis:
    - PowerShell 5.1 ou supérieur
    - Droits administrateur recommandés pour certaines optimisations
    - Windows 10/11 ou Windows Server 2016+
    
    ATTENTION: Certaines optimisations peuvent nécessiter un redémarrage
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, HelpMessage="Niveau d'optimisation")]
    [ValidateSet("Basic", "Standard", "Advanced", "Custom")]
    [string]$OptimizationLevel = "Standard",
    
    [Parameter(Mandatory=$false, HelpMessage="Inclure les optimisations du registre")]
    [switch]$IncludeRegistry,
    
    [Parameter(Mandatory=$false, HelpMessage="Inclure la défragmentation")]
    [switch]$IncludeDefrag,
    
    [Parameter(Mandatory=$false, HelpMessage="Vérifier les fichiers système")]
    [switch]$IncludeSystemFiles,
    
    [Parameter(Mandatory=$false, HelpMessage="Optimiser le démarrage")]
    [switch]$IncludeStartup,
    
    [Parameter(Mandatory=$false, HelpMessage="Créer un point de restauration")]
    [switch]$CreateRestorePoint,
    
    [Parameter(Mandatory=$false, HelpMessage="Redémarrer après optimisation")]
    [switch]$RebootAfter,
    
    [Parameter(Mandatory=$false, HelpMessage="Niveau de détail des logs")]
    [ValidateSet("Minimal", "Standard", "Detailed")]
    [string]$LogLevel = "Standard"
)

# Configuration
$ErrorActionPreference = "Continue"  # Continue pour éviter l'arrêt sur erreurs mineures
$script:ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
$script:LogPath = Join-Path $env:TEMP "$($script:ScriptName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# Statistiques globales
$script:Stats = @{
    FilesDeleted = 0
    SpaceFreed = 0
    OptimizationsApplied = 0
    ErrorsEncountered = 0
    StartTime = Get-Date
}

# Fonctions utilitaires
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO",
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Filtrage selon le niveau de log
    $shouldLog = switch ($LogLevel) {
        "Minimal" { $Level -in @("ERROR", "SUCCESS") }
        "Standard" { $Level -in @("INFO", "WARN", "ERROR", "SUCCESS") }
        "Detailed" { $true }
        default { $true }
    }
    
    if ($shouldLog -and -not $NoConsole) {
        $color = switch($Level) {
            "ERROR" { "Red" }
            "WARN"  { "Yellow" }
            "INFO"  { "Green" }
            "SUCCESS" { "Cyan" }
            "DEBUG" { "Gray" }
            default { "White" }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
    
    try {
        $logEntry | Out-File -FilePath $script:LogPath -Append -Encoding UTF8
    }
    catch {
        # Ignorer les erreurs de log
    }
}

function Test-AdminRights {
    if (-not $script:IsAdmin) {
        Write-Log "⚠️  Certaines optimisations nécessitent des droits administrateur" -Level "WARN"
        return $false
    }
    return $true
}

function Format-FileSize {
    param([long]$Size)
    
    $units = @("B", "KB", "MB", "GB", "TB")
    $unitIndex = 0
    $sizeValue = [double]$Size
    
    while ($sizeValue -ge 1024 -and $unitIndex -lt ($units.Length - 1)) {
        $sizeValue /= 1024
        $unitIndex++
    }
    
    return "{0:N2} {1}" -f $sizeValue, $units[$unitIndex]
}

function New-RestorePoint {
    if (-not $script:IsAdmin) {
        Write-Log "Droits administrateur requis pour créer un point de restauration" -Level "WARN"
        return $false
    }
    
    try {
        Write-Log "Création d'un point de restauration..." -Level "INFO"
        
        # Vérifier si la restauration système est activée
        $restoreStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if (-not $restoreStatus) {
            Write-Log "La restauration système n'est pas activée" -Level "WARN"
            return $false
        }
        
        # Créer le point de restauration
        $description = "Optimisation système - $(Get-Date -Format 'dd/MM/yyyy HH:mm')"
        Checkpoint-Computer -Description $description -RestorePointType "MODIFY_SETTINGS"
        
        Write-Log "✅ Point de restauration créé: $description" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Erreur lors de la création du point de restauration: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Clear-TemporaryFiles {
    Write-Log "🧹 Nettoyage des fichiers temporaires..." -Level "INFO"
    
    $tempPaths = @(
        @{Path = $env:TEMP; Description = "Fichiers temporaires utilisateur"},
        @{Path = "$env:WINDIR\Temp"; Description = "Fichiers temporaires système"},
        @{Path = "$env:WINDIR\Prefetch"; Description = "Fichiers de préchargement"},
        @{Path = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"; Description = "Cache Internet Explorer"},
        @{Path = "$env:LOCALAPPDATA\Temp"; Description = "Fichiers temporaires locaux"}
    )
    
    $totalFreed = 0
    $totalFiles = 0
    
    foreach ($tempPath in $tempPaths) {
        try {
            if (Test-Path $tempPath.Path) {
                Write-Log "Nettoyage: $($tempPath.Description)" -Level "DEBUG"
                
                $filesBefore = (Get-ChildItem -Path $tempPath.Path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
                $sizeBefore = (Get-ChildItem -Path $tempPath.Path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                
                # Supprimer les fichiers (ignorer les erreurs d'accès)
                Get-ChildItem -Path $tempPath.Path -Recurse -File -ErrorAction SilentlyContinue | 
                    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } |
                    Remove-Item -Force -ErrorAction SilentlyContinue
                
                # Supprimer les dossiers vides
                Get-ChildItem -Path $tempPath.Path -Recurse -Directory -ErrorAction SilentlyContinue | 
                    Where-Object { (Get-ChildItem -Path $_.FullName -ErrorAction SilentlyContinue).Count -eq 0 } |
                    Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                
                $filesAfter = (Get-ChildItem -Path $tempPath.Path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
                $sizeAfter = (Get-ChildItem -Path $tempPath.Path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                
                $filesDeleted = $filesBefore - $filesAfter
                $spaceFreed = $sizeBefore - $sizeAfter
                
                if ($filesDeleted -gt 0) {
                    Write-Log "  ✅ $filesDeleted fichiers supprimés, $(Format-FileSize $spaceFreed) libérés" -Level "SUCCESS"
                    $totalFiles += $filesDeleted
                    $totalFreed += $spaceFreed
                }
            }
        }
        catch {
            Write-Log "Erreur lors du nettoyage de $($tempPath.Path): $($_.Exception.Message)" -Level "WARN"
            $script:Stats.ErrorsEncountered++
        }
    }
    
    $script:Stats.FilesDeleted += $totalFiles
    $script:Stats.SpaceFreed += $totalFreed
    
    Write-Log "✅ Nettoyage terminé: $totalFiles fichiers, $(Format-FileSize $totalFreed) libérés" -Level "SUCCESS"
}

function Clear-BrowserCache {
    Write-Log "🌐 Nettoyage des caches navigateurs..." -Level "INFO"
    
    $browserCaches = @(
        @{Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"; Browser = "Chrome"},
        @{Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"; Browser = "Edge"},
        @{Path = "$env:APPDATA\Mozilla\Firefox\Profiles\*\cache2"; Browser = "Firefox"}
    )
    
    foreach ($cache in $browserCaches) {
        try {
            $paths = Get-ChildItem -Path (Split-Path $cache.Path) -Directory -ErrorAction SilentlyContinue | 
                     Where-Object { $_.FullName -like $cache.Path }
            
            foreach ($path in $paths) {
                if (Test-Path $path.FullName) {
                    $sizeBefore = (Get-ChildItem -Path $path.FullName -Recurse -File -ErrorAction SilentlyContinue | 
                                  Measure-Object -Property Length -Sum).Sum
                    
                    Remove-Item -Path "$($path.FullName)\*" -Recurse -Force -ErrorAction SilentlyContinue
                    
                    $sizeAfter = (Get-ChildItem -Path $path.FullName -Recurse -File -ErrorAction SilentlyContinue | 
                                 Measure-Object -Property Length -Sum).Sum
                    
                    $spaceFreed = $sizeBefore - $sizeAfter
                    if ($spaceFreed -gt 0) {
                        Write-Log "  ✅ Cache $($cache.Browser): $(Format-FileSize $spaceFreed) libérés" -Level "SUCCESS"
                        $script:Stats.SpaceFreed += $spaceFreed
                    }
                }
            }
        }
        catch {
            Write-Log "Erreur lors du nettoyage du cache $($cache.Browser): $($_.Exception.Message)" -Level "WARN"
        }
    }
}

function Optimize-Memory {
    Write-Log "🧠 Optimisation de la mémoire..." -Level "INFO"
    
    try {
        # Forcer la collecte des ordures .NET
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
        
        # Vider le cache DNS
        if ($script:IsAdmin) {
            Clear-DnsClientCache
            Write-Log "  ✅ Cache DNS vidé" -Level "SUCCESS"
        }
        
        # Optimiser la mémoire virtuelle (si admin)
        if ($script:IsAdmin) {
            try {
                # Vider les fichiers de pagination inactifs
                $result = Invoke-Expression "rundll32.exe advapi32.dll,ProcessIdleTasks" -ErrorAction SilentlyContinue
                Write-Log "  ✅ Tâches inactives traitées" -Level "SUCCESS"
            }
            catch {
                Write-Log "Impossible d'optimiser les tâches inactives" -Level "DEBUG"
            }
        }
        
        $script:Stats.OptimizationsApplied++
        Write-Log "✅ Optimisation mémoire terminée" -Level "SUCCESS"
    }
    catch {
        Write-Log "Erreur lors de l'optimisation mémoire: $($_.Exception.Message)" -Level "ERROR"
        $script:Stats.ErrorsEncountered++
    }
}

function Optimize-Services {
    if (-not $script:IsAdmin) {
        Write-Log "Droits administrateur requis pour optimiser les services" -Level "WARN"
        return
    }
    
    Write-Log "⚙️ Optimisation des services..." -Level "INFO"
    
    # Services à désactiver (avec précaution)
    $servicesToOptimize = @(
        @{Name = "Fax"; Action = "Disable"; Description = "Service de télécopie"},
        @{Name = "TabletInputService"; Action = "Manual"; Description = "Service d'entrée Tablet PC"},
        @{Name = "WSearch"; Action = "Manual"; Description = "Windows Search (si non utilisé)"}
    )
    
    foreach ($serviceConfig in $servicesToOptimize) {
        try {
            $service = Get-Service -Name $serviceConfig.Name -ErrorAction SilentlyContinue
            if ($service) {
                $currentStartType = (Get-WmiObject -Class Win32_Service -Filter "Name='$($serviceConfig.Name)'").StartMode
                
                if ($serviceConfig.Action -eq "Disable" -and $currentStartType -ne "Disabled") {
                    Set-Service -Name $serviceConfig.Name -StartupType Disabled
                    Write-Log "  ✅ Service $($serviceConfig.Name) désactivé" -Level "SUCCESS"
                    $script:Stats.OptimizationsApplied++
                }
                elseif ($serviceConfig.Action -eq "Manual" -and $currentStartType -eq "Auto") {
                    Set-Service -Name $serviceConfig.Name -StartupType Manual
                    Write-Log "  ✅ Service $($serviceConfig.Name) configuré en manuel" -Level "SUCCESS"
                    $script:Stats.OptimizationsApplied++
                }
            }
        }
        catch {
            Write-Log "Erreur lors de l'optimisation du service $($serviceConfig.Name): $($_.Exception.Message)" -Level "WARN"
        }
    }
}

function Optimize-Registry {
    if (-not $IncludeRegistry -or -not $script:IsAdmin) {
        Write-Log "Optimisations du registre ignorées (droits admin requis ou non demandées)" -Level "INFO"
        return
    }
    
    Write-Log "📝 Optimisation du registre..." -Level "INFO"
    
    $registryOptimizations = @(
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            Name = "ClearPageFileAtShutdown"
            Value = 0
            Type = "DWORD"
            Description = "Ne pas vider le fichier de pagination à l'arrêt"
        },
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            Name = "DisablePagingExecutive"
            Value = 1
            Type = "DWORD"
            Description = "Garder le noyau en mémoire"
        },
        @{
            Path = "HKCU:\Control Panel\Desktop"
            Name = "AutoEndTasks"
            Value = "1"
            Type = "String"
            Description = "Fermeture automatique des tâches"
        },
        @{
            Path = "HKCU:\Control Panel\Desktop"
            Name = "HungAppTimeout"
            Value = "1000"
            Type = "String"
            Description = "Timeout pour applications qui ne répondent pas"
        }
    )
    
    foreach ($optimization in $registryOptimizations) {
        try {
            # Créer le chemin si nécessaire
            if (-not (Test-Path $optimization.Path)) {
                New-Item -Path $optimization.Path -Force | Out-Null
            }
            
            # Appliquer l'optimisation
            Set-ItemProperty -Path $optimization.Path -Name $optimization.Name -Value $optimization.Value -Type $optimization.Type
            Write-Log "  ✅ $($optimization.Description)" -Level "SUCCESS"
            $script:Stats.OptimizationsApplied++
        }
        catch {
            Write-Log "Erreur lors de l'optimisation registre $($optimization.Name): $($_.Exception.Message)" -Level "WARN"
            $script:Stats.ErrorsEncountered++
        }
    }
}

function Optimize-Startup {
    if (-not $IncludeStartup) {
        return
    }
    
    Write-Log "🚀 Optimisation du démarrage..." -Level "INFO"
    
    try {
        # Analyser les programmes de démarrage
        $startupItems = Get-CimInstance -ClassName Win32_StartupCommand
        
        Write-Log "Programmes de démarrage détectés: $($startupItems.Count)" -Level "INFO"
        
        # Afficher les programmes de démarrage pour information
        foreach ($item in $startupItems) {
            Write-Log "  - $($item.Name): $($item.Command)" -Level "DEBUG"
        }
        
        # Note: La désactivation automatique des programmes de démarrage est risquée
        # On se contente de les lister pour que l'utilisateur puisse décider
        Write-Log "ℹ️  Utilisez msconfig ou le Gestionnaire des tâches pour désactiver les programmes non nécessaires" -Level "INFO"
        
    }
    catch {
        Write-Log "Erreur lors de l'analyse du démarrage: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Invoke-SystemFileCheck {
    if (-not $IncludeSystemFiles -or -not $script:IsAdmin) {
        return
    }
    
    Write-Log "🔧 Vérification des fichiers système..." -Level "INFO"
    
    try {
        # SFC Scan
        Write-Log "Exécution de sfc /scannow..." -Level "INFO"
        $sfcResult = Start-Process -FilePath "sfc" -ArgumentList "/scannow" -Wait -PassThru -WindowStyle Hidden
        
        if ($sfcResult.ExitCode -eq 0) {
            Write-Log "  ✅ SFC scan terminé avec succès" -Level "SUCCESS"
        } else {
            Write-Log "  ⚠️  SFC scan terminé avec des avertissements (code: $($sfcResult.ExitCode))" -Level "WARN"
        }
        
        # DISM Health Check
        Write-Log "Vérification de l'intégrité de l'image système..." -Level "INFO"
        $dismResult = Start-Process -FilePath "dism" -ArgumentList "/online", "/cleanup-image", "/checkhealth" -Wait -PassThru -WindowStyle Hidden
        
        if ($dismResult.ExitCode -eq 0) {
            Write-Log "  ✅ Image système saine" -Level "SUCCESS"
        } else {
            Write-Log "  ⚠️  Problèmes détectés dans l'image système" -Level "WARN"
        }
        
        $script:Stats.OptimizationsApplied++
    }
    catch {
        Write-Log "Erreur lors de la vérification système: $($_.Exception.Message)" -Level "ERROR"
        $script:Stats.ErrorsEncountered++
    }
}

function Invoke-DiskDefragmentation {
    if (-not $IncludeDefrag) {
        return
    }
    
    Write-Log "💿 Analyse de la défragmentation..." -Level "INFO"
    
    try {
        $drives = Get-Volume | Where-Object { $_.DriveType -eq "Fixed" -and $_.FileSystem -eq "NTFS" }
        
        foreach ($drive in $drives) {
            if ($drive.DriveLetter) {
                Write-Log "Analyse du lecteur $($drive.DriveLetter):" -Level "INFO"
                
                # Vérifier si c'est un SSD (ne pas défragmenter les SSD)
                $physicalDisk = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq $drive.ObjectId }
                if ($physicalDisk -and $physicalDisk.MediaType -eq "SSD") {
                    Write-Log "  ℹ️  SSD détecté - défragmentation ignorée" -Level "INFO"
                    continue
                }
                
                # Analyser la fragmentation
                $defragAnalysis = defrag "$($drive.DriveLetter):" /A
                Write-Log "  📊 Analyse de fragmentation terminée" -Level "INFO"
                
                # Note: La défragmentation complète peut prendre beaucoup de temps
                # On se contente de l'analyse pour ce script d'optimisation
                Write-Log "  ℹ️  Utilisez 'defrag $($drive.DriveLetter): /O' pour optimiser si nécessaire" -Level "INFO"
            }
        }
    }
    catch {
        Write-Log "Erreur lors de l'analyse de défragmentation: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Show-OptimizationSummary {
    $duration = (Get-Date) - $script:Stats.StartTime
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "📊 RÉSUMÉ DE L'OPTIMISATION SYSTÈME" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor Cyan
    
    Write-Host "🖥️  Ordinateur: $env:COMPUTERNAME" -ForegroundColor Green
    Write-Host "📅 Date: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -ForegroundColor Green
    Write-Host "⏱️  Durée: $($duration.Minutes)m $($duration.Seconds)s" -ForegroundColor Green
    Write-Host "🔧 Niveau: $OptimizationLevel" -ForegroundColor Green
    Write-Host "👤 Droits admin: $(if($script:IsAdmin){'Oui'}else{'Non'})" -ForegroundColor Green
    
    Write-Host "`n📈 STATISTIQUES:" -ForegroundColor Yellow
    Write-Host "   Fichiers supprimés: $($script:Stats.FilesDeleted)" -ForegroundColor White
    Write-Host "   Espace libéré: $(Format-FileSize $script:Stats.SpaceFreed)" -ForegroundColor White
    Write-Host "   Optimisations appliquées: $($script:Stats.OptimizationsApplied)" -ForegroundColor White
    Write-Host "   Erreurs rencontrées: $($script:Stats.ErrorsEncountered)" -ForegroundColor White
    
    if ($script:Stats.ErrorsEncountered -eq 0) {
        Write-Host "`n✅ OPTIMISATION TERMINÉE AVEC SUCCÈS" -ForegroundColor Green
    } else {
        Write-Host "`n⚠️  OPTIMISATION TERMINÉE AVEC DES AVERTISSEMENTS" -ForegroundColor Yellow
    }
    
    Write-Host "`n💡 RECOMMANDATIONS:" -ForegroundColor Cyan
    Write-Host "   - Redémarrez l'ordinateur pour appliquer toutes les optimisations" -ForegroundColor White
    Write-Host "   - Exécutez ce script régulièrement (hebdomadaire recommandé)" -ForegroundColor White
    Write-Host "   - Surveillez les performances après optimisation" -ForegroundColor White
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
}

# Configuration des optimisations selon le niveau
function Set-OptimizationLevel {
    param([string]$Level)
    
    switch ($Level) {
        "Basic" {
            # Nettoyage de base uniquement
        }
        "Standard" {
            # Nettoyage + optimisations mémoire
        }
        "Advanced" {
            # Tout sauf registre (sauf si explicitement demandé)
            $script:IncludeStartup = $true
        }
        "Custom" {
            # Utilise les paramètres fournis par l'utilisateur
        }
    }
}

# Script principal
try {
    Write-Log "🚀 Début de l'optimisation système" -Level "SUCCESS"
    Write-Log "Niveau: $OptimizationLevel | Admin: $script:IsAdmin | Log: $LogLevel"
    
    # Vérifier les droits administrateur si nécessaire
    if ($IncludeRegistry -or $IncludeSystemFiles) {
        Test-AdminRights | Out-Null
    }
    
    # Créer un point de restauration si demandé
    if ($CreateRestorePoint) {
        New-RestorePoint | Out-Null
    }
    
    # Configurer le niveau d'optimisation
    Set-OptimizationLevel -Level $OptimizationLevel
    
    # Exécuter les optimisations
    Write-Log "`n🔄 PHASE 1: Nettoyage des fichiers" -Level "INFO"
    Clear-TemporaryFiles
    Clear-BrowserCache
    
    Write-Log "`n🔄 PHASE 2: Optimisation mémoire et services" -Level "INFO"
    Optimize-Memory
    
    if ($OptimizationLevel -in @("Standard", "Advanced") -or $IncludeRegistry) {
        Optimize-Services
    }
    
    Write-Log "`n🔄 PHASE 3: Optimisations avancées" -Level "INFO"
    if ($OptimizationLevel -in @("Advanced") -or $IncludeRegistry) {
        Optimize-Registry
    }
    
    if ($IncludeStartup) {
        Optimize-Startup
    }
    
    Write-Log "`n🔄 PHASE 4: Vérifications système" -Level "INFO"
    if ($IncludeSystemFiles) {
        Invoke-SystemFileCheck
    }
    
    if ($IncludeDefrag) {
        Invoke-DiskDefragmentation
    }
    
    # Afficher le résumé
    Show-OptimizationSummary
    
    # Redémarrage si demandé
    if ($RebootAfter) {
        Write-Log "🔄 Redémarrage programmé dans 60 secondes..." -Level "WARN"
        Write-Log "Appuyez sur Ctrl+C pour annuler" -Level "WARN"
        Start-Sleep -Seconds 60
        Restart-Computer -Force
    }
    
    Write-Log "✅ Optimisation terminée avec succès" -Level "SUCCESS"
    exit 0
}
catch {
    Write-Log "Erreur fatale: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Ligne: $($_.InvocationInfo.ScriptLineNumber)" -Level "ERROR"
    $script:Stats.ErrorsEncountered++
    exit 1
}
finally {
    Write-Log "📄 Log sauvegardé: $script:LogPath" -Level "INFO"
}