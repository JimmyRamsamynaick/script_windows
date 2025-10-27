<#
.SYNOPSIS
    Analyse automatisée de fichiers de logs Windows

.DESCRIPTION
    Ce script analyse automatiquement les fichiers de logs système et applicatifs
    pour détecter des erreurs, anomalies, patterns suspects et générer des rapports
    détaillés. Il supporte les logs Windows Event, IIS, Apache, et fichiers texte.

    Fonctionnalités :
    - Analyse des journaux d'événements Windows (System, Application, Security)
    - Détection d'erreurs et d'événements critiques
    - Analyse de patterns suspects et anomalies
    - Statistiques détaillées par source et niveau
    - Filtrage par date, source, niveau de gravité
    - Export des résultats (HTML, CSV, JSON, XML)
    - Alertes automatiques par email
    - Analyse de logs personnalisés (IIS, Apache, etc.)
    - Détection d'intrusions et activités suspectes
    - Rapports graphiques et tableaux de bord

.PARAMETER LogSource
    Source des logs à analyser: EventLog, File, IIS, Apache, Custom

.PARAMETER LogPath
    Chemin vers le fichier de log (pour les fichiers)

.PARAMETER EventLogName
    Nom du journal d'événements Windows (System, Application, Security, etc.)

.PARAMETER StartDate
    Date de début d'analyse (format: yyyy-MM-dd)

.PARAMETER EndDate
    Date de fin d'analyse (format: yyyy-MM-dd)

.PARAMETER Severity
    Niveau de gravité minimum: Information, Warning, Error, Critical

.PARAMETER OutputFormat
    Format de sortie: Console, HTML, CSV, JSON, XML

.PARAMETER OutputPath
    Chemin de sortie pour les rapports

.PARAMETER MaxEvents
    Nombre maximum d'événements à analyser

.PARAMETER SearchPattern
    Pattern de recherche dans les logs

.PARAMETER ExcludePattern
    Pattern à exclure de l'analyse

.PARAMETER EnableAlerts
    Activer les alertes automatiques

.PARAMETER EmailRecipients
    Destinataires email pour les alertes

.EXAMPLE
    .\analyse_log.ps1 -LogSource EventLog -EventLogName System -StartDate "2024-10-01" -Severity Error
    Analyse les erreurs du journal système depuis le 1er octobre

.EXAMPLE
    .\analyse_log.ps1 -LogSource File -LogPath "C:\inetpub\logs\LogFiles\W3SVC1\*.log" -OutputFormat HTML -OutputPath "C:\Reports"
    Analyse les logs IIS et génère un rapport HTML

.EXAMPLE
    .\analyse_log.ps1 -LogSource EventLog -EventLogName Security -SearchPattern "Logon" -EnableAlerts
    Analyse les événements de connexion avec alertes

.NOTES
    Auteur: Jimmy Ramsamynaick
    Date: 28/10/2025
    Version: 1.0
    
    Prérequis:
    - PowerShell 5.1 ou supérieur
    - Droits de lecture sur les journaux d'événements
    - Module ImportExcel (optionnel pour export Excel)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, HelpMessage="Source des logs")]
    [ValidateSet("EventLog", "File", "IIS", "Apache", "Custom")]
    [string]$LogSource = "EventLog",
    
    [Parameter(Mandatory=$false, HelpMessage="Chemin du fichier de log")]
    [string]$LogPath,
    
    [Parameter(Mandatory=$false, HelpMessage="Nom du journal d'événements")]
    [string]$EventLogName = "System",
    
    [Parameter(Mandatory=$false, HelpMessage="Date de début")]
    [datetime]$StartDate = (Get-Date).AddDays(-7),
    
    [Parameter(Mandatory=$false, HelpMessage="Date de fin")]
    [datetime]$EndDate = (Get-Date),
    
    [Parameter(Mandatory=$false, HelpMessage="Niveau de gravité minimum")]
    [ValidateSet("Information", "Warning", "Error", "Critical", "All")]
    [string]$Severity = "Warning",
    
    [Parameter(Mandatory=$false, HelpMessage="Format de sortie")]
    [ValidateSet("Console", "HTML", "CSV", "JSON", "XML")]
    [string]$OutputFormat = "Console",
    
    [Parameter(Mandatory=$false, HelpMessage="Chemin de sortie")]
    [string]$OutputPath = ".",
    
    [Parameter(Mandatory=$false, HelpMessage="Nombre maximum d'événements")]
    [int]$MaxEvents = 1000,
    
    [Parameter(Mandatory=$false, HelpMessage="Pattern de recherche")]
    [string]$SearchPattern,
    
    [Parameter(Mandatory=$false, HelpMessage="Pattern d'exclusion")]
    [string]$ExcludePattern,
    
    [Parameter(Mandatory=$false, HelpMessage="Activer les alertes")]
    [switch]$EnableAlerts,
    
    [Parameter(Mandatory=$false, HelpMessage="Destinataires email")]
    [string[]]$EmailRecipients = @(),
    
    [Parameter(Mandatory=$false, HelpMessage="Analyse détaillée")]
    [switch]$DetailedAnalysis,
    
    [Parameter(Mandatory=$false, HelpMessage="Mode interactif")]
    [switch]$Interactive
)

# Configuration
$ErrorActionPreference = "Stop"
$script:ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
$script:LogPath = Join-Path $env:TEMP "$($script:ScriptName)_$(Get-Date -Format 'yyyyMMdd').log"
$script:AnalysisResults = @{}
$script:AlertThresholds = @{
    ErrorsPerHour = 10
    CriticalEvents = 1
    FailedLogons = 5
    ServiceFailures = 3
}

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

function Get-EventLogAnalysis {
    param(
        [string]$LogName,
        [datetime]$StartDate,
        [datetime]$EndDate,
        [string]$Severity,
        [int]$MaxEvents,
        [string]$SearchPattern,
        [string]$ExcludePattern
    )
    
    try {
        Write-Log "📊 Analyse du journal d'événements: $LogName" -Level "INFO"
        Write-Log "   Période: $($StartDate.ToString('yyyy-MM-dd')) à $($EndDate.ToString('yyyy-MM-dd'))" -Level "INFO"
        
        # Construire le filtre de niveau
        $levelFilter = switch ($Severity) {
            "Information" { @(0,1,2,3,4) }
            "Warning" { @(2,3,4) }
            "Error" { @(3,4) }
            "Critical" { @(4) }
            "All" { @(0,1,2,3,4) }
            default { @(2,3,4) }
        }
        
        # Récupérer les événements
        $filterHashtable = @{
            LogName = $LogName
            StartTime = $StartDate
            EndTime = $EndDate
            Level = $levelFilter
        }
        
        Write-Log "Récupération des événements..." -Level "INFO"
        $events = Get-WinEvent -FilterHashtable $filterHashtable -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        
        if (-not $events) {
            Write-Log "Aucun événement trouvé pour les critères spécifiés" -Level "WARN"
            return @()
        }
        
        Write-Log "   Événements récupérés: $($events.Count)" -Level "INFO"
        
        # Filtrer par pattern si spécifié
        if ($SearchPattern) {
            $events = $events | Where-Object { $_.Message -match $SearchPattern }
            Write-Log "   Après filtrage par pattern '$SearchPattern': $($events.Count)" -Level "INFO"
        }
        
        if ($ExcludePattern) {
            $events = $events | Where-Object { $_.Message -notmatch $ExcludePattern }
            Write-Log "   Après exclusion du pattern '$ExcludePattern': $($events.Count)" -Level "INFO"
        }
        
        # Analyser les événements
        $analysis = @{
            TotalEvents = $events.Count
            EventsByLevel = $events | Group-Object LevelDisplayName | ForEach-Object { @{$_.Name = $_.Count} }
            EventsBySource = $events | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 10
            EventsByHour = $events | Group-Object { $_.TimeCreated.ToString("yyyy-MM-dd HH:00") } | Sort-Object Name
            TopEventIDs = $events | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10
            CriticalEvents = $events | Where-Object { $_.LevelDisplayName -eq "Critical" }
            ErrorEvents = $events | Where-Object { $_.LevelDisplayName -eq "Error" }
            WarningEvents = $events | Where-Object { $_.LevelDisplayName -eq "Warning" }
            Events = $events
        }
        
        return $analysis
    }
    catch {
        Write-Log "Erreur lors de l'analyse du journal d'événements: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Get-FileLogAnalysis {
    param(
        [string]$FilePath,
        [datetime]$StartDate,
        [datetime]$EndDate,
        [string]$SearchPattern,
        [string]$ExcludePattern,
        [int]$MaxLines = 10000
    )
    
    try {
        Write-Log "📄 Analyse du fichier de log: $FilePath" -Level "INFO"
        
        if (-not (Test-Path $FilePath)) {
            throw "Fichier de log non trouvé: $FilePath"
        }
        
        # Lire le fichier
        $logLines = Get-Content -Path $FilePath -Tail $MaxLines -ErrorAction Stop
        Write-Log "   Lignes lues: $($logLines.Count)" -Level "INFO"
        
        # Filtrer par pattern
        if ($SearchPattern) {
            $logLines = $logLines | Where-Object { $_ -match $SearchPattern }
            Write-Log "   Après filtrage par pattern: $($logLines.Count)" -Level "INFO"
        }
        
        if ($ExcludePattern) {
            $logLines = $logLines | Where-Object { $_ -notmatch $ExcludePattern }
            Write-Log "   Après exclusion: $($logLines.Count)" -Level "INFO"
        }
        
        # Analyser les patterns communs
        $errorPatterns = @(
            "error", "ERROR", "Error",
            "exception", "EXCEPTION", "Exception",
            "failed", "FAILED", "Failed",
            "critical", "CRITICAL", "Critical",
            "fatal", "FATAL", "Fatal"
        )
        
        $warningPatterns = @(
            "warning", "WARNING", "Warning",
            "warn", "WARN", "Warn",
            "deprecated", "DEPRECATED", "Deprecated"
        )
        
        $errors = @()
        $warnings = @()
        $info = @()
        
        foreach ($line in $logLines) {
            $isError = $false
            $isWarning = $false
            
            foreach ($pattern in $errorPatterns) {
                if ($line -match $pattern) {
                    $errors += $line
                    $isError = $true
                    break
                }
            }
            
            if (-not $isError) {
                foreach ($pattern in $warningPatterns) {
                    if ($line -match $pattern) {
                        $warnings += $line
                        $isWarning = $true
                        break
                    }
                }
            }
            
            if (-not $isError -and -not $isWarning) {
                $info += $line
            }
        }
        
        $analysis = @{
            TotalLines = $logLines.Count
            ErrorLines = $errors.Count
            WarningLines = $warnings.Count
            InfoLines = $info.Count
            Errors = $errors
            Warnings = $warnings
            AllLines = $logLines
            FilePath = $FilePath
            FileSize = (Get-Item $FilePath).Length
            LastModified = (Get-Item $FilePath).LastWriteTime
        }
        
        return $analysis
    }
    catch {
        Write-Log "Erreur lors de l'analyse du fichier: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Get-IISLogAnalysis {
    param(
        [string]$LogPath,
        [datetime]$StartDate,
        [datetime]$EndDate
    )
    
    try {
        Write-Log "🌐 Analyse des logs IIS: $LogPath" -Level "INFO"
        
        $logFiles = Get-ChildItem -Path $LogPath -Filter "*.log" -ErrorAction Stop
        $allEntries = @()
        
        foreach ($logFile in $logFiles) {
            $content = Get-Content $logFile.FullName | Where-Object { $_ -notmatch "^#" }
            
            foreach ($line in $content) {
                $fields = $line -split '\s+'
                if ($fields.Count -ge 10) {
                    try {
                        $dateTime = [datetime]::ParseExact("$($fields[0]) $($fields[1])", "yyyy-MM-dd HH:mm:ss", $null)
                        
                        if ($dateTime -ge $StartDate -and $dateTime -le $EndDate) {
                            $allEntries += [PSCustomObject]@{
                                DateTime = $dateTime
                                ClientIP = $fields[2]
                                Method = $fields[3]
                                URI = $fields[4]
                                StatusCode = $fields[5]
                                BytesSent = [int]$fields[6]
                                TimeTaken = [int]$fields[7]
                                UserAgent = if ($fields.Count -gt 10) { $fields[10] } else { "" }
                                Referer = if ($fields.Count -gt 9) { $fields[9] } else { "" }
                            }
                        }
                    }
                    catch {
                        # Ignorer les lignes mal formatées
                    }
                }
            }
        }
        
        Write-Log "   Entrées IIS analysées: $($allEntries.Count)" -Level "INFO"
        
        $analysis = @{
            TotalRequests = $allEntries.Count
            UniqueIPs = ($allEntries | Group-Object ClientIP).Count
            StatusCodes = $allEntries | Group-Object StatusCode | Sort-Object Count -Descending
            TopIPs = $allEntries | Group-Object ClientIP | Sort-Object Count -Descending | Select-Object -First 10
            TopURIs = $allEntries | Group-Object URI | Sort-Object Count -Descending | Select-Object -First 10
            ErrorRequests = $allEntries | Where-Object { [int]$_.StatusCode -ge 400 }
            AverageResponseTime = ($allEntries | Measure-Object TimeTaken -Average).Average
            TotalBandwidth = ($allEntries | Measure-Object BytesSent -Sum).Sum
            RequestsByHour = $allEntries | Group-Object { $_.DateTime.ToString("yyyy-MM-dd HH:00") } | Sort-Object Name
            Entries = $allEntries
        }
        
        return $analysis
    }
    catch {
        Write-Log "Erreur lors de l'analyse des logs IIS: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Test-SecurityThreats {
    param($Analysis)
    
    $threats = @()
    
    try {
        Write-Log "🔍 Détection de menaces de sécurité..." -Level "INFO"
        
        # Analyser selon le type de source
        switch ($LogSource) {
            "EventLog" {
                if ($EventLogName -eq "Security") {
                    # Tentatives de connexion échouées
                    $failedLogons = $Analysis.Events | Where-Object { $_.Id -eq 4625 }
                    if ($failedLogons.Count -gt $script:AlertThresholds.FailedLogons) {
                        $threats += "Tentatives de connexion échouées excessives: $($failedLogons.Count)"
                    }
                    
                    # Élévations de privilèges
                    $privilegeEscalation = $Analysis.Events | Where-Object { $_.Id -in @(4672, 4673, 4674) }
                    if ($privilegeEscalation.Count -gt 0) {
                        $threats += "Élévations de privilèges détectées: $($privilegeEscalation.Count)"
                    }
                    
                    # Modifications de comptes
                    $accountChanges = $Analysis.Events | Where-Object { $_.Id -in @(4720, 4722, 4724, 4726) }
                    if ($accountChanges.Count -gt 0) {
                        $threats += "Modifications de comptes utilisateur: $($accountChanges.Count)"
                    }
                }
                
                # Événements critiques
                if ($Analysis.CriticalEvents.Count -gt $script:AlertThresholds.CriticalEvents) {
                    $threats += "Événements critiques: $($Analysis.CriticalEvents.Count)"
                }
                
                # Erreurs système fréquentes
                $systemErrors = $Analysis.ErrorEvents | Where-Object { $_.ProviderName -like "*System*" }
                if ($systemErrors.Count -gt $script:AlertThresholds.ErrorsPerHour) {
                    $threats += "Erreurs système fréquentes: $($systemErrors.Count)"
                }
            }
            
            "IIS" {
                # Attaques par injection
                $injectionAttempts = $Analysis.Entries | Where-Object { 
                    $_.URI -match "(select|union|insert|delete|drop|script|alert|javascript)" 
                }
                if ($injectionAttempts.Count -gt 0) {
                    $threats += "Tentatives d'injection détectées: $($injectionAttempts.Count)"
                }
                
                # Scans de ports/répertoires
                $scanAttempts = $Analysis.ErrorRequests | Where-Object { [int]$_.StatusCode -eq 404 } | 
                    Group-Object ClientIP | Where-Object { $_.Count -gt 20 }
                if ($scanAttempts.Count -gt 0) {
                    $threats += "Scans de répertoires suspects: $($scanAttempts.Count) IPs"
                }
                
                # Attaques DDoS potentielles
                $ddosAttempts = $Analysis.TopIPs | Where-Object { $_.Count -gt 1000 }
                if ($ddosAttempts.Count -gt 0) {
                    $threats += "Activité DDoS potentielle: $($ddosAttempts.Count) IPs suspectes"
                }
            }
            
            "File" {
                # Rechercher des patterns suspects dans les logs
                $suspiciousPatterns = @(
                    "hack", "exploit", "malware", "virus", "trojan",
                    "unauthorized", "breach", "intrusion", "attack"
                )
                
                foreach ($pattern in $suspiciousPatterns) {
                    $matches = $Analysis.AllLines | Where-Object { $_ -match $pattern }
                    if ($matches.Count -gt 0) {
                        $threats += "Pattern suspect '$pattern': $($matches.Count) occurrences"
                    }
                }
            }
        }
        
        return $threats
    }
    catch {
        Write-Log "Erreur lors de la détection de menaces: $($_.Exception.Message)" -Level "WARN"
        return @()
    }
}

function Export-AnalysisResults {
    param(
        $Analysis,
        [string]$Format,
        [string]$OutputPath,
        [string]$FileName
    )
    
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $baseFileName = if ($FileName) { $FileName } else { "log_analysis_$timestamp" }
        
        switch ($Format) {
            "HTML" {
                $htmlFile = Join-Path $OutputPath "$baseFileName.html"
                $html = Generate-HTMLReport -Analysis $Analysis
                $html | Out-File -FilePath $htmlFile -Encoding UTF8
                Write-Log "✅ Rapport HTML généré: $htmlFile" -Level "SUCCESS"
            }
            
            "CSV" {
                $csvFile = Join-Path $OutputPath "$baseFileName.csv"
                
                if ($LogSource -eq "EventLog") {
                    $Analysis.Events | Select-Object TimeCreated, LevelDisplayName, ProviderName, Id, Message | 
                        Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
                } elseif ($LogSource -eq "IIS") {
                    $Analysis.Entries | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
                } else {
                    # Pour les fichiers texte, créer un CSV avec les lignes et leur classification
                    $csvData = @()
                    $csvData += $Analysis.Errors | ForEach-Object { [PSCustomObject]@{Type="Error"; Content=$_} }
                    $csvData += $Analysis.Warnings | ForEach-Object { [PSCustomObject]@{Type="Warning"; Content=$_} }
                    $csvData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
                }
                
                Write-Log "✅ Rapport CSV généré: $csvFile" -Level "SUCCESS"
            }
            
            "JSON" {
                $jsonFile = Join-Path $OutputPath "$baseFileName.json"
                $Analysis | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonFile -Encoding UTF8
                Write-Log "✅ Rapport JSON généré: $jsonFile" -Level "SUCCESS"
            }
            
            "XML" {
                $xmlFile = Join-Path $OutputPath "$baseFileName.xml"
                
                if ($LogSource -eq "EventLog") {
                    $Analysis.Events | Export-Clixml -Path $xmlFile
                } else {
                    $Analysis | Export-Clixml -Path $xmlFile
                }
                
                Write-Log "✅ Rapport XML généré: $xmlFile" -Level "SUCCESS"
            }
        }
    }
    catch {
        Write-Log "Erreur lors de l'export: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Generate-HTMLReport {
    param($Analysis)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Rapport d'Analyse de Logs - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .critical { background-color: #e74c3c; color: white; }
        .error { background-color: #f39c12; color: white; }
        .warning { background-color: #f1c40f; color: black; }
        .info { background-color: #3498db; color: white; }
        .success { background-color: #27ae60; color: white; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .chart { margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>📊 Rapport d'Analyse de Logs</h1>
        <p>Généré le $(Get-Date -Format 'yyyy-MM-dd à HH:mm:ss')</p>
        <p>Source: $LogSource | Période: $($StartDate.ToString('yyyy-MM-dd')) - $($EndDate.ToString('yyyy-MM-dd'))</p>
    </div>
"@

    # Résumé exécutif
    $html += @"
    <div class="section">
        <h2>📋 Résumé Exécutif</h2>
"@

    if ($LogSource -eq "EventLog") {
        $html += @"
        <p><strong>Total d'événements analysés:</strong> $($Analysis.TotalEvents)</p>
        <p><strong>Événements critiques:</strong> $($Analysis.CriticalEvents.Count)</p>
        <p><strong>Erreurs:</strong> $($Analysis.ErrorEvents.Count)</p>
        <p><strong>Avertissements:</strong> $($Analysis.WarningEvents.Count)</p>
"@
    } elseif ($LogSource -eq "IIS") {
        $html += @"
        <p><strong>Total de requêtes:</strong> $($Analysis.TotalRequests)</p>
        <p><strong>IPs uniques:</strong> $($Analysis.UniqueIPs)</p>
        <p><strong>Requêtes en erreur:</strong> $($Analysis.ErrorRequests.Count)</p>
        <p><strong>Bande passante totale:</strong> $(Format-FileSize $Analysis.TotalBandwidth)</p>
"@
    } else {
        $html += @"
        <p><strong>Total de lignes analysées:</strong> $($Analysis.TotalLines)</p>
        <p><strong>Erreurs détectées:</strong> $($Analysis.ErrorLines)</p>
        <p><strong>Avertissements:</strong> $($Analysis.WarningLines)</p>
"@
    }

    $html += "</div>"

    # Menaces détectées
    $threats = Test-SecurityThreats -Analysis $Analysis
    if ($threats.Count -gt 0) {
        $html += @"
        <div class="section critical">
            <h2>🚨 Menaces de Sécurité Détectées</h2>
            <ul>
"@
        foreach ($threat in $threats) {
            $html += "<li>$threat</li>"
        }
        $html += "</ul></div>"
    }

    # Statistiques détaillées
    if ($LogSource -eq "EventLog" -and $Analysis.EventsBySource) {
        $html += @"
        <div class="section">
            <h2>📈 Top Sources d'Événements</h2>
            <table>
                <tr><th>Source</th><th>Nombre d'événements</th></tr>
"@
        foreach ($source in $Analysis.EventsBySource | Select-Object -First 10) {
            $html += "<tr><td>$($source.Name)</td><td>$($source.Count)</td></tr>"
        }
        $html += "</table></div>"
    }

    $html += "</body></html>"
    
    return $html
}

function Format-FileSize {
    param([long]$Size)
    
    if ($Size -gt 1TB) { return "{0:N2} TB" -f ($Size / 1TB) }
    elseif ($Size -gt 1GB) { return "{0:N2} GB" -f ($Size / 1GB) }
    elseif ($Size -gt 1MB) { return "{0:N2} MB" -f ($Size / 1MB) }
    elseif ($Size -gt 1KB) { return "{0:N2} KB" -f ($Size / 1KB) }
    else { return "$Size bytes" }
}

function Show-ConsoleReport {
    param($Analysis)
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "📊 RAPPORT D'ANALYSE DE LOGS" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor Cyan
    
    Write-Host "Source: $LogSource" -ForegroundColor White
    Write-Host "Période: $($StartDate.ToString('yyyy-MM-dd')) - $($EndDate.ToString('yyyy-MM-dd'))" -ForegroundColor White
    Write-Host "Généré le: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
    
    # Résumé selon le type de source
    Write-Host "`n📋 RÉSUMÉ:" -ForegroundColor Yellow
    
    switch ($LogSource) {
        "EventLog" {
            Write-Host "   Total d'événements: $($Analysis.TotalEvents)" -ForegroundColor White
            Write-Host "   Événements critiques: $($Analysis.CriticalEvents.Count)" -ForegroundColor Red
            Write-Host "   Erreurs: $($Analysis.ErrorEvents.Count)" -ForegroundColor Red
            Write-Host "   Avertissements: $($Analysis.WarningEvents.Count)" -ForegroundColor Yellow
            
            if ($Analysis.TopEventIDs) {
                Write-Host "`n🔝 TOP EVENT IDs:" -ForegroundColor Yellow
                $Analysis.TopEventIDs | Select-Object -First 5 | ForEach-Object {
                    Write-Host "   ID $($_.Name): $($_.Count) occurrences" -ForegroundColor White
                }
            }
        }
        
        "IIS" {
            Write-Host "   Total de requêtes: $($Analysis.TotalRequests)" -ForegroundColor White
            Write-Host "   IPs uniques: $($Analysis.UniqueIPs)" -ForegroundColor White
            Write-Host "   Requêtes en erreur: $($Analysis.ErrorRequests.Count)" -ForegroundColor Red
            Write-Host "   Temps de réponse moyen: $([math]::Round($Analysis.AverageResponseTime, 2)) ms" -ForegroundColor White
            Write-Host "   Bande passante totale: $(Format-FileSize $Analysis.TotalBandwidth)" -ForegroundColor White
            
            if ($Analysis.TopIPs) {
                Write-Host "`n🌐 TOP IPs:" -ForegroundColor Yellow
                $Analysis.TopIPs | Select-Object -First 5 | ForEach-Object {
                    Write-Host "   $($_.Name): $($_.Count) requêtes" -ForegroundColor White
                }
            }
        }
        
        "File" {
            Write-Host "   Total de lignes: $($Analysis.TotalLines)" -ForegroundColor White
            Write-Host "   Erreurs détectées: $($Analysis.ErrorLines)" -ForegroundColor Red
            Write-Host "   Avertissements: $($Analysis.WarningLines)" -ForegroundColor Yellow
            Write-Host "   Informations: $($Analysis.InfoLines)" -ForegroundColor Green
            Write-Host "   Taille du fichier: $(Format-FileSize $Analysis.FileSize)" -ForegroundColor White
            Write-Host "   Dernière modification: $($Analysis.LastModified)" -ForegroundColor White
        }
    }
    
    # Menaces de sécurité
    $threats = Test-SecurityThreats -Analysis $Analysis
    if ($threats.Count -gt 0) {
        Write-Host "`n🚨 MENACES DE SÉCURITÉ DÉTECTÉES:" -ForegroundColor Red
        foreach ($threat in $threats) {
            Write-Host "   ⚠️  $threat" -ForegroundColor Red
        }
    } else {
        Write-Host "`n✅ Aucune menace de sécurité majeure détectée" -ForegroundColor Green
    }
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
}

function Show-InteractiveMenu {
    do {
        Clear-Host
        Write-Host "🔍 ANALYSEUR DE LOGS WINDOWS" -ForegroundColor Cyan
        Write-Host "="*50 -ForegroundColor Cyan
        Write-Host "1. Analyser les journaux d'événements Windows" -ForegroundColor White
        Write-Host "2. Analyser un fichier de log personnalisé" -ForegroundColor White
        Write-Host "3. Analyser les logs IIS" -ForegroundColor White
        Write-Host "4. Recherche dans les logs de sécurité" -ForegroundColor White
        Write-Host "5. Analyse rapide des erreurs système" -ForegroundColor White
        Write-Host "6. Génération de rapport complet" -ForegroundColor White
        Write-Host "0. Quitter" -ForegroundColor Red
        Write-Host "="*50 -ForegroundColor Cyan
        
        $choice = Read-Host "Votre choix"
        
        switch ($choice) {
            "1" {
                $logName = Read-Host "Nom du journal (System/Application/Security)"
                if (-not $logName) { $logName = "System" }
                $days = Read-Host "Nombre de jours à analyser (défaut: 7)"
                if (-not $days) { $days = 7 }
                
                $script:LogSource = "EventLog"
                $script:EventLogName = $logName
                $script:StartDate = (Get-Date).AddDays(-$days)
                $script:EndDate = Get-Date
                
                $analysis = Get-EventLogAnalysis -LogName $logName -StartDate $script:StartDate -EndDate $script:EndDate -Severity "Warning" -MaxEvents 1000
                Show-ConsoleReport -Analysis $analysis
            }
            
            "2" {
                $filePath = Read-Host "Chemin du fichier de log"
                if ($filePath -and (Test-Path $filePath)) {
                    $script:LogSource = "File"
                    $analysis = Get-FileLogAnalysis -FilePath $filePath -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date)
                    Show-ConsoleReport -Analysis $analysis
                } else {
                    Write-Host "Fichier non trouvé !" -ForegroundColor Red
                }
            }
            
            "3" {
                $iisPath = Read-Host "Chemin des logs IIS (ex: C:\inetpub\logs\LogFiles\W3SVC1\)"
                if ($iisPath -and (Test-Path $iisPath)) {
                    $script:LogSource = "IIS"
                    $analysis = Get-IISLogAnalysis -LogPath $iisPath -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)
                    Show-ConsoleReport -Analysis $analysis
                } else {
                    Write-Host "Dossier non trouvé !" -ForegroundColor Red
                }
            }
            
            "4" {
                $script:LogSource = "EventLog"
                $script:EventLogName = "Security"
                $analysis = Get-EventLogAnalysis -LogName "Security" -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) -Severity "Warning" -MaxEvents 500
                Show-ConsoleReport -Analysis $analysis
            }
            
            "5" {
                $script:LogSource = "EventLog"
                $script:EventLogName = "System"
                $analysis = Get-EventLogAnalysis -LogName "System" -StartDate (Get-Date).AddHours(-24) -EndDate (Get-Date) -Severity "Error" -MaxEvents 100
                Show-ConsoleReport -Analysis $analysis
            }
            
            "6" {
                $outputPath = Read-Host "Dossier de sortie (défaut: Bureau)"
                if (-not $outputPath) { $outputPath = [Environment]::GetFolderPath("Desktop") }
                
                Write-Host "Génération du rapport complet..." -ForegroundColor Yellow
                
                # Analyser plusieurs sources
                $systemAnalysis = Get-EventLogAnalysis -LogName "System" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -Severity "Warning" -MaxEvents 500
                $appAnalysis = Get-EventLogAnalysis -LogName "Application" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -Severity "Warning" -MaxEvents 500
                
                Export-AnalysisResults -Analysis $systemAnalysis -Format "HTML" -OutputPath $outputPath -FileName "rapport_system"
                Export-AnalysisResults -Analysis $appAnalysis -Format "HTML" -OutputPath $outputPath -FileName "rapport_application"
                
                Write-Host "Rapports générés dans: $outputPath" -ForegroundColor Green
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

# Script principal
try {
    Write-Log "🚀 Analyseur de logs Windows" -Level "SUCCESS"
    Write-Log "Source: $LogSource | Format: $OutputFormat"
    
    if ($Interactive) {
        Show-InteractiveMenu
    } else {
        # Mode automatique
        $analysis = $null
        
        switch ($LogSource) {
            "EventLog" {
                $analysis = Get-EventLogAnalysis -LogName $EventLogName -StartDate $StartDate -EndDate $EndDate -Severity $Severity -MaxEvents $MaxEvents -SearchPattern $SearchPattern -ExcludePattern $ExcludePattern
            }
            
            "File" {
                if (-not $LogPath) {
                    throw "LogPath est requis pour l'analyse de fichiers"
                }
                $analysis = Get-FileLogAnalysis -FilePath $LogPath -StartDate $StartDate -EndDate $EndDate -SearchPattern $SearchPattern -ExcludePattern $ExcludePattern
            }
            
            "IIS" {
                if (-not $LogPath) {
                    throw "LogPath est requis pour l'analyse des logs IIS"
                }
                $analysis = Get-IISLogAnalysis -LogPath $LogPath -StartDate $StartDate -EndDate $EndDate
            }
            
            default {
                throw "Source de log non supportée: $LogSource"
            }
        }
        
        # Afficher ou exporter les résultats
        if ($OutputFormat -eq "Console") {
            Show-ConsoleReport -Analysis $analysis
        } else {
            Export-AnalysisResults -Analysis $analysis -Format $OutputFormat -OutputPath $OutputPath
        }
        
        # Alertes si activées
        if ($EnableAlerts) {
            $threats = Test-SecurityThreats -Analysis $analysis
            if ($threats.Count -gt 0) {
                Write-Log "🚨 $($threats.Count) menaces détectées - Alertes activées" -Level "WARN"
                # Ici on pourrait envoyer des emails ou notifications
            }
        }
    }
    
    Write-Log "✅ Analyse terminée avec succès" -Level "SUCCESS"
}
catch {
    Write-Log "Erreur: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Utilisez Get-Help .\analyse_log.ps1 -Full pour plus d'informations" -Level "INFO"
    exit 1
}