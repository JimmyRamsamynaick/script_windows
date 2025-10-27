<#
.SYNOPSIS
    Analyse des connexions SSH actives et de l'historique des connexions

.DESCRIPTION
    Ce script analyse les connexions SSH sur un système Windows en utilisant :
    - Les logs d'événements Windows
    - Les connexions réseau actives
    - L'historique des connexions SSH via OpenSSH
    - Les tentatives de connexion échouées

.PARAMETER LogPath
    Chemin vers les logs SSH personnalisés (optionnel)

.PARAMETER ExportPath
    Chemin pour exporter le rapport d'analyse

.PARAMETER Days
    Nombre de jours d'historique à analyser (défaut: 7)

.EXAMPLE
    .\analysSSH.ps1
    Analyse les connexions SSH des 7 derniers jours

.EXAMPLE
    .\analysSSH.ps1 -Days 30 -ExportPath "C:\Reports\ssh_analysis.html"
    Analyse sur 30 jours et exporte en HTML

.NOTES
    Auteur: Sameer
    Date: 28/10/2025
    Version: 1.0
    Prérequis: OpenSSH Server installé, droits administrateur
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "",
    
    [Parameter(Mandatory=$false)]
    [int]$Days = 7
)

# Configuration
$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

# Fonctions utilitaires
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "INFO"  { "Green" }
        "SUCCESS" { "Cyan" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Get-SSHActiveConnections {
    Write-Log "Recherche des connexions SSH actives..."
    try {
        $connections = Get-NetTCPConnection -LocalPort 22 -State Established -ErrorAction SilentlyContinue
        return $connections | ForEach-Object {
            [PSCustomObject]@{
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort = $_.RemotePort
                State = $_.State
                ProcessId = $_.OwningProcess
                ProcessName = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
                CreationTime = $_.CreationTime
            }
        }
    }
    catch {
        Write-Log "Erreur lors de la récupération des connexions actives: $($_.Exception.Message)" -Level "WARN"
        return @()
    }
}

function Get-SSHEventLogs {
    param([int]$DaysBack)
    
    Write-Log "Analyse des logs d'événements SSH (derniers $DaysBack jours)..."
    $startDate = (Get-Date).AddDays(-$DaysBack)
    
    try {
        # Logs OpenSSH Server
        $sshLogs = Get-WinEvent -FilterHashtable @{
            LogName = 'OpenSSH/Operational'
            StartTime = $startDate
        } -ErrorAction SilentlyContinue
        
        # Logs de sécurité Windows pour les connexions
        $securityLogs = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = @(4624, 4625, 4634)  # Logon success, failure, logoff
            StartTime = $startDate
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -like "*ssh*" -or $_.Message -like "*OpenSSH*"
        }
        
        return @{
            SSHLogs = $sshLogs
            SecurityLogs = $securityLogs
        }
    }
    catch {
        Write-Log "Erreur lors de la lecture des logs: $($_.Exception.Message)" -Level "WARN"
        return @{
            SSHLogs = @()
            SecurityLogs = @()
        }
    }
}

function Get-SSHFailedAttempts {
    param([int]$DaysBack)
    
    Write-Log "Recherche des tentatives de connexion échouées..."
    $startDate = (Get-Date).AddDays(-$DaysBack)
    
    try {
        $failedAttempts = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4625  # Failed logon
            StartTime = $startDate
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -like "*ssh*" -or $_.Message -like "*OpenSSH*"
        }
        
        return $failedAttempts | ForEach-Object {
            $message = $_.Message
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                SourceIP = if($message -match "Source Network Address:\s+([^\s]+)") { $matches[1] } else { "Unknown" }
                Username = if($message -match "Account Name:\s+([^\s]+)") { $matches[1] } else { "Unknown" }
                FailureReason = if($message -match "Failure Reason:\s+([^\r\n]+)") { $matches[1] } else { "Unknown" }
                ProcessName = if($message -match "Process Name:\s+([^\r\n]+)") { $matches[1] } else { "Unknown" }
            }
        }
    }
    catch {
        Write-Log "Erreur lors de la recherche des tentatives échouées: $($_.Exception.Message)" -Level "WARN"
        return @()
    }
}

function Get-SSHConfiguration {
    Write-Log "Vérification de la configuration SSH..."
    
    $sshConfig = @{
        ServiceStatus = "Non installé"
        ConfigFile = ""
        Port = 22
        AuthMethods = @()
        AllowUsers = @()
        DenyUsers = @()
    }
    
    try {
        # Vérifier le service OpenSSH
        $service = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
        if ($service) {
            $sshConfig.ServiceStatus = $service.Status
        }
        
        # Lire le fichier de configuration
        $configPath = "$env:ProgramData\ssh\sshd_config"
        if (Test-Path $configPath) {
            $sshConfig.ConfigFile = $configPath
            $configContent = Get-Content $configPath
            
            foreach ($line in $configContent) {
                if ($line -match "^Port\s+(\d+)") {
                    $sshConfig.Port = [int]$matches[1]
                }
                elseif ($line -match "^AuthenticationMethods\s+(.+)") {
                    $sshConfig.AuthMethods = $matches[1] -split '\s+'
                }
                elseif ($line -match "^AllowUsers\s+(.+)") {
                    $sshConfig.AllowUsers = $matches[1] -split '\s+'
                }
                elseif ($line -match "^DenyUsers\s+(.+)") {
                    $sshConfig.DenyUsers = $matches[1] -split '\s+'
                }
            }
        }
        
        return $sshConfig
    }
    catch {
        Write-Log "Erreur lors de la lecture de la configuration: $($_.Exception.Message)" -Level "WARN"
        return $sshConfig
    }
}

function Export-SSHReport {
    param(
        [object]$ActiveConnections,
        [object]$EventLogs,
        [object]$FailedAttempts,
        [object]$Configuration,
        [string]$ExportPath
    )
    
    Write-Log "Génération du rapport d'analyse SSH..."
    
    $report = @"
<!DOCTYPE html>
<html>
<head>
    <title>Rapport d'Analyse SSH - $(Get-Date -Format 'dd/MM/yyyy HH:mm')</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .danger { background-color: #f8d7da; border-color: #f5c6cb; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .metric { display: inline-block; margin: 10px; padding: 15px; background: #f8f9fa; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Rapport d'Analyse SSH</h1>
        <p>Généré le $(Get-Date -Format 'dd/MM/yyyy à HH:mm:ss')</p>
        <p>Période d'analyse: $(Get-Date).AddDays(-$Days) au $(Get-Date)</p>
    </div>

    <div class="section">
        <h2>📊 Métriques Générales</h2>
        <div class="metric">
            <strong>Connexions Actives:</strong> $($ActiveConnections.Count)
        </div>
        <div class="metric">
            <strong>Tentatives Échouées:</strong> $($FailedAttempts.Count)
        </div>
        <div class="metric">
            <strong>Service SSH:</strong> $($Configuration.ServiceStatus)
        </div>
        <div class="metric">
            <strong>Port SSH:</strong> $($Configuration.Port)
        </div>
    </div>

    <div class="section $(if($ActiveConnections.Count -gt 0){'warning'}else{'success'})">
        <h2>🔗 Connexions SSH Actives ($($ActiveConnections.Count))</h2>
        $(if($ActiveConnections.Count -gt 0) {
            "<table><tr><th>IP Distante</th><th>Port Distant</th><th>Processus</th><th>Heure de Création</th></tr>"
            foreach($conn in $ActiveConnections) {
                "<tr><td>$($conn.RemoteAddress)</td><td>$($conn.RemotePort)</td><td>$($conn.ProcessName) (PID: $($conn.ProcessId))</td><td>$($conn.CreationTime)</td></tr>"
            }
            "</table>"
        } else {
            "<p>✅ Aucune connexion SSH active détectée.</p>"
        })
    </div>

    <div class="section $(if($FailedAttempts.Count -gt 10){'danger'}elseif($FailedAttempts.Count -gt 0){'warning'}else{'success'})">
        <h2>❌ Tentatives de Connexion Échouées ($($FailedAttempts.Count))</h2>
        $(if($FailedAttempts.Count -gt 0) {
            "<table><tr><th>Date/Heure</th><th>IP Source</th><th>Utilisateur</th><th>Raison</th></tr>"
            foreach($attempt in ($FailedAttempts | Select-Object -First 20)) {
                "<tr><td>$($attempt.TimeCreated)</td><td>$($attempt.SourceIP)</td><td>$($attempt.Username)</td><td>$($attempt.FailureReason)</td></tr>"
            }
            "</table>"
            if($FailedAttempts.Count -gt 20) {
                "<p><em>... et $($FailedAttempts.Count - 20) autres tentatives</em></p>"
            }
        } else {
            "<p>✅ Aucune tentative de connexion échouée détectée.</p>"
        })
    </div>

    <div class="section">
        <h2>⚙️ Configuration SSH</h2>
        <table>
            <tr><th>Paramètre</th><th>Valeur</th></tr>
            <tr><td>Statut du Service</td><td>$($Configuration.ServiceStatus)</td></tr>
            <tr><td>Port d'Écoute</td><td>$($Configuration.Port)</td></tr>
            <tr><td>Fichier de Config</td><td>$($Configuration.ConfigFile)</td></tr>
            <tr><td>Méthodes d'Auth</td><td>$($Configuration.AuthMethods -join ', ')</td></tr>
            <tr><td>Utilisateurs Autorisés</td><td>$($Configuration.AllowUsers -join ', ')</td></tr>
            <tr><td>Utilisateurs Interdits</td><td>$($Configuration.DenyUsers -join ', ')</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>💡 Recommandations</h2>
        <ul>
            $(if($FailedAttempts.Count -gt 10) { "<li>⚠️ Nombre élevé de tentatives échouées détecté. Considérez l'implémentation de Fail2Ban.</li>" })
            $(if($Configuration.Port -eq 22) { "<li>💡 Considérez changer le port SSH par défaut (22) pour réduire les attaques automatisées.</li>" })
            $(if($Configuration.AuthMethods.Count -eq 0) { "<li>🔐 Configurez l'authentification par clés SSH pour plus de sécurité.</li>" })
            $(if($ActiveConnections.Count -gt 5) { "<li>👥 Nombre élevé de connexions actives. Vérifiez si toutes sont légitimes.</li>" })
            <li>📝 Activez la journalisation détaillée SSH pour un meilleur suivi.</li>
            <li>🔄 Effectuez cette analyse régulièrement pour détecter les anomalies.</li>
        </ul>
    </div>

    <div class="section">
        <p><em>Rapport généré par analysSSH.ps1 - Version 1.0</em></p>
    </div>
</body>
</html>
"@

    try {
        $report | Out-File -FilePath $ExportPath -Encoding UTF8
        Write-Log "Rapport exporté vers: $ExportPath" -Level "SUCCESS"
    }
    catch {
        Write-Log "Erreur lors de l'export: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Script principal
try {
    Write-Log "🔐 Début de l'analyse SSH" -Level "SUCCESS"
    Write-Log "Période d'analyse: $Days derniers jours"
    
    # Vérification des prérequis
    if (-not (Get-Command "Get-NetTCPConnection" -ErrorAction SilentlyContinue)) {
        throw "Commande Get-NetTCPConnection non disponible. Windows 8/Server 2012 minimum requis."
    }
    
    # Collecte des données
    $activeConnections = Get-SSHActiveConnections
    $eventLogs = Get-SSHEventLogs -DaysBack $Days
    $failedAttempts = Get-SSHFailedAttempts -DaysBack $Days
    $configuration = Get-SSHConfiguration
    
    # Affichage des résultats
    Write-Host "`n" -NoNewline
    Write-Log "=== RÉSULTATS DE L'ANALYSE SSH ===" -Level "SUCCESS"
    Write-Log "Connexions actives: $($activeConnections.Count)"
    Write-Log "Tentatives échouées: $($failedAttempts.Count)"
    Write-Log "Service SSH: $($configuration.ServiceStatus)"
    Write-Log "Port configuré: $($configuration.Port)"
    
    if ($activeConnections.Count -gt 0) {
        Write-Host "`nConnexions SSH actives:" -ForegroundColor Yellow
        $activeConnections | Format-Table RemoteAddress, RemotePort, ProcessName, CreationTime -AutoSize
    }
    
    if ($failedAttempts.Count -gt 0) {
        Write-Host "`nDernières tentatives échouées:" -ForegroundColor Red
        $failedAttempts | Select-Object -First 10 | Format-Table TimeCreated, SourceIP, Username, FailureReason -AutoSize
    }
    
    # Export si demandé
    if ($ExportPath) {
        Export-SSHReport -ActiveConnections $activeConnections -EventLogs $eventLogs -FailedAttempts $failedAttempts -Configuration $configuration -ExportPath $ExportPath
    }
    
    # Alertes de sécurité
    if ($failedAttempts.Count -gt 20) {
        Write-Log "⚠️  ALERTE: Nombre élevé de tentatives de connexion échouées ($($failedAttempts.Count))" -Level "WARN"
    }
    
    if ($activeConnections.Count -gt 10) {
        Write-Log "⚠️  ALERTE: Nombre élevé de connexions SSH actives ($($activeConnections.Count))" -Level "WARN"
    }
    
    Write-Log "Analyse SSH terminée avec succès" -Level "SUCCESS"
}
catch {
    Write-Log "Erreur lors de l'analyse SSH: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}