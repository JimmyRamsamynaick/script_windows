<#
.SYNOPSIS
    Outils de test réseau complets pour Windows
    
.DESCRIPTION
    Ce script fournit une suite complète d'outils de diagnostic réseau pour Windows :
    - Tests de connectivité (ping, traceroute, telnet)
    - Analyse des ports (scan, vérification d'ouverture)
    - Tests de bande passante et latence
    - Diagnostic DNS (résolution, propagation)
    - Analyse des connexions actives
    - Tests de services réseau (HTTP, HTTPS, FTP, SMTP)
    - Monitoring continu avec alertes
    - Génération de rapports détaillés
    - Tests de sécurité réseau de base
    
.PARAMETER Target
    Adresse IP ou nom d'hôte à tester
    
.PARAMETER TestType
    Type de test : Ping, Traceroute, PortScan, DNS, Bandwidth, Full, Monitor
    
.PARAMETER Port
    Port spécifique à tester (pour PortScan)
    
.PARAMETER PortRange
    Plage de ports à scanner (format: "80-443")
    
.PARAMETER Count
    Nombre de tests à effectuer (pour ping, monitoring)
    
.PARAMETER Timeout
    Timeout en millisecondes pour les tests
    
.PARAMETER Continuous
    Mode monitoring continu
    
.PARAMETER AlertThreshold
    Seuil d'alerte pour la latence (ms)
    
.PARAMETER OutputFormat
    Format de sortie : Console, CSV, JSON, HTML, XML
    
.PARAMETER ReportPath
    Chemin du fichier de rapport
    
.PARAMETER LogPath
    Chemin du fichier de log
    
.PARAMETER Interactive
    Mode interactif avec menu
    
.EXAMPLE
    .\test_reseaux.ps1 -Target "google.com" -TestType Ping -Count 10
    
.EXAMPLE
    .\test_reseaux.ps1 -Target "192.168.1.1" -TestType PortScan -PortRange "1-1000"
    
.EXAMPLE
    .\test_reseaux.ps1 -Target "example.com" -TestType Full -OutputFormat HTML
    
.EXAMPLE
    .\test_reseaux.ps1 -Interactive
    
.NOTES
    Auteur: Jimmy Ramsamynaick
    Version: 2.0
    Dernière modification: 2025
    
    Prérequis:
    - PowerShell 5.1 ou supérieur
    - Droits d'administrateur pour certains tests
    - Modules optionnels : Test-NetConnection, Resolve-DnsName
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Target,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Ping", "Traceroute", "PortScan", "DNS", "Bandwidth", "Full", "Monitor", "Security")]
    [string]$TestType = "Ping",
    
    [Parameter(Mandatory=$false)]
    [int]$Port,
    
    [Parameter(Mandatory=$false)]
    [string]$PortRange,
    
    [Parameter(Mandatory=$false)]
    [int]$Count = 4,
    
    [Parameter(Mandatory=$false)]
    [int]$Timeout = 5000,
    
    [Parameter(Mandatory=$false)]
    [switch]$Continuous,
    
    [Parameter(Mandatory=$false)]
    [int]$AlertThreshold = 1000,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Console", "CSV", "JSON", "HTML", "XML")]
    [string]$OutputFormat = "Console",
    
    [Parameter(Mandatory=$false)]
    [string]$ReportPath,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$Interactive
)

# Variables globales
$script:LogFile = ""
$script:TestResults = @()
$script:StartTime = Get-Date

# Configuration des chemins
if (-not $LogPath) {
    $LogDir = Join-Path $PSScriptRoot "logs"
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    $script:LogFile = Join-Path $LogDir "network_test_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
} else {
    $script:LogFile = $LogPath
}

if (-not $ReportPath) {
    $ReportDir = Join-Path $PSScriptRoot "reports"
    if (-not (Test-Path $ReportDir)) {
        New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
    }
    $ReportPath = Join-Path $ReportDir "network_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').$($OutputFormat.ToLower())"
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

# Fonction de test de ping avancé
function Test-PingAdvanced {
    param(
        [string]$TargetHost,
        [int]$PingCount = 4,
        [int]$TimeoutMs = 5000
    )
    
    Write-Log "Test de ping vers $TargetHost ($PingCount paquets)" -Level "INFO"
    
    $results = @()
    $successCount = 0
    $totalTime = 0
    $minTime = [int]::MaxValue
    $maxTime = 0
    
    for ($i = 1; $i -le $PingCount; $i++) {
        try {
            $ping = Test-Connection -ComputerName $TargetHost -Count 1 -TimeoutSeconds ($TimeoutMs / 1000) -ErrorAction Stop
            
            $responseTime = $ping.ResponseTime
            $successCount++
            $totalTime += $responseTime
            
            if ($responseTime -lt $minTime) { $minTime = $responseTime }
            if ($responseTime -gt $maxTime) { $maxTime = $responseTime }
            
            $result = @{
                Sequence = $i
                Status = "Success"
                ResponseTime = $responseTime
                TTL = $ping.TimeToLive
                Source = $ping.Source
                Destination = $ping.Destination
            }
            
            Write-Log "Ping $i : $($ping.Destination) - Temps=$($responseTime)ms TTL=$($ping.TimeToLive)" -Level "SUCCESS"
            
        } catch {
            $result = @{
                Sequence = $i
                Status = "Failed"
                ResponseTime = $null
                TTL = $null
                Source = $null
                Destination = $TargetHost
                Error = $_.Exception.Message
            }
            
            Write-Log "Ping $i : Échec - $($_.Exception.Message)" -Level "ERROR"
        }
        
        $results += $result
        Start-Sleep -Milliseconds 1000
    }
    
    # Calcul des statistiques
    $packetLoss = (($PingCount - $successCount) / $PingCount) * 100
    $avgTime = if ($successCount -gt 0) { $totalTime / $successCount } else { 0 }
    
    $statistics = @{
        Target = $TargetHost
        PacketsSent = $PingCount
        PacketsReceived = $successCount
        PacketLoss = $packetLoss
        MinTime = if ($minTime -eq [int]::MaxValue) { 0 } else { $minTime }
        MaxTime = $maxTime
        AvgTime = $avgTime
        Results = $results
    }
    
    Write-Log "Statistiques: $successCount/$PingCount reçus ($packetLoss% perte), Min/Moy/Max = $($statistics.MinTime)/$([math]::Round($avgTime, 2))/$maxTime ms" -Level "INFO"
    
    return $statistics
}

# Fonction de traceroute
function Test-Traceroute {
    param(
        [string]$TargetHost,
        [int]$MaxHops = 30
    )
    
    Write-Log "Traceroute vers $TargetHost (max $MaxHops sauts)" -Level "INFO"
    
    $results = @()
    
    try {
        # Utilisation de Test-NetConnection pour tracer la route
        for ($hop = 1; $hop -le $MaxHops; $hop++) {
            try {
                $trace = Test-NetConnection -ComputerName $TargetHost -TraceRoute -Hops $hop -WarningAction SilentlyContinue
                
                if ($trace.TraceRoute) {
                    foreach ($hopResult in $trace.TraceRoute) {
                        $hopInfo = @{
                            Hop = $hop
                            Address = $hopResult
                            Hostname = try { [System.Net.Dns]::GetHostEntry($hopResult).HostName } catch { $hopResult }
                            ResponseTime = "N/A"
                        }
                        
                        $results += $hopInfo
                        Write-Log "Saut $hop : $($hopResult) ($($hopInfo.Hostname))" -Level "INFO"
                    }
                }
                
                if ($trace.RemoteAddress -eq $TargetHost) {
                    break
                }
                
            } catch {
                Write-Log "Erreur au saut $hop : $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
    } catch {
        Write-Log "Erreur lors du traceroute: $($_.Exception.Message)" -Level "ERROR"
        
        # Fallback avec tracert Windows
        try {
            $tracertOutput = & tracert -h $MaxHops $TargetHost 2>&1
            
            foreach ($line in $tracertOutput) {
                if ($line -match '^\s*(\d+)\s+(.+)') {
                    $hopNumber = $matches[1]
                    $hopData = $matches[2]
                    
                    $hopInfo = @{
                        Hop = [int]$hopNumber
                        Address = "N/A"
                        Hostname = $hopData.Trim()
                        ResponseTime = "N/A"
                    }
                    
                    $results += $hopInfo
                    Write-Log "Saut $hopNumber : $($hopData.Trim())" -Level "INFO"
                }
            }
            
        } catch {
            Write-Log "Échec du traceroute de fallback: $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    return @{
        Target = $TargetHost
        MaxHops = $MaxHops
        Results = $results
    }
}

# Fonction de scan de ports
function Test-PortScan {
    param(
        [string]$TargetHost,
        [string]$PortRangeStr,
        [int]$SinglePort,
        [int]$TimeoutMs = 5000
    )
    
    $ports = @()
    
    if ($SinglePort) {
        $ports = @($SinglePort)
        Write-Log "Scan du port $SinglePort sur $TargetHost" -Level "INFO"
    } elseif ($PortRangeStr) {
        if ($PortRangeStr -match '^(\d+)-(\d+)$') {
            $startPort = [int]$matches[1]
            $endPort = [int]$matches[2]
            $ports = $startPort..$endPort
            Write-Log "Scan des ports $startPort-$endPort sur $TargetHost" -Level "INFO"
        } else {
            Write-Log "Format de plage de ports invalide. Utilisez le format '80-443'" -Level "ERROR"
            return $null
        }
    } else {
        # Ports communs par défaut
        $ports = @(21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3389, 5432, 8080)
        Write-Log "Scan des ports communs sur $TargetHost" -Level "INFO"
    }
    
    $results = @()
    $openPorts = @()
    
    foreach ($port in $ports) {
        try {
            $connection = Test-NetConnection -ComputerName $TargetHost -Port $port -WarningAction SilentlyContinue
            
            $portResult = @{
                Port = $port
                Status = if ($connection.TcpTestSucceeded) { "Open" } else { "Closed" }
                Service = Get-ServiceByPort -Port $port
                ResponseTime = "N/A"
            }
            
            if ($connection.TcpTestSucceeded) {
                $openPorts += $port
                Write-Log "Port $port : OUVERT ($($portResult.Service))" -Level "SUCCESS"
            } else {
                Write-Log "Port $port : FERMÉ" -Level "DEBUG"
            }
            
            $results += $portResult
            
        } catch {
            $portResult = @{
                Port = $port
                Status = "Error"
                Service = Get-ServiceByPort -Port $port
                ResponseTime = "N/A"
                Error = $_.Exception.Message
            }
            
            $results += $portResult
            Write-Log "Port $port : ERREUR - $($_.Exception.Message)" -Level "ERROR"
        }
        
        # Petite pause pour éviter de surcharger le réseau
        Start-Sleep -Milliseconds 50
    }
    
    Write-Log "Scan terminé: $($openPorts.Count) ports ouverts sur $($ports.Count) testés" -Level "INFO"
    
    return @{
        Target = $TargetHost
        PortsScanned = $ports.Count
        OpenPorts = $openPorts
        Results = $results
    }
}

# Fonction pour obtenir le service associé à un port
function Get-ServiceByPort {
    param([int]$Port)
    
    $services = @{
        21 = "FTP"
        22 = "SSH"
        23 = "Telnet"
        25 = "SMTP"
        53 = "DNS"
        80 = "HTTP"
        110 = "POP3"
        143 = "IMAP"
        443 = "HTTPS"
        993 = "IMAPS"
        995 = "POP3S"
        1433 = "SQL Server"
        3389 = "RDP"
        5432 = "PostgreSQL"
        8080 = "HTTP Alt"
    }
    
    return if ($services.ContainsKey($Port)) { $services[$Port] } else { "Unknown" }
}

# Fonction de test DNS
function Test-DNSResolution {
    param(
        [string]$TargetHost
    )
    
    Write-Log "Test de résolution DNS pour $TargetHost" -Level "INFO"
    
    $results = @{
        Target = $TargetHost
        ARecords = @()
        AAAARecords = @()
        MXRecords = @()
        NSRecords = @()
        CNAMERecords = @()
        TXTRecords = @()
        ReverseDNS = @()
    }
    
    try {
        # Enregistrements A (IPv4)
        try {
            $aRecords = Resolve-DnsName -Name $TargetHost -Type A -ErrorAction Stop
            foreach ($record in $aRecords) {
                if ($record.Type -eq "A") {
                    $results.ARecords += $record.IPAddress
                    Write-Log "A Record: $($record.IPAddress)" -Level "SUCCESS"
                }
            }
        } catch {
            Write-Log "Aucun enregistrement A trouvé" -Level "WARNING"
        }
        
        # Enregistrements AAAA (IPv6)
        try {
            $aaaaRecords = Resolve-DnsName -Name $TargetHost -Type AAAA -ErrorAction Stop
            foreach ($record in $aaaaRecords) {
                if ($record.Type -eq "AAAA") {
                    $results.AAAARecords += $record.IPAddress
                    Write-Log "AAAA Record: $($record.IPAddress)" -Level "SUCCESS"
                }
            }
        } catch {
            Write-Log "Aucun enregistrement AAAA trouvé" -Level "DEBUG"
        }
        
        # Enregistrements MX
        try {
            $mxRecords = Resolve-DnsName -Name $TargetHost -Type MX -ErrorAction Stop
            foreach ($record in $mxRecords) {
                if ($record.Type -eq "MX") {
                    $mxInfo = @{
                        Exchange = $record.NameExchange
                        Priority = $record.Preference
                    }
                    $results.MXRecords += $mxInfo
                    Write-Log "MX Record: $($record.NameExchange) (Priority: $($record.Preference))" -Level "SUCCESS"
                }
            }
        } catch {
            Write-Log "Aucun enregistrement MX trouvé" -Level "DEBUG"
        }
        
        # Enregistrements NS
        try {
            $nsRecords = Resolve-DnsName -Name $TargetHost -Type NS -ErrorAction Stop
            foreach ($record in $nsRecords) {
                if ($record.Type -eq "NS") {
                    $results.NSRecords += $record.NameHost
                    Write-Log "NS Record: $($record.NameHost)" -Level "SUCCESS"
                }
            }
        } catch {
            Write-Log "Aucun enregistrement NS trouvé" -Level "DEBUG"
        }
        
        # DNS inverse pour les adresses IP trouvées
        foreach ($ip in $results.ARecords) {
            try {
                $reverseRecord = Resolve-DnsName -Name $ip -Type PTR -ErrorAction Stop
                if ($reverseRecord.Type -eq "PTR") {
                    $results.ReverseDNS += @{
                        IP = $ip
                        Hostname = $reverseRecord.NameHost
                    }
                    Write-Log "Reverse DNS: $ip -> $($reverseRecord.NameHost)" -Level "SUCCESS"
                }
            } catch {
                Write-Log "Pas de DNS inverse pour $ip" -Level "DEBUG"
            }
        }
        
    } catch {
        Write-Log "Erreur lors de la résolution DNS: $($_.Exception.Message)" -Level "ERROR"
    }
    
    return $results
}

# Fonction de test de bande passante
function Test-Bandwidth {
    param(
        [string]$TargetHost,
        [int]$Port = 80
    )
    
    Write-Log "Test de bande passante vers $TargetHost:$Port" -Level "INFO"
    
    $results = @{
        Target = $TargetHost
        Port = $Port
        DownloadSpeed = 0
        UploadSpeed = 0
        Latency = 0
        Jitter = 0
    }
    
    try {
        # Test de latence
        $pingResult = Test-PingAdvanced -TargetHost $TargetHost -PingCount 10
        $results.Latency = $pingResult.AvgTime
        
        # Calcul du jitter (variation de latence)
        if ($pingResult.Results.Count -gt 1) {
            $latencies = $pingResult.Results | Where-Object { $_.Status -eq "Success" } | ForEach-Object { $_.ResponseTime }
            if ($latencies.Count -gt 1) {
                $jitterSum = 0
                for ($i = 1; $i -lt $latencies.Count; $i++) {
                    $jitterSum += [math]::Abs($latencies[$i] - $latencies[$i-1])
                }
                $results.Jitter = $jitterSum / ($latencies.Count - 1)
            }
        }
        
        Write-Log "Latence moyenne: $([math]::Round($results.Latency, 2)) ms" -Level "INFO"
        Write-Log "Jitter: $([math]::Round($results.Jitter, 2)) ms" -Level "INFO"
        
        # Test de débit (simulation avec téléchargement HTTP si possible)
        if ($Port -eq 80 -or $Port -eq 443) {
            try {
                $protocol = if ($Port -eq 443) { "https" } else { "http" }
                $url = "$protocol://$TargetHost/"
                
                $startTime = Get-Date
                $response = Invoke-WebRequest -Uri $url -TimeoutSec 10 -ErrorAction Stop
                $endTime = Get-Date
                
                $duration = ($endTime - $startTime).TotalSeconds
                $dataSize = $response.RawContentLength
                
                if ($duration -gt 0 -and $dataSize -gt 0) {
                    $results.DownloadSpeed = ($dataSize * 8) / ($duration * 1000000) # Mbps
                    Write-Log "Vitesse de téléchargement estimée: $([math]::Round($results.DownloadSpeed, 2)) Mbps" -Level "SUCCESS"
                }
                
            } catch {
                Write-Log "Impossible de tester la bande passante HTTP: $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
    } catch {
        Write-Log "Erreur lors du test de bande passante: $($_.Exception.Message)" -Level "ERROR"
    }
    
    return $results
}

# Fonction de monitoring continu
function Start-NetworkMonitoring {
    param(
        [string]$TargetHost,
        [int]$IntervalSeconds = 60,
        [int]$AlertThresholdMs = 1000
    )
    
    Write-Log "Début du monitoring réseau de $TargetHost (intervalle: ${IntervalSeconds}s, seuil d'alerte: ${AlertThresholdMs}ms)" -Level "INFO"
    
    $monitoringResults = @()
    $alertCount = 0
    
    try {
        while ($Continuous -or $monitoringResults.Count -lt $Count) {
            $timestamp = Get-Date
            
            # Test de ping
            $pingResult = Test-PingAdvanced -TargetHost $TargetHost -PingCount 1
            
            $monitorResult = @{
                Timestamp = $timestamp
                Target = $TargetHost
                Status = if ($pingResult.PacketsReceived -gt 0) { "Online" } else { "Offline" }
                ResponseTime = $pingResult.AvgTime
                PacketLoss = $pingResult.PacketLoss
            }
            
            $monitoringResults += $monitorResult
            
            # Vérification des seuils d'alerte
            if ($pingResult.PacketsReceived -eq 0) {
                $alertCount++
                Write-Log "ALERTE: $TargetHost est HORS LIGNE!" -Level "ERROR"
            } elseif ($pingResult.AvgTime -gt $AlertThresholdMs) {
                $alertCount++
                Write-Log "ALERTE: Latence élevée pour $TargetHost : $([math]::Round($pingResult.AvgTime, 2))ms (seuil: ${AlertThresholdMs}ms)" -Level "WARNING"
            } else {
                Write-Log "Monitoring: $TargetHost - $([math]::Round($pingResult.AvgTime, 2))ms - OK" -Level "SUCCESS"
            }
            
            if (-not $Continuous) {
                break
            }
            
            Start-Sleep -Seconds $IntervalSeconds
        }
        
    } catch {
        Write-Log "Erreur lors du monitoring: $($_.Exception.Message)" -Level "ERROR"
    }
    
    Write-Log "Monitoring terminé. $alertCount alertes générées sur $($monitoringResults.Count) tests" -Level "INFO"
    
    return @{
        Target = $TargetHost
        Duration = (Get-Date) - $script:StartTime
        TotalTests = $monitoringResults.Count
        AlertCount = $alertCount
        Results = $monitoringResults
    }
}

# Fonction de test de sécurité réseau
function Test-NetworkSecurity {
    param(
        [string]$TargetHost
    )
    
    Write-Log "Test de sécurité réseau pour $TargetHost" -Level "INFO"
    
    $securityResults = @{
        Target = $TargetHost
        OpenPorts = @()
        VulnerablePorts = @()
        SSLInfo = @()
        SecurityHeaders = @()
        Recommendations = @()
    }
    
    try {
        # Scan des ports sensibles
        $sensitivePorts = @(21, 22, 23, 25, 53, 135, 139, 445, 1433, 3389, 5432)
        $portScanResult = Test-PortScan -TargetHost $TargetHost -PortRangeStr "1-1000"
        
        foreach ($result in $portScanResult.Results) {
            if ($result.Status -eq "Open") {
                $securityResults.OpenPorts += $result.Port
                
                if ($sensitivePorts -contains $result.Port) {
                    $securityResults.VulnerablePorts += @{
                        Port = $result.Port
                        Service = $result.Service
                        Risk = "High"
                        Description = Get-PortSecurityInfo -Port $result.Port
                    }
                    Write-Log "Port sensible ouvert: $($result.Port) ($($result.Service))" -Level "WARNING"
                }
            }
        }
        
        # Test SSL/TLS si HTTPS est disponible
        if ($securityResults.OpenPorts -contains 443) {
            try {
                $sslInfo = Test-SSLCertificate -TargetHost $TargetHost
                $securityResults.SSLInfo = $sslInfo
            } catch {
                Write-Log "Erreur lors du test SSL: $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
        # Test des en-têtes de sécurité HTTP
        if ($securityResults.OpenPorts -contains 80 -or $securityResults.OpenPorts -contains 443) {
            try {
                $headersInfo = Test-SecurityHeaders -TargetHost $TargetHost
                $securityResults.SecurityHeaders = $headersInfo
            } catch {
                Write-Log "Erreur lors du test des en-têtes de sécurité: $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
        # Génération de recommandations
        $securityResults.Recommendations = Generate-SecurityRecommendations -SecurityResults $securityResults
        
    } catch {
        Write-Log "Erreur lors du test de sécurité: $($_.Exception.Message)" -Level "ERROR"
    }
    
    return $securityResults
}

# Fonction d'information de sécurité des ports
function Get-PortSecurityInfo {
    param([int]$Port)
    
    $portInfo = @{
        21 = "FTP - Protocole non chiffré, vulnérable aux attaques man-in-the-middle"
        22 = "SSH - Sécurisé si configuré correctement, vérifier les clés et mots de passe"
        23 = "Telnet - Protocole non chiffré, très vulnérable"
        25 = "SMTP - Peut être utilisé pour le spam, vérifier la configuration"
        135 = "RPC - Service Windows, peut être exploité pour des attaques"
        139 = "NetBIOS - Partage Windows, risque d'exposition de données"
        445 = "SMB - Partage Windows, vulnérable si non sécurisé"
        1433 = "SQL Server - Base de données, risque d'injection SQL"
        3389 = "RDP - Bureau à distance, cible fréquente d'attaques"
        5432 = "PostgreSQL - Base de données, vérifier l'authentification"
    }
    
    return if ($portInfo.ContainsKey($Port)) { $portInfo[$Port] } else { "Port non standard ouvert" }
}

# Fonction de test SSL
function Test-SSLCertificate {
    param([string]$TargetHost)
    
    Write-Log "Test du certificat SSL pour $TargetHost" -Level "INFO"
    
    try {
        $uri = "https://$TargetHost"
        $request = [System.Net.WebRequest]::Create($uri)
        $request.Timeout = 10000
        
        $response = $request.GetResponse()
        $cert = $request.ServicePoint.Certificate
        
        if ($cert) {
            $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
            
            $sslInfo = @{
                Subject = $cert2.Subject
                Issuer = $cert2.Issuer
                ValidFrom = $cert2.NotBefore
                ValidTo = $cert2.NotAfter
                IsExpired = $cert2.NotAfter -lt (Get-Date)
                DaysUntilExpiry = ($cert2.NotAfter - (Get-Date)).Days
                SignatureAlgorithm = $cert2.SignatureAlgorithm.FriendlyName
                KeySize = $cert2.PublicKey.Key.KeySize
            }
            
            if ($sslInfo.IsExpired) {
                Write-Log "ALERTE: Certificat SSL expiré!" -Level "ERROR"
            } elseif ($sslInfo.DaysUntilExpiry -lt 30) {
                Write-Log "ATTENTION: Certificat SSL expire dans $($sslInfo.DaysUntilExpiry) jours" -Level "WARNING"
            } else {
                Write-Log "Certificat SSL valide (expire le $($sslInfo.ValidTo))" -Level "SUCCESS"
            }
            
            return $sslInfo
        }
        
    } catch {
        Write-Log "Erreur lors du test SSL: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# Fonction de test des en-têtes de sécurité
function Test-SecurityHeaders {
    param([string]$TargetHost)
    
    Write-Log "Test des en-têtes de sécurité HTTP pour $TargetHost" -Level "INFO"
    
    $securityHeaders = @(
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Referrer-Policy"
    )
    
    $headerResults = @{}
    
    try {
        $protocols = @("http", "https")
        
        foreach ($protocol in $protocols) {
            if (($protocol -eq "http" -and $securityResults.OpenPorts -contains 80) -or 
                ($protocol -eq "https" -and $securityResults.OpenPorts -contains 443)) {
                
                try {
                    $uri = "$protocol://$TargetHost"
                    $response = Invoke-WebRequest -Uri $uri -TimeoutSec 10 -ErrorAction Stop
                    
                    foreach ($header in $securityHeaders) {
                        $headerValue = $response.Headers[$header]
                        $headerResults[$header] = @{
                            Present = $headerValue -ne $null
                            Value = $headerValue
                            Protocol = $protocol
                        }
                        
                        if ($headerValue) {
                            Write-Log "En-tête de sécurité trouvé: $header" -Level "SUCCESS"
                        } else {
                            Write-Log "En-tête de sécurité manquant: $header" -Level "WARNING"
                        }
                    }
                    
                    break # Sortir de la boucle si une connexion réussit
                    
                } catch {
                    Write-Log "Erreur lors du test $protocol : $($_.Exception.Message)" -Level "DEBUG"
                }
            }
        }
        
    } catch {
        Write-Log "Erreur lors du test des en-têtes: $($_.Exception.Message)" -Level "ERROR"
    }
    
    return $headerResults
}

# Fonction de génération de recommandations de sécurité
function Generate-SecurityRecommendations {
    param($SecurityResults)
    
    $recommendations = @()
    
    # Recommandations basées sur les ports ouverts
    foreach ($vulnPort in $SecurityResults.VulnerablePorts) {
        $recommendations += "Sécuriser ou fermer le port $($vulnPort.Port) ($($vulnPort.Service)) - $($vulnPort.Description)"
    }
    
    # Recommandations SSL
    if ($SecurityResults.SSLInfo) {
        $ssl = $SecurityResults.SSLInfo
        if ($ssl.IsExpired) {
            $recommendations += "Renouveler immédiatement le certificat SSL expiré"
        } elseif ($ssl.DaysUntilExpiry -lt 30) {
            $recommendations += "Planifier le renouvellement du certificat SSL (expire dans $($ssl.DaysUntilExpiry) jours)"
        }
        
        if ($ssl.KeySize -lt 2048) {
            $recommendations += "Utiliser une clé SSL d'au moins 2048 bits (actuellement: $($ssl.KeySize) bits)"
        }
    }
    
    # Recommandations en-têtes de sécurité
    $missingHeaders = $SecurityResults.SecurityHeaders.Keys | Where-Object { -not $SecurityResults.SecurityHeaders[$_].Present }
    foreach ($header in $missingHeaders) {
        $recommendations += "Ajouter l'en-tête de sécurité: $header"
    }
    
    return $recommendations
}

# Fonction de génération de rapport
function Generate-NetworkReport {
    param(
        [array]$TestResults,
        [string]$Format = "HTML",
        [string]$OutputPath
    )
    
    Write-Log "Génération du rapport réseau ($Format)" -Level "INFO"
    
    try {
        switch ($Format.ToUpper()) {
            "HTML" {
                Generate-HTMLReport -TestResults $TestResults -OutputPath $OutputPath
            }
            "CSV" {
                Generate-CSVReport -TestResults $TestResults -OutputPath $OutputPath
            }
            "JSON" {
                Generate-JSONReport -TestResults $TestResults -OutputPath $OutputPath
            }
            "XML" {
                Generate-XMLReport -TestResults $TestResults -OutputPath $OutputPath
            }
            default {
                Write-Log "Format de rapport non supporté: $Format" -Level "ERROR"
            }
        }
    } catch {
        Write-Log "Erreur lors de la génération du rapport: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Fonction de génération de rapport HTML
function Generate-HTMLReport {
    param(
        [array]$TestResults,
        [string]$OutputPath
    )
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Rapport de Test Réseau</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .test-section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { color: #28a745; }
        .warning { color: #ffc107; }
        .error { color: #dc3545; }
        .info { color: #17a2b8; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .port-open { background-color: #d4edda; }
        .port-closed { background-color: #f8d7da; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Rapport de Test Réseau</h1>
        <p><strong>Date:</strong> $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')</p>
        <p><strong>Cible:</strong> $Target</p>
        <p><strong>Type de test:</strong> $TestType</p>
    </div>
"@
    
    foreach ($result in $TestResults) {
        $html += "<div class='test-section'>"
        $html += "<h2>$($result.TestType)</h2>"
        
        switch ($result.TestType) {
            "Ping" {
                $html += "<p><strong>Statistiques:</strong></p>"
                $html += "<ul>"
                $html += "<li>Paquets envoyés: $($result.Data.PacketsSent)</li>"
                $html += "<li>Paquets reçus: $($result.Data.PacketsReceived)</li>"
                $html += "<li>Perte de paquets: $($result.Data.PacketLoss)%</li>"
                $html += "<li>Temps de réponse moyen: $([math]::Round($result.Data.AvgTime, 2)) ms</li>"
                $html += "</ul>"
            }
            
            "PortScan" {
                $html += "<p><strong>Ports scannés:</strong> $($result.Data.PortsScanned)</p>"
                $html += "<p><strong>Ports ouverts:</strong> $($result.Data.OpenPorts.Count)</p>"
                $html += "<table>"
                $html += "<tr><th>Port</th><th>Status</th><th>Service</th></tr>"
                
                foreach ($portResult in $result.Data.Results) {
                    $cssClass = if ($portResult.Status -eq "Open") { "port-open" } else { "port-closed" }
                    $html += "<tr class='$cssClass'>"
                    $html += "<td>$($portResult.Port)</td>"
                    $html += "<td>$($portResult.Status)</td>"
                    $html += "<td>$($portResult.Service)</td>"
                    $html += "</tr>"
                }
                
                $html += "</table>"
            }
            
            "DNS" {
                $html += "<h3>Enregistrements DNS</h3>"
                if ($result.Data.ARecords.Count -gt 0) {
                    $html += "<p><strong>Enregistrements A:</strong> $($result.Data.ARecords -join ', ')</p>"
                }
                if ($result.Data.MXRecords.Count -gt 0) {
                    $html += "<p><strong>Enregistrements MX:</strong></p><ul>"
                    foreach ($mx in $result.Data.MXRecords) {
                        $html += "<li>$($mx.Exchange) (Priorité: $($mx.Priority))</li>"
                    }
                    $html += "</ul>"
                }
            }
        }
        
        $html += "</div>"
    }
    
    $html += @"
    <div class="test-section">
        <h2>Informations Système</h2>
        <p><strong>Fichier de log:</strong> $script:LogFile</p>
        <p><strong>Durée totale:</strong> $((Get-Date) - $script:StartTime)</p>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Log "Rapport HTML généré: $OutputPath" -Level "SUCCESS"
}

# Fonction de menu interactif
function Show-InteractiveMenu {
    do {
        Clear-Host
        Write-Host "=== OUTILS DE TEST RÉSEAU ===" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1. Test de ping" -ForegroundColor White
        Write-Host "2. Traceroute" -ForegroundColor White
        Write-Host "3. Scan de ports" -ForegroundColor White
        Write-Host "4. Test DNS" -ForegroundColor White
        Write-Host "5. Test de bande passante" -ForegroundColor White
        Write-Host "6. Test complet" -ForegroundColor White
        Write-Host "7. Monitoring continu" -ForegroundColor White
        Write-Host "8. Test de sécurité" -ForegroundColor White
        Write-Host "9. Générer un rapport" -ForegroundColor White
        Write-Host "0. Quitter" -ForegroundColor Red
        Write-Host ""
        
        $choice = Read-Host "Choisissez une option"
        
        switch ($choice) {
            "1" {
                $target = Read-Host "Adresse IP ou nom d'hôte"
                $count = Read-Host "Nombre de pings (défaut: 4)"
                if (-not $count) { $count = 4 }
                
                $result = Test-PingAdvanced -TargetHost $target -PingCount $count
                $script:TestResults += @{ TestType = "Ping"; Target = $target; Data = $result }
                
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            
            "2" {
                $target = Read-Host "Adresse IP ou nom d'hôte"
                $maxHops = Read-Host "Nombre maximum de sauts (défaut: 30)"
                if (-not $maxHops) { $maxHops = 30 }
                
                $result = Test-Traceroute -TargetHost $target -MaxHops $maxHops
                $script:TestResults += @{ TestType = "Traceroute"; Target = $target; Data = $result }
                
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            
            "3" {
                $target = Read-Host "Adresse IP ou nom d'hôte"
                Write-Host "Options de scan:"
                Write-Host "1. Port unique"
                Write-Host "2. Plage de ports (ex: 80-443)"
                Write-Host "3. Ports communs"
                
                $scanChoice = Read-Host "Choisissez une option"
                
                switch ($scanChoice) {
                    "1" {
                        $port = Read-Host "Numéro de port"
                        $result = Test-PortScan -TargetHost $target -SinglePort $port
                    }
                    "2" {
                        $portRange = Read-Host "Plage de ports (ex: 80-443)"
                        $result = Test-PortScan -TargetHost $target -PortRangeStr $portRange
                    }
                    default {
                        $result = Test-PortScan -TargetHost $target
                    }
                }
                
                $script:TestResults += @{ TestType = "PortScan"; Target = $target; Data = $result }
                
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            
            "4" {
                $target = Read-Host "Nom de domaine"
                
                $result = Test-DNSResolution -TargetHost $target
                $script:TestResults += @{ TestType = "DNS"; Target = $target; Data = $result }
                
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            
            "5" {
                $target = Read-Host "Adresse IP ou nom d'hôte"
                $port = Read-Host "Port (défaut: 80)"
                if (-not $port) { $port = 80 }
                
                $result = Test-Bandwidth -TargetHost $target -Port $port
                $script:TestResults += @{ TestType = "Bandwidth"; Target = $target; Data = $result }
                
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            
            "6" {
                $target = Read-Host "Adresse IP ou nom d'hôte"
                
                Write-Host "Exécution du test complet..." -ForegroundColor Yellow
                
                # Ping
                $pingResult = Test-PingAdvanced -TargetHost $target
                $script:TestResults += @{ TestType = "Ping"; Target = $target; Data = $pingResult }
                
                # DNS
                $dnsResult = Test-DNSResolution -TargetHost $target
                $script:TestResults += @{ TestType = "DNS"; Target = $target; Data = $dnsResult }
                
                # Port scan
                $portResult = Test-PortScan -TargetHost $target
                $script:TestResults += @{ TestType = "PortScan"; Target = $target; Data = $portResult }
                
                # Traceroute
                $traceResult = Test-Traceroute -TargetHost $target
                $script:TestResults += @{ TestType = "Traceroute"; Target = $target; Data = $traceResult }
                
                Write-Host "Test complet terminé!" -ForegroundColor Green
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            
            "7" {
                $target = Read-Host "Adresse IP ou nom d'hôte"
                $interval = Read-Host "Intervalle en secondes (défaut: 60)"
                if (-not $interval) { $interval = 60 }
                
                $threshold = Read-Host "Seuil d'alerte en ms (défaut: 1000)"
                if (-not $threshold) { $threshold = 1000 }
                
                Write-Host "Monitoring en cours... Appuyez sur Ctrl+C pour arrêter" -ForegroundColor Yellow
                
                $script:Continuous = $true
                $result = Start-NetworkMonitoring -TargetHost $target -IntervalSeconds $interval -AlertThresholdMs $threshold
                $script:TestResults += @{ TestType = "Monitoring"; Target = $target; Data = $result }
            }
            
            "8" {
                $target = Read-Host "Adresse IP ou nom d'hôte"
                
                Write-Host "Exécution du test de sécurité..." -ForegroundColor Yellow
                
                $result = Test-NetworkSecurity -TargetHost $target
                $script:TestResults += @{ TestType = "Security"; Target = $target; Data = $result }
                
                # Affichage des recommandations
                if ($result.Recommendations.Count -gt 0) {
                    Write-Host "`nRecommandations de sécurité:" -ForegroundColor Yellow
                    foreach ($recommendation in $result.Recommendations) {
                        Write-Host "- $recommendation" -ForegroundColor White
                    }
                }
                
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            
            "9" {
                if ($script:TestResults.Count -eq 0) {
                    Write-Host "Aucun test effectué. Effectuez d'abord des tests." -ForegroundColor Red
                } else {
                    Write-Host "Formats disponibles:"
                    Write-Host "1. HTML"
                    Write-Host "2. CSV"
                    Write-Host "3. JSON"
                    Write-Host "4. XML"
                    
                    $formatChoice = Read-Host "Choisissez un format"
                    $format = switch ($formatChoice) {
                        "1" { "HTML" }
                        "2" { "CSV" }
                        "3" { "JSON" }
                        "4" { "XML" }
                        default { "HTML" }
                    }
                    
                    $outputPath = Read-Host "Chemin de sortie (Entrée pour défaut)"
                    if (-not $outputPath) {
                        $outputPath = Join-Path $PSScriptRoot "reports\network_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').$($format.ToLower())"
                    }
                    
                    Generate-NetworkReport -TestResults $script:TestResults -Format $format -OutputPath $outputPath
                }
                
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
    Write-Log "=== DÉBUT DES TESTS RÉSEAU ===" -Level "INFO"
    Write-Log "Version: 2.0 | Auteur: Jimmy Ramsamynaick" -Level "INFO"
    
    if ($Interactive) {
        Show-InteractiveMenu
    } else {
        # Validation du paramètre Target
        if (-not $Target) {
            Write-Log "Le paramètre Target est obligatoire en mode non-interactif" -Level "ERROR"
            Write-Log "Utilisez -Interactive pour le mode interactif ou spécifiez -Target" -Level "INFO"
            exit 1
        }
        
        # Exécution du test selon le type
        switch ($TestType) {
            "Ping" {
                $result = Test-PingAdvanced -TargetHost $Target -PingCount $Count -TimeoutMs $Timeout
                $script:TestResults += @{ TestType = "Ping"; Target = $Target; Data = $result }
            }
            
            "Traceroute" {
                $result = Test-Traceroute -TargetHost $Target
                $script:TestResults += @{ TestType = "Traceroute"; Target = $Target; Data = $result }
            }
            
            "PortScan" {
                if ($Port) {
                    $result = Test-PortScan -TargetHost $Target -SinglePort $Port -TimeoutMs $Timeout
                } elseif ($PortRange) {
                    $result = Test-PortScan -TargetHost $Target -PortRangeStr $PortRange -TimeoutMs $Timeout
                } else {
                    $result = Test-PortScan -TargetHost $Target -TimeoutMs $Timeout
                }
                $script:TestResults += @{ TestType = "PortScan"; Target = $Target; Data = $result }
            }
            
            "DNS" {
                $result = Test-DNSResolution -TargetHost $Target
                $script:TestResults += @{ TestType = "DNS"; Target = $Target; Data = $result }
            }
            
            "Bandwidth" {
                $portToTest = if ($Port) { $Port } else { 80 }
                $result = Test-Bandwidth -TargetHost $Target -Port $portToTest
                $script:TestResults += @{ TestType = "Bandwidth"; Target = $Target; Data = $result }
            }
            
            "Monitor" {
                $result = Start-NetworkMonitoring -TargetHost $Target -IntervalSeconds 60 -AlertThresholdMs $AlertThreshold
                $script:TestResults += @{ TestType = "Monitoring"; Target = $Target; Data = $result }
            }
            
            "Security" {
                $result = Test-NetworkSecurity -TargetHost $Target
                $script:TestResults += @{ TestType = "Security"; Target = $Target; Data = $result }
                
                # Affichage des recommandations
                if ($result.Recommendations.Count -gt 0) {
                    Write-Log "Recommandations de sécurité:" -Level "WARNING"
                    foreach ($recommendation in $result.Recommendations) {
                        Write-Log "- $recommendation" -Level "INFO"
                    }
                }
            }
            
            "Full" {
                Write-Log "Exécution du test complet pour $Target" -Level "INFO"
                
                # Ping
                $pingResult = Test-PingAdvanced -TargetHost $Target -PingCount $Count
                $script:TestResults += @{ TestType = "Ping"; Target = $Target; Data = $pingResult }
                
                # DNS
                $dnsResult = Test-DNSResolution -TargetHost $Target
                $script:TestResults += @{ TestType = "DNS"; Target = $Target; Data = $dnsResult }
                
                # Port scan
                $portResult = Test-PortScan -TargetHost $Target
                $script:TestResults += @{ TestType = "PortScan"; Target = $Target; Data = $portResult }
                
                # Traceroute
                $traceResult = Test-Traceroute -TargetHost $Target
                $script:TestResults += @{ TestType = "Traceroute"; Target = $Target; Data = $traceResult }
                
                # Test de sécurité
                $securityResult = Test-NetworkSecurity -TargetHost $Target
                $script:TestResults += @{ TestType = "Security"; Target = $Target; Data = $securityResult }
            }
        }
        
        # Génération du rapport si demandé
        if ($OutputFormat -ne "Console") {
            Generate-NetworkReport -TestResults $script:TestResults -Format $OutputFormat -OutputPath $ReportPath
        }
        
        Write-Log "Tests terminés avec succès" -Level "SUCCESS"
    }
    
    Write-Log "=== FIN DES TESTS RÉSEAU ===" -Level "SUCCESS"
    
} catch {
    Write-Log "Erreur critique: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Utilisez Get-Help .\test_reseaux.ps1 -Full pour plus d'informations" -Level "INFO"
    exit 1
}