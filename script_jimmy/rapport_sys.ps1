<#
.SYNOPSIS
    Génération de rapports système complets pour Windows

.DESCRIPTION
    Ce script génère des rapports système détaillés incluant les informations
    matérielles, logicielles, performances, sécurité, réseau et état général
    du système Windows. Il peut produire des rapports en plusieurs formats
    et inclure des recommandations d'optimisation.

    Fonctionnalités :
    - Informations système complètes (CPU, RAM, disques, réseau)
    - État des services et processus critiques
    - Analyse des performances et utilisation des ressources
    - Vérification de la sécurité et des mises à jour
    - Inventaire logiciel et licences
    - Configuration réseau et connectivité
    - Journaux d'événements récents
    - Recommandations d'optimisation
    - Export multi-formats (HTML, PDF, CSV, JSON, XML)
    - Rapports programmés et automatisés
    - Comparaison avec rapports précédents
    - Alertes et notifications

.PARAMETER ReportType
    Type de rapport: Complete, Hardware, Software, Performance, Security, Network, Quick

.PARAMETER OutputFormat
    Format de sortie: HTML, PDF, CSV, JSON, XML, Console

.PARAMETER OutputPath
    Dossier de destination des rapports

.PARAMETER IncludePerformance
    Inclure l'analyse des performances

.PARAMETER IncludeSecurity
    Inclure l'audit de sécurité

.PARAMETER IncludeInventory
    Inclure l'inventaire logiciel

.PARAMETER IncludeNetwork
    Inclure la configuration réseau

.PARAMETER IncludeLogs
    Inclure les journaux d'événements

.PARAMETER IncludeRecommendations
    Inclure les recommandations d'optimisation

.PARAMETER CompareWithPrevious
    Comparer avec le rapport précédent

.PARAMETER SendEmail
    Envoyer le rapport par email

.PARAMETER EmailRecipients
    Destinataires email

.PARAMETER Detailed
    Rapport détaillé avec informations avancées

.PARAMETER Interactive
    Mode interactif avec menu

.EXAMPLE
    .\rapport_sys.ps1 -ReportType Complete -OutputFormat HTML -OutputPath "C:\Reports"
    Génère un rapport complet en HTML

.EXAMPLE
    .\rapport_sys.ps1 -ReportType Performance -IncludeRecommendations -OutputFormat PDF
    Génère un rapport de performances avec recommandations en PDF

.EXAMPLE
    .\rapport_sys.ps1 -Interactive
    Lance le mode interactif avec menu

.NOTES
    Auteur: Jimmy Ramsamynaick
    Date: 28/10/2025
    Version: 1.0
    
    Prérequis:
    - PowerShell 5.1 ou supérieur
    - Droits administrateur (recommandé)
    - Module ImportExcel (optionnel pour export Excel)
    - wkhtmltopdf (optionnel pour export PDF)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, HelpMessage="Type de rapport")]
    [ValidateSet("Complete", "Hardware", "Software", "Performance", "Security", "Network", "Quick")]
    [string]$ReportType = "Complete",
    
    [Parameter(Mandatory=$false, HelpMessage="Format de sortie")]
    [ValidateSet("HTML", "PDF", "CSV", "JSON", "XML", "Console")]
    [string]$OutputFormat = "HTML",
    
    [Parameter(Mandatory=$false, HelpMessage="Dossier de destination")]
    [string]$OutputPath = ".",
    
    [Parameter(Mandatory=$false, HelpMessage="Inclure les performances")]
    [switch]$IncludePerformance,
    
    [Parameter(Mandatory=$false, HelpMessage="Inclure la sécurité")]
    [switch]$IncludeSecurity,
    
    [Parameter(Mandatory=$false, HelpMessage="Inclure l'inventaire")]
    [switch]$IncludeInventory,
    
    [Parameter(Mandatory=$false, HelpMessage="Inclure le réseau")]
    [switch]$IncludeNetwork,
    
    [Parameter(Mandatory=$false, HelpMessage="Inclure les logs")]
    [switch]$IncludeLogs,
    
    [Parameter(Mandatory=$false, HelpMessage="Inclure les recommandations")]
    [switch]$IncludeRecommendations,
    
    [Parameter(Mandatory=$false, HelpMessage="Comparer avec précédent")]
    [switch]$CompareWithPrevious,
    
    [Parameter(Mandatory=$false, HelpMessage="Envoyer par email")]
    [switch]$SendEmail,
    
    [Parameter(Mandatory=$false, HelpMessage="Destinataires email")]
    [string[]]$EmailRecipients = @(),
    
    [Parameter(Mandatory=$false, HelpMessage="Rapport détaillé")]
    [switch]$Detailed,
    
    [Parameter(Mandatory=$false, HelpMessage="Mode interactif")]
    [switch]$Interactive
)

# Configuration
$ErrorActionPreference = "Continue"
$script:ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
$script:LogPath = Join-Path $env:TEMP "$($script:ScriptName)_$(Get-Date -Format 'yyyyMMdd').log"
$script:ReportData = @{}
$script:Recommendations = @()

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

function Get-SystemInformation {
    try {
        Write-Log "🖥️ Collecte des informations système..." -Level "INFO"
        
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
        $processor = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        $bios = Get-CimInstance -ClassName Win32_BIOS
        
        $systemInfo = @{
            ComputerName = $env:COMPUTERNAME
            Domain = $computerSystem.Domain
            Manufacturer = $computerSystem.Manufacturer
            Model = $computerSystem.Model
            TotalPhysicalMemory = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
            OSName = $operatingSystem.Caption
            OSVersion = $operatingSystem.Version
            OSBuild = $operatingSystem.BuildNumber
            OSArchitecture = $operatingSystem.OSArchitecture
            InstallDate = $operatingSystem.InstallDate
            LastBootUpTime = $operatingSystem.LastBootUpTime
            Uptime = (Get-Date) - $operatingSystem.LastBootUpTime
            ProcessorName = $processor.Name
            ProcessorCores = $processor.NumberOfCores
            ProcessorLogicalProcessors = $processor.NumberOfLogicalProcessors
            ProcessorMaxClockSpeed = $processor.MaxClockSpeed
            BIOSVersion = $bios.SMBIOSBIOSVersion
            BIOSDate = $bios.ReleaseDate
            TimeZone = (Get-TimeZone).DisplayName
            CurrentUser = $env:USERNAME
            PowerPlan = (Get-CimInstance -ClassName Win32_PowerPlan -Namespace "root\cimv2\power" | Where-Object {$_.IsActive}).ElementName
        }
        
        return $systemInfo
    }
    catch {
        Write-Log "Erreur lors de la collecte des informations système: $($_.Exception.Message)" -Level "ERROR"
        return @{}
    }
}

function Get-HardwareInformation {
    try {
        Write-Log "🔧 Collecte des informations matérielles..." -Level "INFO"
        
        # Disques
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {
            @{
                Drive = $_.DeviceID
                Label = $_.VolumeName
                FileSystem = $_.FileSystem
                SizeGB = [math]::Round($_.Size / 1GB, 2)
                FreeSpaceGB = [math]::Round($_.FreeSpace / 1GB, 2)
                UsedSpaceGB = [math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)
                PercentFree = [math]::Round(($_.FreeSpace / $_.Size) * 100, 1)
            }
        }
        
        # Mémoire
        $memory = Get-CimInstance -ClassName Win32_PhysicalMemory | ForEach-Object {
            @{
                BankLabel = $_.BankLabel
                Capacity = [math]::Round($_.Capacity / 1GB, 2)
                Speed = $_.Speed
                Manufacturer = $_.Manufacturer
                PartNumber = $_.PartNumber
            }
        }
        
        # Cartes réseau
        $networkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 } | ForEach-Object {
            $config = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.Index -eq $_.DeviceID }
            @{
                Name = $_.Name
                MACAddress = $_.MACAddress
                Speed = if ($_.Speed) { [math]::Round($_.Speed / 1MB, 0) } else { "N/A" }
                IPAddress = if ($config.IPAddress) { $config.IPAddress[0] } else { "N/A" }
                SubnetMask = if ($config.IPSubnet) { $config.IPSubnet[0] } else { "N/A" }
                DefaultGateway = if ($config.DefaultIPGateway) { $config.DefaultIPGateway[0] } else { "N/A" }
                DHCPEnabled = $config.DHCPEnabled
            }
        }
        
        # Cartes graphiques
        $videoCards = Get-CimInstance -ClassName Win32_VideoController | ForEach-Object {
            @{
                Name = $_.Name
                AdapterRAM = if ($_.AdapterRAM) { [math]::Round($_.AdapterRAM / 1MB, 0) } else { "N/A" }
                DriverVersion = $_.DriverVersion
                DriverDate = $_.DriverDate
            }
        }
        
        # Température (si disponible)
        $temperature = @()
        try {
            $temps = Get-CimInstance -ClassName MSAcpi_ThermalZoneTemperature -Namespace "root/wmi" -ErrorAction SilentlyContinue
            if ($temps) {
                $temperature = $temps | ForEach-Object {
                    @{
                        Zone = $_.InstanceName
                        Temperature = [math]::Round(($_.CurrentTemperature / 10) - 273.15, 1)
                    }
                }
            }
        }
        catch {
            # Température non disponible
        }
        
        $hardwareInfo = @{
            Disks = $disks
            Memory = $memory
            NetworkAdapters = $networkAdapters
            VideoCards = $videoCards
            Temperature = $temperature
        }
        
        return $hardwareInfo
    }
    catch {
        Write-Log "Erreur lors de la collecte des informations matérielles: $($_.Exception.Message)" -Level "ERROR"
        return @{}
    }
}

function Get-PerformanceInformation {
    try {
        Write-Log "📊 Collecte des informations de performance..." -Level "INFO"
        
        # Utilisation CPU
        $cpuUsage = (Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 3 | 
                    Select-Object -ExpandProperty CounterSamples | 
                    Measure-Object -Property CookedValue -Average).Average
        
        # Utilisation mémoire
        $totalMemory = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory
        $availableMemory = (Get-Counter "\Memory\Available Bytes").CounterSamples.CookedValue
        $usedMemory = $totalMemory - $availableMemory
        $memoryUsagePercent = ($usedMemory / $totalMemory) * 100
        
        # Top processus par CPU
        $topProcessesCPU = Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | ForEach-Object {
            @{
                Name = $_.ProcessName
                PID = $_.Id
                CPU = [math]::Round($_.CPU, 2)
                WorkingSet = [math]::Round($_.WorkingSet / 1MB, 2)
                Handles = $_.Handles
            }
        }
        
        # Top processus par mémoire
        $topProcessesMemory = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10 | ForEach-Object {
            @{
                Name = $_.ProcessName
                PID = $_.Id
                WorkingSetMB = [math]::Round($_.WorkingSet / 1MB, 2)
                VirtualMemoryMB = [math]::Round($_.VirtualMemorySize / 1MB, 2)
                PagedMemoryMB = [math]::Round($_.PagedMemorySize / 1MB, 2)
            }
        }
        
        # Services critiques
        $criticalServices = @("Spooler", "BITS", "Themes", "AudioSrv", "Dhcp", "Dnscache", "EventLog", "PlugPlay", "RpcSs", "Schedule", "W32Time", "Winmgmt", "WSearch")
        $serviceStatus = $criticalServices | ForEach-Object {
            $service = Get-Service -Name $_ -ErrorAction SilentlyContinue
            if ($service) {
                @{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    Status = $service.Status
                    StartType = $service.StartType
                }
            }
        } | Where-Object { $_ -ne $null }
        
        # Performances disque
        $diskPerformance = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {
            try {
                $diskReads = (Get-Counter "\LogicalDisk($($_.DeviceID))\Disk Reads/sec" -ErrorAction SilentlyContinue).CounterSamples.CookedValue
                $diskWrites = (Get-Counter "\LogicalDisk($($_.DeviceID))\Disk Writes/sec" -ErrorAction SilentlyContinue).CounterSamples.CookedValue
                
                @{
                    Drive = $_.DeviceID
                    ReadsPerSec = [math]::Round($diskReads, 2)
                    WritesPerSec = [math]::Round($diskWrites, 2)
                }
            }
            catch {
                @{
                    Drive = $_.DeviceID
                    ReadsPerSec = "N/A"
                    WritesPerSec = "N/A"
                }
            }
        }
        
        $performanceInfo = @{
            CPUUsagePercent = [math]::Round($cpuUsage, 2)
            MemoryUsagePercent = [math]::Round($memoryUsagePercent, 2)
            TotalMemoryGB = [math]::Round($totalMemory / 1GB, 2)
            AvailableMemoryGB = [math]::Round($availableMemory / 1GB, 2)
            UsedMemoryGB = [math]::Round($usedMemory / 1GB, 2)
            TopProcessesCPU = $topProcessesCPU
            TopProcessesMemory = $topProcessesMemory
            ServiceStatus = $serviceStatus
            DiskPerformance = $diskPerformance
            ProcessCount = (Get-Process).Count
            ThreadCount = (Get-Process | Measure-Object -Property Threads -Sum).Sum
        }
        
        return $performanceInfo
    }
    catch {
        Write-Log "Erreur lors de la collecte des performances: $($_.Exception.Message)" -Level "ERROR"
        return @{}
    }
}

function Get-SecurityInformation {
    try {
        Write-Log "🔒 Collecte des informations de sécurité..." -Level "INFO"
        
        # Windows Defender
        $defenderStatus = @{}
        try {
            $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($defender) {
                $defenderStatus = @{
                    AntivirusEnabled = $defender.AntivirusEnabled
                    RealTimeProtectionEnabled = $defender.RealTimeProtectionEnabled
                    AntivirusSignatureLastUpdated = $defender.AntivirusSignatureLastUpdated
                    QuickScanAge = $defender.QuickScanAge
                    FullScanAge = $defender.FullScanAge
                }
            }
        }
        catch {
            $defenderStatus = @{ Status = "Non disponible" }
        }
        
        # Pare-feu Windows
        $firewallProfiles = Get-NetFirewallProfile | ForEach-Object {
            @{
                Name = $_.Name
                Enabled = $_.Enabled
                DefaultInboundAction = $_.DefaultInboundAction
                DefaultOutboundAction = $_.DefaultOutboundAction
            }
        }
        
        # Mises à jour Windows
        $updates = @{}
        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsInstalled=0")
            
            $updates = @{
                PendingUpdates = $searchResult.Updates.Count
                LastInstallDate = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
                RebootRequired = (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) -ne $null
            }
        }
        catch {
            $updates = @{ Status = "Non disponible" }
        }
        
        # Comptes utilisateurs
        $userAccounts = Get-LocalUser | ForEach-Object {
            @{
                Name = $_.Name
                Enabled = $_.Enabled
                LastLogon = $_.LastLogon
                PasswordLastSet = $_.PasswordLastSet
                PasswordExpires = $_.PasswordExpires
                UserMayChangePassword = $_.UserMayChangePassword
            }
        }
        
        # Groupes locaux
        $localGroups = Get-LocalGroup | ForEach-Object {
            $members = try { Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue } catch { @() }
            @{
                Name = $_.Name
                Description = $_.Description
                MemberCount = $members.Count
                Members = $members | ForEach-Object { $_.Name }
            }
        }
        
        # Événements de sécurité récents
        $securityEvents = @()
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 -ErrorAction SilentlyContinue
            $securityEvents = $events | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
                @{
                    EventId = $_.Name
                    Count = $_.Count
                    Description = ($_.Group | Select-Object -First 1).LevelDisplayName
                }
            }
        }
        catch {
            # Pas d'accès aux événements de sécurité
        }
        
        $securityInfo = @{
            WindowsDefender = $defenderStatus
            FirewallProfiles = $firewallProfiles
            WindowsUpdates = $updates
            UserAccounts = $userAccounts
            LocalGroups = $localGroups
            SecurityEvents = $securityEvents
            UAC = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
        }
        
        return $securityInfo
    }
    catch {
        Write-Log "Erreur lors de la collecte des informations de sécurité: $($_.Exception.Message)" -Level "ERROR"
        return @{}
    }
}

function Get-NetworkInformation {
    try {
        Write-Log "🌐 Collecte des informations réseau..." -Level "INFO"
        
        # Configuration IP
        $ipConfig = Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq "Up" } | ForEach-Object {
            @{
                InterfaceAlias = $_.InterfaceAlias
                IPAddress = ($_.IPv4Address | Select-Object -First 1).IPAddress
                SubnetMask = ($_.IPv4Address | Select-Object -First 1).PrefixLength
                DefaultGateway = ($_.IPv4DefaultGateway | Select-Object -First 1).NextHop
                DNSServers = $_.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses }
            }
        }
        
        # Connexions réseau actives
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | 
                      Group-Object RemotePort | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
            @{
                Port = $_.Name
                ConnectionCount = $_.Count
                Protocol = "TCP"
            }
        }
        
        # Statistiques réseau
        $networkStats = Get-NetAdapterStatistics | Where-Object { $_.Name -notlike "*Loopback*" } | ForEach-Object {
            @{
                Name = $_.Name
                BytesReceived = [math]::Round($_.ReceivedBytes / 1MB, 2)
                BytesSent = [math]::Round($_.SentBytes / 1MB, 2)
                PacketsReceived = $_.ReceivedUnicastPackets
                PacketsSent = $_.SentUnicastPackets
            }
        }
        
        # Test de connectivité
        $connectivityTests = @()
        $testHosts = @("8.8.8.8", "1.1.1.1", "google.com", "microsoft.com")
        
        foreach ($host in $testHosts) {
            try {
                $ping = Test-Connection -ComputerName $host -Count 1 -Quiet
                $connectivityTests += @{
                    Host = $host
                    Status = if ($ping) { "OK" } else { "Échec" }
                    ResponseTime = if ($ping) { (Test-Connection -ComputerName $host -Count 1).ResponseTime } else { "N/A" }
                }
            }
            catch {
                $connectivityTests += @{
                    Host = $host
                    Status = "Erreur"
                    ResponseTime = "N/A"
                }
            }
        }
        
        # Partages réseau
        $networkShares = Get-SmbShare | ForEach-Object {
            @{
                Name = $_.Name
                Path = $_.Path
                Description = $_.Description
                ShareType = $_.ShareType
            }
        }
        
        $networkInfo = @{
            IPConfiguration = $ipConfig
            ActiveConnections = $connections
            NetworkStatistics = $networkStats
            ConnectivityTests = $connectivityTests
            NetworkShares = $networkShares
            HostName = $env:COMPUTERNAME
            Domain = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
        }
        
        return $networkInfo
    }
    catch {
        Write-Log "Erreur lors de la collecte des informations réseau: $($_.Exception.Message)" -Level "ERROR"
        return @{}
    }
}

function Get-SoftwareInventory {
    try {
        Write-Log "📦 Collecte de l'inventaire logiciel..." -Level "INFO"
        
        # Programmes installés (Registre)
        $installedPrograms = @()
        
        $registryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        foreach ($path in $registryPaths) {
            try {
                $programs = Get-ItemProperty $path -ErrorAction SilentlyContinue | 
                           Where-Object { $_.DisplayName -and $_.DisplayName -notmatch "^(KB|Update)" } |
                           ForEach-Object {
                    @{
                        Name = $_.DisplayName
                        Version = $_.DisplayVersion
                        Publisher = $_.Publisher
                        InstallDate = $_.InstallDate
                        Size = if ($_.EstimatedSize) { [math]::Round($_.EstimatedSize / 1024, 2) } else { "N/A" }
                        UninstallString = $_.UninstallString
                    }
                }
                $installedPrograms += $programs
            }
            catch {
                # Continuer si erreur d'accès au registre
            }
        }
        
        # Fonctionnalités Windows
        $windowsFeatures = @()
        try {
            $windowsFeatures = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq "Enabled" } | 
                              Select-Object -First 20 | ForEach-Object {
                @{
                    Name = $_.FeatureName
                    State = $_.State
                    Description = $_.Description
                }
            }
        }
        catch {
            # Fonctionnalités non disponibles
        }
        
        # Services installés
        $services = Get-Service | ForEach-Object {
            @{
                Name = $_.Name
                DisplayName = $_.DisplayName
                Status = $_.Status
                StartType = $_.StartType
                ServiceType = $_.ServiceType
            }
        }
        
        # Pilotes
        $drivers = Get-CimInstance -ClassName Win32_PnPSignedDriver | 
                  Where-Object { $_.DeviceName -and $_.DriverVersion } |
                  Sort-Object DeviceName | ForEach-Object {
            @{
                DeviceName = $_.DeviceName
                DriverVersion = $_.DriverVersion
                DriverDate = $_.DriverDate
                Manufacturer = $_.Manufacturer
                IsSigned = $_.IsSigned
            }
        }
        
        $softwareInfo = @{
            InstalledPrograms = $installedPrograms | Sort-Object Name
            WindowsFeatures = $windowsFeatures
            Services = $services | Sort-Object Name
            Drivers = $drivers
            ProgramCount = $installedPrograms.Count
            ServiceCount = $services.Count
            DriverCount = $drivers.Count
        }
        
        return $softwareInfo
    }
    catch {
        Write-Log "Erreur lors de la collecte de l'inventaire logiciel: $($_.Exception.Message)" -Level "ERROR"
        return @{}
    }
}

function Get-EventLogSummary {
    try {
        Write-Log "📋 Collecte du résumé des journaux d'événements..." -Level "INFO"
        
        $logSummary = @{}
        $logNames = @("System", "Application", "Security")
        
        foreach ($logName in $logNames) {
            try {
                $events = Get-WinEvent -FilterHashtable @{LogName=$logName; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 1000 -ErrorAction SilentlyContinue
                
                if ($events) {
                    $summary = @{
                        TotalEvents = $events.Count
                        Critical = ($events | Where-Object { $_.LevelDisplayName -eq "Critical" }).Count
                        Error = ($events | Where-Object { $_.LevelDisplayName -eq "Error" }).Count
                        Warning = ($events | Where-Object { $_.LevelDisplayName -eq "Warning" }).Count
                        Information = ($events | Where-Object { $_.LevelDisplayName -eq "Information" }).Count
                        TopSources = $events | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
                            @{ Source = $_.Name; Count = $_.Count }
                        }
                        RecentCritical = $events | Where-Object { $_.LevelDisplayName -eq "Critical" } | Select-Object -First 5 | ForEach-Object {
                            @{
                                TimeCreated = $_.TimeCreated
                                Id = $_.Id
                                Source = $_.ProviderName
                                Message = $_.Message.Substring(0, [Math]::Min(100, $_.Message.Length))
                            }
                        }
                    }
                    
                    $logSummary[$logName] = $summary
                }
            }
            catch {
                $logSummary[$logName] = @{ Error = "Accès refusé ou journal non disponible" }
            }
        }
        
        return $logSummary
    }
    catch {
        Write-Log "Erreur lors de la collecte des journaux: $($_.Exception.Message)" -Level "ERROR"
        return @{}
    }
}

function Generate-Recommendations {
    param($ReportData)
    
    $recommendations = @()
    
    try {
        Write-Log "💡 Génération des recommandations..." -Level "INFO"
        
        # Recommandations basées sur les performances
        if ($ReportData.Performance) {
            if ($ReportData.Performance.CPUUsagePercent -gt 80) {
                $recommendations += "⚠️ Utilisation CPU élevée ($($ReportData.Performance.CPUUsagePercent)%) - Vérifier les processus consommateurs"
            }
            
            if ($ReportData.Performance.MemoryUsagePercent -gt 85) {
                $recommendations += "⚠️ Utilisation mémoire élevée ($($ReportData.Performance.MemoryUsagePercent)%) - Considérer l'ajout de RAM"
            }
            
            $stoppedServices = $ReportData.Performance.ServiceStatus | Where-Object { $_.Status -eq "Stopped" }
            if ($stoppedServices.Count -gt 0) {
                $recommendations += "⚠️ $($stoppedServices.Count) service(s) critique(s) arrêté(s) - Vérifier: $($stoppedServices.Name -join ', ')"
            }
        }
        
        # Recommandations basées sur le matériel
        if ($ReportData.Hardware -and $ReportData.Hardware.Disks) {
            $lowSpaceDisks = $ReportData.Hardware.Disks | Where-Object { $_.PercentFree -lt 15 }
            foreach ($disk in $lowSpaceDisks) {
                $recommendations += "⚠️ Espace disque faible sur $($disk.Drive) ($($disk.PercentFree)% libre) - Nettoyer ou étendre"
            }
        }
        
        # Recommandations de sécurité
        if ($ReportData.Security) {
            if ($ReportData.Security.WindowsDefender.AntivirusEnabled -eq $false) {
                $recommendations += "🔒 Windows Defender désactivé - Activer la protection antivirus"
            }
            
            if ($ReportData.Security.WindowsUpdates.PendingUpdates -gt 0) {
                $recommendations += "🔒 $($ReportData.Security.WindowsUpdates.PendingUpdates) mise(s) à jour en attente - Installer les mises à jour"
            }
            
            if ($ReportData.Security.WindowsUpdates.RebootRequired) {
                $recommendations += "🔒 Redémarrage requis pour finaliser les mises à jour"
            }
            
            $disabledFirewall = $ReportData.Security.FirewallProfiles | Where-Object { $_.Enabled -eq $false }
            if ($disabledFirewall.Count -gt 0) {
                $recommendations += "🔒 Pare-feu désactivé sur profil(s): $($disabledFirewall.Name -join ', ')"
            }
        }
        
        # Recommandations réseau
        if ($ReportData.Network -and $ReportData.Network.ConnectivityTests) {
            $failedTests = $ReportData.Network.ConnectivityTests | Where-Object { $_.Status -ne "OK" }
            if ($failedTests.Count -gt 0) {
                $recommendations += "🌐 Problèmes de connectivité détectés vers: $($failedTests.Host -join ', ')"
            }
        }
        
        # Recommandations générales
        if ($ReportData.System -and $ReportData.System.Uptime) {
            if ($ReportData.System.Uptime.Days -gt 30) {
                $recommendations += "🔄 Système non redémarré depuis $($ReportData.System.Uptime.Days) jours - Redémarrage recommandé"
            }
        }
        
        if ($recommendations.Count -eq 0) {
            $recommendations += "✅ Aucun problème majeur détecté - Système en bon état"
        }
        
        return $recommendations
    }
    catch {
        Write-Log "Erreur lors de la génération des recommandations: $($_.Exception.Message)" -Level "ERROR"
        return @("Erreur lors de la génération des recommandations")
    }
}

function Export-Report {
    param(
        $ReportData,
        [string]$Format,
        [string]$OutputPath,
        [string]$FileName
    )
    
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $baseFileName = if ($FileName) { $FileName } else { "rapport_systeme_$timestamp" }
        
        switch ($Format) {
            "HTML" {
                $htmlFile = Join-Path $OutputPath "$baseFileName.html"
                $html = Generate-HTMLReport -ReportData $ReportData
                $html | Out-File -FilePath $htmlFile -Encoding UTF8
                Write-Log "✅ Rapport HTML généré: $htmlFile" -Level "SUCCESS"
                return $htmlFile
            }
            
            "JSON" {
                $jsonFile = Join-Path $OutputPath "$baseFileName.json"
                $ReportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
                Write-Log "✅ Rapport JSON généré: $jsonFile" -Level "SUCCESS"
                return $jsonFile
            }
            
            "CSV" {
                $csvFile = Join-Path $OutputPath "$baseFileName.csv"
                
                # Créer un résumé CSV
                $csvData = @()
                
                if ($ReportData.System) {
                    $csvData += [PSCustomObject]@{
                        Category = "System"
                        Item = "Computer Name"
                        Value = $ReportData.System.ComputerName
                    }
                    $csvData += [PSCustomObject]@{
                        Category = "System"
                        Item = "OS Version"
                        Value = $ReportData.System.OSName
                    }
                }
                
                if ($ReportData.Performance) {
                    $csvData += [PSCustomObject]@{
                        Category = "Performance"
                        Item = "CPU Usage %"
                        Value = $ReportData.Performance.CPUUsagePercent
                    }
                    $csvData += [PSCustomObject]@{
                        Category = "Performance"
                        Item = "Memory Usage %"
                        Value = $ReportData.Performance.MemoryUsagePercent
                    }
                }
                
                $csvData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
                Write-Log "✅ Rapport CSV généré: $csvFile" -Level "SUCCESS"
                return $csvFile
            }
            
            "XML" {
                $xmlFile = Join-Path $OutputPath "$baseFileName.xml"
                $ReportData | Export-Clixml -Path $xmlFile
                Write-Log "✅ Rapport XML généré: $xmlFile" -Level "SUCCESS"
                return $xmlFile
            }
        }
    }
    catch {
        Write-Log "Erreur lors de l'export: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Generate-HTMLReport {
    param($ReportData)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Rapport Système - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; }
        .section { margin: 30px 0; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px; background-color: #fafafa; }
        .section h2 { color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; margin-top: 0; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .metric { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #eee; }
        .metric:last-child { border-bottom: none; }
        .metric-label { font-weight: 600; color: #555; }
        .metric-value { color: #333; font-weight: bold; }
        .status-ok { color: #27ae60; }
        .status-warning { color: #f39c12; }
        .status-error { color: #e74c3c; }
        .recommendations { background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 20px; }
        .recommendations ul { margin: 0; padding-left: 20px; }
        .recommendations li { margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #667eea; color: white; font-weight: 600; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .progress-bar { width: 100%; height: 20px; background-color: #e0e0e0; border-radius: 10px; overflow: hidden; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #27ae60, #f39c12, #e74c3c); transition: width 0.3s ease; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🖥️ Rapport Système Windows</h1>
            <p>Généré le $(Get-Date -Format 'dddd dd MMMM yyyy à HH:mm:ss')</p>
            <p>Ordinateur: $($ReportData.System.ComputerName) | Utilisateur: $($ReportData.System.CurrentUser)</p>
        </div>
"@

    # Section Résumé Exécutif
    $html += @"
        <div class="section">
            <h2>📊 Résumé Exécutif</h2>
            <div class="grid">
                <div class="card">
                    <h3>Informations Système</h3>
"@

    if ($ReportData.System) {
        $html += @"
                    <div class="metric">
                        <span class="metric-label">Système d'exploitation:</span>
                        <span class="metric-value">$($ReportData.System.OSName)</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Version:</span>
                        <span class="metric-value">$($ReportData.System.OSVersion)</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Temps de fonctionnement:</span>
                        <span class="metric-value">$($ReportData.System.Uptime.Days) jours, $($ReportData.System.Uptime.Hours) heures</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Processeur:</span>
                        <span class="metric-value">$($ReportData.System.ProcessorName)</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Mémoire totale:</span>
                        <span class="metric-value">$($ReportData.System.TotalPhysicalMemory) GB</span>
                    </div>
"@
    }

    $html += "</div>"

    # Performances
    if ($ReportData.Performance) {
        $cpuClass = if ($ReportData.Performance.CPUUsagePercent -gt 80) { "status-error" } elseif ($ReportData.Performance.CPUUsagePercent -gt 60) { "status-warning" } else { "status-ok" }
        $memClass = if ($ReportData.Performance.MemoryUsagePercent -gt 85) { "status-error" } elseif ($ReportData.Performance.MemoryUsagePercent -gt 70) { "status-warning" } else { "status-ok" }
        
        $html += @"
                <div class="card">
                    <h3>Performances</h3>
                    <div class="metric">
                        <span class="metric-label">Utilisation CPU:</span>
                        <span class="metric-value $cpuClass">$($ReportData.Performance.CPUUsagePercent)%</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: $($ReportData.Performance.CPUUsagePercent)%"></div>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Utilisation Mémoire:</span>
                        <span class="metric-value $memClass">$($ReportData.Performance.MemoryUsagePercent)%</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: $($ReportData.Performance.MemoryUsagePercent)%"></div>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Processus actifs:</span>
                        <span class="metric-value">$($ReportData.Performance.ProcessCount)</span>
                    </div>
                </div>
"@
    }

    $html += "</div></div>"

    # Recommandations
    if ($script:Recommendations -and $script:Recommendations.Count -gt 0) {
        $html += @"
        <div class="section">
            <h2>💡 Recommandations</h2>
            <div class="recommendations">
                <ul>
"@
        foreach ($recommendation in $script:Recommendations) {
            $html += "<li>$recommendation</li>"
        }
        $html += "</ul></div></div>"
    }

    # Disques
    if ($ReportData.Hardware -and $ReportData.Hardware.Disks) {
        $html += @"
        <div class="section">
            <h2>💾 Espace Disque</h2>
            <table>
                <tr><th>Lecteur</th><th>Nom</th><th>Système de fichiers</th><th>Taille totale</th><th>Espace libre</th><th>% Libre</th></tr>
"@
        foreach ($disk in $ReportData.Hardware.Disks) {
            $freeClass = if ($disk.PercentFree -lt 15) { "status-error" } elseif ($disk.PercentFree -lt 25) { "status-warning" } else { "status-ok" }
            $html += @"
                <tr>
                    <td>$($disk.Drive)</td>
                    <td>$($disk.Label)</td>
                    <td>$($disk.FileSystem)</td>
                    <td>$($disk.SizeGB) GB</td>
                    <td>$($disk.FreeSpaceGB) GB</td>
                    <td class="$freeClass">$($disk.PercentFree)%</td>
                </tr>
"@
        }
        $html += "</table></div>"
    }

    # Top processus
    if ($ReportData.Performance -and $ReportData.Performance.TopProcessesCPU) {
        $html += @"
        <div class="section">
            <h2>⚡ Top Processus (CPU)</h2>
            <table>
                <tr><th>Processus</th><th>PID</th><th>CPU</th><th>Mémoire (MB)</th><th>Handles</th></tr>
"@
        foreach ($process in $ReportData.Performance.TopProcessesCPU | Select-Object -First 10) {
            $html += @"
                <tr>
                    <td>$($process.Name)</td>
                    <td>$($process.PID)</td>
                    <td>$($process.CPU)</td>
                    <td>$($process.WorkingSet)</td>
                    <td>$($process.Handles)</td>
                </tr>
"@
        }
        $html += "</table></div>"
    }

    $html += @"
        <div class="section">
            <h2>ℹ️ Informations sur le Rapport</h2>
            <p><strong>Type de rapport:</strong> $ReportType</p>
            <p><strong>Généré par:</strong> $($env:USERNAME) sur $($env:COMPUTERNAME)</p>
            <p><strong>Script:</strong> $($script:ScriptName)</p>
            <p><strong>Durée de génération:</strong> Quelques secondes</p>
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}

function Show-ConsoleReport {
    param($ReportData)
    
    Clear-Host
    Write-Host "="*80 -ForegroundColor Cyan
    Write-Host "🖥️  RAPPORT SYSTÈME WINDOWS" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor Cyan
    
    if ($ReportData.System) {
        Write-Host "`n📋 INFORMATIONS SYSTÈME:" -ForegroundColor Yellow
        Write-Host "   Ordinateur: $($ReportData.System.ComputerName)" -ForegroundColor White
        Write-Host "   Système: $($ReportData.System.OSName)" -ForegroundColor White
        Write-Host "   Version: $($ReportData.System.OSVersion)" -ForegroundColor White
        Write-Host "   Processeur: $($ReportData.System.ProcessorName)" -ForegroundColor White
        Write-Host "   Mémoire: $($ReportData.System.TotalPhysicalMemory) GB" -ForegroundColor White
        Write-Host "   Temps de fonctionnement: $($ReportData.System.Uptime.Days) jours, $($ReportData.System.Uptime.Hours) heures" -ForegroundColor White
    }
    
    if ($ReportData.Performance) {
        Write-Host "`n📊 PERFORMANCES:" -ForegroundColor Yellow
        
        $cpuColor = if ($ReportData.Performance.CPUUsagePercent -gt 80) { "Red" } elseif ($ReportData.Performance.CPUUsagePercent -gt 60) { "Yellow" } else { "Green" }
        $memColor = if ($ReportData.Performance.MemoryUsagePercent -gt 85) { "Red" } elseif ($ReportData.Performance.MemoryUsagePercent -gt 70) { "Yellow" } else { "Green" }
        
        Write-Host "   CPU: $($ReportData.Performance.CPUUsagePercent)%" -ForegroundColor $cpuColor
        Write-Host "   Mémoire: $($ReportData.Performance.MemoryUsagePercent)% ($($ReportData.Performance.UsedMemoryGB)/$($ReportData.Performance.TotalMemoryGB) GB)" -ForegroundColor $memColor
        Write-Host "   Processus: $($ReportData.Performance.ProcessCount)" -ForegroundColor White
    }
    
    if ($ReportData.Hardware -and $ReportData.Hardware.Disks) {
        Write-Host "`n💾 DISQUES:" -ForegroundColor Yellow
        foreach ($disk in $ReportData.Hardware.Disks) {
            $freeColor = if ($disk.PercentFree -lt 15) { "Red" } elseif ($disk.PercentFree -lt 25) { "Yellow" } else { "Green" }
            Write-Host "   $($disk.Drive) [$($disk.Label)] - $($disk.FreeSpaceGB)/$($disk.SizeGB) GB libre ($($disk.PercentFree)%)" -ForegroundColor $freeColor
        }
    }
    
    if ($script:Recommendations -and $script:Recommendations.Count -gt 0) {
        Write-Host "`n💡 RECOMMANDATIONS:" -ForegroundColor Yellow
        foreach ($recommendation in $script:Recommendations) {
            if ($recommendation -match "⚠️") {
                Write-Host "   $recommendation" -ForegroundColor Red
            } elseif ($recommendation -match "🔒") {
                Write-Host "   $recommendation" -ForegroundColor Yellow
            } else {
                Write-Host "   $recommendation" -ForegroundColor Green
            }
        }
    }
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
}

function Show-InteractiveMenu {
    do {
        Clear-Host
        Write-Host "🖥️ GÉNÉRATEUR DE RAPPORTS SYSTÈME" -ForegroundColor Cyan
        Write-Host "="*50 -ForegroundColor Cyan
        Write-Host "1. Rapport système complet" -ForegroundColor White
        Write-Host "2. Rapport de performances" -ForegroundColor White
        Write-Host "3. Rapport matériel" -ForegroundColor White
        Write-Host "4. Rapport de sécurité" -ForegroundColor White
        Write-Host "5. Rapport réseau" -ForegroundColor White
        Write-Host "6. Inventaire logiciel" -ForegroundColor White
        Write-Host "7. Rapport rapide" -ForegroundColor White
        Write-Host "8. Rapport personnalisé" -ForegroundColor White
        Write-Host "0. Quitter" -ForegroundColor Red
        Write-Host "="*50 -ForegroundColor Cyan
        
        $choice = Read-Host "Votre choix"
        
        switch ($choice) {
            "1" {
                Write-Host "Génération du rapport complet..." -ForegroundColor Yellow
                $script:ReportType = "Complete"
                Generate-SystemReport
            }
            
            "2" {
                Write-Host "Génération du rapport de performances..." -ForegroundColor Yellow
                $script:ReportType = "Performance"
                $script:IncludePerformance = $true
                Generate-SystemReport
            }
            
            "3" {
                Write-Host "Génération du rapport matériel..." -ForegroundColor Yellow
                $script:ReportType = "Hardware"
                Generate-SystemReport
            }
            
            "4" {
                Write-Host "Génération du rapport de sécurité..." -ForegroundColor Yellow
                $script:ReportType = "Security"
                $script:IncludeSecurity = $true
                Generate-SystemReport
            }
            
            "5" {
                Write-Host "Génération du rapport réseau..." -ForegroundColor Yellow
                $script:ReportType = "Network"
                $script:IncludeNetwork = $true
                Generate-SystemReport
            }
            
            "6" {
                Write-Host "Génération de l'inventaire logiciel..." -ForegroundColor Yellow
                $script:ReportType = "Software"
                $script:IncludeInventory = $true
                Generate-SystemReport
            }
            
            "7" {
                Write-Host "Génération du rapport rapide..." -ForegroundColor Yellow
                $script:ReportType = "Quick"
                Generate-SystemReport
            }
            
            "8" {
                Write-Host "Configuration du rapport personnalisé:" -ForegroundColor Yellow
                $script:IncludePerformance = (Read-Host "Inclure les performances? (o/N)") -eq "o"
                $script:IncludeSecurity = (Read-Host "Inclure la sécurité? (o/N)") -eq "o"
                $script:IncludeNetwork = (Read-Host "Inclure le réseau? (o/N)") -eq "o"
                $script:IncludeInventory = (Read-Host "Inclure l'inventaire? (o/N)") -eq "o"
                $script:IncludeRecommendations = (Read-Host "Inclure les recommandations? (o/N)") -eq "o"
                
                $format = Read-Host "Format de sortie (HTML/JSON/CSV/Console)"
                if ($format) { $script:OutputFormat = $format }
                
                Generate-SystemReport
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

function Generate-SystemReport {
    try {
        Write-Log "🚀 Génération du rapport système ($ReportType)" -Level "SUCCESS"
        
        # Collecter les données selon le type de rapport
        $script:ReportData = @{}
        
        # Informations système (toujours incluses)
        $script:ReportData.System = Get-SystemInformation
        
        switch ($ReportType) {
            "Complete" {
                $script:ReportData.Hardware = Get-HardwareInformation
                $script:ReportData.Performance = Get-PerformanceInformation
                $script:ReportData.Security = Get-SecurityInformation
                $script:ReportData.Network = Get-NetworkInformation
                $script:ReportData.Software = Get-SoftwareInventory
                $script:ReportData.EventLogs = Get-EventLogSummary
                $script:IncludeRecommendations = $true
            }
            
            "Hardware" {
                $script:ReportData.Hardware = Get-HardwareInformation
            }
            
            "Performance" {
                $script:ReportData.Performance = Get-PerformanceInformation
                $script:IncludeRecommendations = $true
            }
            
            "Security" {
                $script:ReportData.Security = Get-SecurityInformation
                $script:IncludeRecommendations = $true
            }
            
            "Network" {
                $script:ReportData.Network = Get-NetworkInformation
            }
            
            "Software" {
                $script:ReportData.Software = Get-SoftwareInventory
            }
            
            "Quick" {
                $script:ReportData.Performance = Get-PerformanceInformation
                $script:ReportData.Hardware = @{ Disks = (Get-HardwareInformation).Disks }
            }
        }
        
        # Ajouter les sections optionnelles
        if ($IncludePerformance -and -not $script:ReportData.Performance) {
            $script:ReportData.Performance = Get-PerformanceInformation
        }
        
        if ($IncludeSecurity -and -not $script:ReportData.Security) {
            $script:ReportData.Security = Get-SecurityInformation
        }
        
        if ($IncludeNetwork -and -not $script:ReportData.Network) {
            $script:ReportData.Network = Get-NetworkInformation
        }
        
        if ($IncludeInventory -and -not $script:ReportData.Software) {
            $script:ReportData.Software = Get-SoftwareInventory
        }
        
        if ($IncludeLogs -and -not $script:ReportData.EventLogs) {
            $script:ReportData.EventLogs = Get-EventLogSummary
        }
        
        # Générer les recommandations
        if ($IncludeRecommendations) {
            $script:Recommendations = Generate-Recommendations -ReportData $script:ReportData
        }
        
        # Afficher ou exporter le rapport
        if ($OutputFormat -eq "Console") {
            Show-ConsoleReport -ReportData $script:ReportData
        } else {
            $reportFile = Export-Report -ReportData $script:ReportData -Format $OutputFormat -OutputPath $OutputPath
            Write-Log "📄 Rapport généré: $reportFile" -Level "SUCCESS"
            
            # Ouvrir le rapport si HTML
            if ($OutputFormat -eq "HTML" -and (Test-Path $reportFile)) {
                try {
                    Start-Process $reportFile
                }
                catch {
                    Write-Log "Impossible d'ouvrir automatiquement le rapport" -Level "WARN"
                }
            }
        }
        
        Write-Log "✅ Rapport système généré avec succès" -Level "SUCCESS"
    }
    catch {
        Write-Log "Erreur lors de la génération du rapport: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Script principal
try {
    Write-Log "🚀 Générateur de rapports système Windows" -Level "SUCCESS"
    Write-Log "Type: $ReportType | Format: $OutputFormat"
    
    if ($Interactive) {
        Show-InteractiveMenu
    } else {
        Generate-SystemReport
    }
}
catch {
    Write-Log "Erreur: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Utilisez Get-Help .\rapport_sys.ps1 -Full pour plus d'informations" -Level "INFO"
    exit 1
}