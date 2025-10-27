<#
.SYNOPSIS
    Générateur de templates de scripts PowerShell professionnels

.DESCRIPTION
    Ce script génère des templates de scripts PowerShell avec :
    - Structure standardisée et bonnes pratiques
    - Gestion d'erreurs intégrée
    - Documentation complète
    - Fonctions utilitaires communes
    - Templates spécialisés (système, réseau, maintenance, etc.)

.PARAMETER TemplateType
    Type de template: Basic, System, Network, Maintenance, GUI, Module, Class

.PARAMETER ScriptName
    Nom du script à générer (sans extension)

.PARAMETER OutputPath
    Chemin de sortie pour le script généré

.PARAMETER Author
    Nom de l'auteur du script

.PARAMETER Description
    Description du script à générer

.PARAMETER IncludeExamples
    Inclure des exemples d'utilisation dans le template

.PARAMETER AddLogging
    Ajouter un système de logging avancé

.EXAMPLE
    .\templateGenerator.ps1 -TemplateType Basic -ScriptName "mon-script"
    Génère un template de base

.EXAMPLE
    .\templateGenerator.ps1 -TemplateType System -ScriptName "system-monitor" -Author "John Doe" -AddLogging
    Génère un template système avec logging

.NOTES
    Auteur: Sameer
    Date: 28/10/2025
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Basic", "System", "Network", "Maintenance", "GUI", "Module", "Class")]
    [string]$TemplateType,
    
    [Parameter(Mandatory=$true)]
    [string]$ScriptName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".",
    
    [Parameter(Mandatory=$false)]
    [string]$Author = $env:USERNAME,
    
    [Parameter(Mandatory=$false)]
    [string]$Description = "Description du script",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeExamples,
    
    [Parameter(Mandatory=$false)]
    [switch]$AddLogging
)

# Configuration
$ErrorActionPreference = "Stop"

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

function Get-TemplateHeader {
    param([string]$ScriptName, [string]$Description, [string]$Author)
    
    $date = Get-Date -Format "dd/MM/yyyy"
    
    return @"
<#
.SYNOPSIS
    $Description

.DESCRIPTION
    Description détaillée du script $ScriptName
    
    Ce script permet de :
    - Fonctionnalité 1
    - Fonctionnalité 2
    - Fonctionnalité 3

.PARAMETER Parameter1
    Description du premier paramètre

.PARAMETER Parameter2
    Description du deuxième paramètre

.EXAMPLE
    .\$ScriptName.ps1
    Exemple d'utilisation de base

.EXAMPLE
    .\$ScriptName.ps1 -Parameter1 "value" -Parameter2
    Exemple avec paramètres

.NOTES
    Auteur: $Author
    Date: $date
    Version: 1.0
    
    Prérequis:
    - PowerShell 5.1 ou supérieur
    - Droits d'exécution appropriés
    
    Historique des versions:
    1.0 - Version initiale
#>
"@
}

function Get-BasicParameters {
    return @"

[CmdletBinding()]
param(
    [Parameter(Mandatory=`$false, HelpMessage="Premier paramètre")]
    [string]`$Parameter1 = "DefaultValue",
    
    [Parameter(Mandatory=`$false, HelpMessage="Deuxième paramètre")]
    [switch]`$Parameter2,
    
    [Parameter(Mandatory=`$false, HelpMessage="Mode verbeux")]
    [switch]`$Verbose
)
"@
}

function Get-CommonFunctions {
    param([bool]$IncludeLogging)
    
    $functions = @"

# Configuration globale
`$ErrorActionPreference = "Stop"
`$VerbosePreference = if (`$Verbose) { "Continue" } else { "SilentlyContinue" }

# Variables globales
`$script:ScriptPath = `$PSScriptRoot
`$script:ScriptName = [System.IO.Path]::GetFileNameWithoutExtension(`$PSCommandPath)
"@

    if ($IncludeLogging) {
        $functions += @"

`$script:LogPath = Join-Path `$script:ScriptPath "`$(`$script:ScriptName)_`$(Get-Date -Format 'yyyyMMdd').log"

# Fonction de logging avancée
function Write-Log {
    param(
        [Parameter(Mandatory=`$true)]
        [string]`$Message,
        
        [Parameter(Mandatory=`$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]`$Level = "INFO",
        
        [Parameter(Mandatory=`$false)]
        [switch]`$NoConsole,
        
        [Parameter(Mandatory=`$false)]
        [switch]`$NoFile
    )
    
    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$logEntry = "[`$timestamp] [`$Level] `$Message"
    
    # Affichage console avec couleurs
    if (-not `$NoConsole) {
        `$color = switch(`$Level) {
            "ERROR" { "Red" }
            "WARN"  { "Yellow" }
            "INFO"  { "Green" }
            "SUCCESS" { "Cyan" }
            "DEBUG" { "Gray" }
            default { "White" }
        }
        Write-Host `$logEntry -ForegroundColor `$color
    }
    
    # Écriture dans le fichier de log
    if (-not `$NoFile) {
        try {
            `$logEntry | Out-File -FilePath `$script:LogPath -Append -Encoding UTF8
        }
        catch {
            Write-Warning "Impossible d'écrire dans le log: `$(`$_.Exception.Message)"
        }
    }
}
"@
    } else {
        $functions += @"

# Fonction de logging simple
function Write-Log {
    param([string]`$Message, [string]`$Level = "INFO")
    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$color = switch(`$Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "INFO"  { "Green" }
        "SUCCESS" { "Cyan" }
        default { "White" }
    }
    Write-Host "[`$timestamp] [`$Level] `$Message" -ForegroundColor `$color
}
"@
    }

    $functions += @"

# Fonction de validation des prérequis
function Test-Prerequisites {
    Write-Log "Vérification des prérequis..."
    
    # Vérifier la version PowerShell
    if (`$PSVersionTable.PSVersion.Major -lt 5) {
        throw "PowerShell 5.0 ou supérieur requis. Version actuelle: `$(`$PSVersionTable.PSVersion)"
    }
    
    # Vérifier les modules requis
    `$requiredModules = @()  # Ajouter les modules nécessaires
    foreach (`$module in `$requiredModules) {
        if (-not (Get-Module -ListAvailable -Name `$module)) {
            throw "Module requis non trouvé: `$module"
        }
    }
    
    Write-Log "✅ Prérequis validés" -Level "SUCCESS"
    return `$true
}

# Fonction de gestion d'erreurs
function Handle-Error {
    param([System.Management.Automation.ErrorRecord]`$ErrorRecord)
    
    `$errorMessage = "Erreur: `$(`$ErrorRecord.Exception.Message)"
    `$errorLine = "Ligne: `$(`$ErrorRecord.InvocationInfo.ScriptLineNumber)"
    `$errorCommand = "Commande: `$(`$ErrorRecord.InvocationInfo.Line.Trim())"
    
    Write-Log `$errorMessage -Level "ERROR"
    Write-Log `$errorLine -Level "ERROR"
    Write-Log `$errorCommand -Level "ERROR"
}
"@

    return $functions
}

function Get-SystemTemplate {
    return @"

# Fonctions spécifiques système
function Get-SystemInfo {
    Write-Log "Collecte des informations système..."
    
    try {
        `$systemInfo = [PSCustomObject]@{
            ComputerName = `$env:COMPUTERNAME
            OS = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
            Version = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
            Architecture = (Get-CimInstance -ClassName Win32_OperatingSystem).OSArchitecture
            TotalMemory = [math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
            Processor = (Get-CimInstance -ClassName Win32_Processor).Name
            LastBoot = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
        }
        
        Write-Log "Informations système collectées" -Level "SUCCESS"
        return `$systemInfo
    }
    catch {
        Handle-Error `$_
        throw
    }
}

function Test-SystemHealth {
    Write-Log "Vérification de la santé du système..."
    
    `$healthChecks = @{
        DiskSpace = `$false
        Memory = `$false
        Services = `$false
        EventLogs = `$false
    }
    
    try {
        # Vérifier l'espace disque
        `$drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { `$_.DriveType -eq 3 }
        `$healthChecks.DiskSpace = (`$drives | ForEach-Object { (`$_.FreeSpace / `$_.Size) * 100 } | Measure-Object -Minimum).Minimum -gt 10
        
        # Vérifier la mémoire
        `$memory = Get-CimInstance -ClassName Win32_OperatingSystem
        `$memoryUsage = ((`$memory.TotalVisibleMemorySize - `$memory.FreePhysicalMemory) / `$memory.TotalVisibleMemorySize) * 100
        `$healthChecks.Memory = `$memoryUsage -lt 90
        
        # Vérifier les services critiques
        `$criticalServices = @("Winmgmt", "RpcSs", "Dhcp", "Dnscache")
        `$healthChecks.Services = (`$criticalServices | ForEach-Object { (Get-Service -Name `$_).Status -eq "Running" } | Where-Object { -not `$_ }).Count -eq 0
        
        # Vérifier les erreurs récentes dans les logs
        `$recentErrors = Get-WinEvent -FilterHashtable @{LogName="System"; Level=2; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 10 -ErrorAction SilentlyContinue
        `$healthChecks.EventLogs = (`$recentErrors.Count -lt 5)
        
        Write-Log "Vérification de santé terminée" -Level "SUCCESS"
        return `$healthChecks
    }
    catch {
        Handle-Error `$_
        throw
    }
}
"@
}

function Get-NetworkTemplate {
    return @"

# Fonctions spécifiques réseau
function Test-NetworkConnectivity {
    param(
        [string[]]`$Hosts = @("8.8.8.8", "1.1.1.1", "google.com"),
        [int]`$Timeout = 5000
    )
    
    Write-Log "Test de connectivité réseau..."
    
    `$results = @()
    foreach (`$host in `$Hosts) {
        try {
            `$ping = Test-Connection -ComputerName `$host -Count 1 -Quiet -TimeoutSeconds (`$Timeout/1000)
            `$results += [PSCustomObject]@{
                Host = `$host
                Status = if (`$ping) { "Success" } else { "Failed" }
                ResponseTime = if (`$ping) { (Test-Connection -ComputerName `$host -Count 1).ResponseTime } else { 0 }
            }
        }
        catch {
            `$results += [PSCustomObject]@{
                Host = `$host
                Status = "Error"
                ResponseTime = 0
            }
        }
    }
    
    return `$results
}

function Get-NetworkConfiguration {
    Write-Log "Collecte de la configuration réseau..."
    
    try {
        `$adapters = Get-NetAdapter | Where-Object { `$_.Status -eq "Up" }
        `$networkConfig = @()
        
        foreach (`$adapter in `$adapters) {
            `$ipConfig = Get-NetIPAddress -InterfaceIndex `$adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            `$dnsServers = Get-DnsClientServerAddress -InterfaceIndex `$adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            
            `$networkConfig += [PSCustomObject]@{
                Name = `$adapter.Name
                Description = `$adapter.InterfaceDescription
                Status = `$adapter.Status
                Speed = `$adapter.LinkSpeed
                IPAddress = `$ipConfig.IPAddress -join ", "
                SubnetMask = `$ipConfig.PrefixLength -join ", "
                DNSServers = `$dnsServers.ServerAddresses -join ", "
            }
        }
        
        return `$networkConfig
    }
    catch {
        Handle-Error `$_
        throw
    }
}
"@
}

function Get-MainScript {
    param([string]$TemplateType)
    
    $mainScript = @"

# Script principal
try {
    Write-Log "🚀 Début du script `$(`$script:ScriptName)" -Level "SUCCESS"
    
    # Validation des prérequis
    Test-Prerequisites
    
    # Logique principale du script
    switch ("`$TemplateType") {
"@

    switch ($TemplateType) {
        "System" {
            $mainScript += @"
        "System" {
            `$systemInfo = Get-SystemInfo
            Write-Log "Système: `$(`$systemInfo.ComputerName) - `$(`$systemInfo.OS)"
            
            `$healthCheck = Test-SystemHealth
            Write-Log "État du système: Disque=`$(`$healthCheck.DiskSpace), Mémoire=`$(`$healthCheck.Memory), Services=`$(`$healthCheck.Services)"
        }
"@
        }
        "Network" {
            $mainScript += @"
        "Network" {
            `$connectivity = Test-NetworkConnectivity
            `$connectivity | ForEach-Object { Write-Log "Connectivité `$(`$_.Host): `$(`$_.Status)" }
            
            `$networkConfig = Get-NetworkConfiguration
            `$networkConfig | ForEach-Object { Write-Log "Adaptateur `$(`$_.Name): `$(`$_.IPAddress)" }
        }
"@
        }
        default {
            $mainScript += @"
        default {
            Write-Log "Exécution de la logique principale..."
            
            # TODO: Implémenter la logique spécifique du script
            Write-Log "Traitement en cours..."
            
            # Exemple de traitement
            for (`$i = 1; `$i -le 5; `$i++) {
                Write-Log "Étape `$i/5 en cours..."
                Start-Sleep -Seconds 1
            }
        }
"@
        }
    }

    $mainScript += @"
    }
    
    Write-Log "✅ Script terminé avec succès" -Level "SUCCESS"
}
catch {
    Handle-Error `$_
    Write-Log "❌ Script terminé avec des erreurs" -Level "ERROR"
    exit 1
}
finally {
    # Nettoyage si nécessaire
    Write-Log "Nettoyage final..." -Level "INFO"
}
"@

    return $mainScript
}

function Get-ExamplesSection {
    return @"

<#
EXEMPLES D'UTILISATION:

# Exemple 1: Utilisation de base
.\$ScriptName.ps1

# Exemple 2: Avec paramètres
.\$ScriptName.ps1 -Parameter1 "valeur" -Parameter2

# Exemple 3: Mode verbeux
.\$ScriptName.ps1 -Verbose

# Exemple 4: Aide
Get-Help .\$ScriptName.ps1 -Full

NOTES IMPORTANTES:
- Exécuter avec des droits appropriés
- Vérifier les prérequis avant utilisation
- Consulter les logs en cas de problème
#>
"@
}

function New-PowerShellScript {
    param(
        [string]$TemplateType,
        [string]$ScriptName,
        [string]$OutputPath,
        [string]$Author,
        [string]$Description,
        [bool]$IncludeExamples,
        [bool]$AddLogging
    )
    
    # Construire le contenu du script
    $scriptContent = ""
    
    # Header
    $scriptContent += Get-TemplateHeader -ScriptName $ScriptName -Description $Description -Author $Author
    
    # Paramètres
    $scriptContent += Get-BasicParameters
    
    # Fonctions communes
    $scriptContent += Get-CommonFunctions -IncludeLogging $AddLogging
    
    # Templates spécialisés
    switch ($TemplateType) {
        "System" {
            $scriptContent += Get-SystemTemplate
        }
        "Network" {
            $scriptContent += Get-NetworkTemplate
        }
        "Maintenance" {
            $scriptContent += Get-SystemTemplate  # Réutilise les fonctions système
        }
    }
    
    # Script principal
    $scriptContent += Get-MainScript -TemplateType $TemplateType
    
    # Exemples si demandés
    if ($IncludeExamples) {
        $scriptContent += Get-ExamplesSection
    }
    
    return $scriptContent
}

# Script principal
try {
    Write-Log "🔧 Générateur de templates PowerShell" -Level "SUCCESS"
    Write-Log "Type: $TemplateType | Script: $ScriptName | Auteur: $Author"
    
    # Valider le nom du script
    if ($ScriptName -notmatch '^[a-zA-Z0-9_-]+$') {
        throw "Nom de script invalide. Utilisez uniquement des lettres, chiffres, tirets et underscores."
    }
    
    # Construire le chemin de sortie
    $outputFile = Join-Path $OutputPath "$ScriptName.ps1"
    
    # Vérifier si le fichier existe déjà
    if (Test-Path $outputFile) {
        $response = Read-Host "Le fichier $outputFile existe déjà. Écraser ? (o/N)"
        if ($response -ne 'o' -and $response -ne 'O') {
            Write-Log "Génération annulée par l'utilisateur" -Level "INFO"
            exit 0
        }
    }
    
    # Générer le script
    Write-Log "Génération du template $TemplateType..."
    $scriptContent = New-PowerShellScript -TemplateType $TemplateType -ScriptName $ScriptName -OutputPath $OutputPath -Author $Author -Description $Description -IncludeExamples $IncludeExamples -AddLogging $AddLogging
    
    # Écrire le fichier
    $scriptContent | Out-File -FilePath $outputFile -Encoding UTF8
    
    Write-Log "✅ Script généré: $outputFile" -Level "SUCCESS"
    Write-Log "Taille: $([math]::Round((Get-Item $outputFile).Length / 1KB, 2)) KB"
    
    # Afficher un résumé
    Write-Host "`n=== RÉSUMÉ DU TEMPLATE GÉNÉRÉ ===" -ForegroundColor Cyan
    Write-Host "Fichier: $outputFile" -ForegroundColor Green
    Write-Host "Type: $TemplateType" -ForegroundColor Green
    Write-Host "Auteur: $Author" -ForegroundColor Green
    Write-Host "Logging avancé: $(if($AddLogging){'Oui'}else{'Non'})" -ForegroundColor Green
    Write-Host "Exemples inclus: $(if($IncludeExamples){'Oui'}else{'Non'})" -ForegroundColor Green
    
    Write-Host "`nPour utiliser le script généré:" -ForegroundColor Yellow
    Write-Host "  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor White
    Write-Host "  .\$ScriptName.ps1" -ForegroundColor White
    
    Write-Log "Template généré avec succès" -Level "SUCCESS"
}
catch {
    Write-Log "Erreur lors de la génération: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}