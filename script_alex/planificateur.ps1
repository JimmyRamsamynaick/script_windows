<#
.SYNOPSIS
    Planificateur de tâches récurrentes pour Windows

.DESCRIPTION
    Ce script permet de créer, gérer et surveiller des tâches planifiées sur Windows.
    Il offre une interface simplifiée pour automatiser l'exécution de scripts,
    programmes et commandes selon des horaires définis.

    Fonctionnalités :
    - Création de tâches planifiées avec différents déclencheurs
    - Gestion des tâches existantes (liste, modification, suppression)
    - Templates prédéfinis pour tâches courantes
    - Surveillance et rapports d'exécution
    - Gestion des utilisateurs et permissions
    - Export/Import de configurations de tâches
    - Notifications par email (optionnel)

.PARAMETER Action
    Action à effectuer: Create, List, Delete, Modify, Status, Export, Import

.PARAMETER TaskName
    Nom de la tâche à créer ou gérer

.PARAMETER ScriptPath
    Chemin vers le script ou programme à exécuter

.PARAMETER Schedule
    Type de planification: Daily, Weekly, Monthly, Startup, Logon, OnIdle

.PARAMETER Time
    Heure d'exécution (format HH:mm)

.PARAMETER Days
    Jours de la semaine (pour Weekly) ou du mois (pour Monthly)

.PARAMETER User
    Utilisateur sous lequel exécuter la tâche

.PARAMETER Template
    Template prédéfini: Backup, Cleanup, SystemCheck, LogRotation, Update

.PARAMETER ExportPath
    Chemin pour exporter/importer les configurations

.PARAMETER EnableNotifications
    Activer les notifications par email

.EXAMPLE
    .\planificateur.ps1 -Action Create -TaskName "Sauvegarde quotidienne" -ScriptPath "C:\Scripts\backup.ps1" -Schedule Daily -Time "02:00"
    Crée une tâche de sauvegarde quotidienne à 2h du matin

.EXAMPLE
    .\planificateur.ps1 -Action List
    Liste toutes les tâches planifiées

.EXAMPLE
    .\planificateur.ps1 -Action Create -Template Cleanup -Time "03:00"
    Crée une tâche de nettoyage avec le template prédéfini

.NOTES
    Auteur: Alex
    Date: 28/10/2025
    Version: 1.0
    
    Prérequis:
    - PowerShell 5.1 ou supérieur
    - Droits administrateur pour certaines opérations
    - Module ScheduledTasks (inclus dans Windows 10/Server 2016+)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Action à effectuer")]
    [ValidateSet("Create", "List", "Delete", "Modify", "Status", "Export", "Import", "Template")]
    [string]$Action,
    
    [Parameter(Mandatory=$false, HelpMessage="Nom de la tâche")]
    [string]$TaskName,
    
    [Parameter(Mandatory=$false, HelpMessage="Chemin du script à exécuter")]
    [string]$ScriptPath,
    
    [Parameter(Mandatory=$false, HelpMessage="Type de planification")]
    [ValidateSet("Daily", "Weekly", "Monthly", "Startup", "Logon", "OnIdle", "Custom")]
    [string]$Schedule = "Daily",
    
    [Parameter(Mandatory=$false, HelpMessage="Heure d'exécution")]
    [string]$Time = "02:00",
    
    [Parameter(Mandatory=$false, HelpMessage="Jours (1-7 pour semaine, 1-31 pour mois)")]
    [string[]]$Days = @(),
    
    [Parameter(Mandatory=$false, HelpMessage="Utilisateur pour l'exécution")]
    [string]$User = "SYSTEM",
    
    [Parameter(Mandatory=$false, HelpMessage="Template prédéfini")]
    [ValidateSet("Backup", "Cleanup", "SystemCheck", "LogRotation", "Update", "Monitoring")]
    [string]$Template,
    
    [Parameter(Mandatory=$false, HelpMessage="Chemin d'export/import")]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory=$false, HelpMessage="Activer les notifications")]
    [switch]$EnableNotifications,
    
    [Parameter(Mandatory=$false, HelpMessage="Description de la tâche")]
    [string]$Description = "",
    
    [Parameter(Mandatory=$false, HelpMessage="Priorité de la tâche")]
    [ValidateSet("Low", "Normal", "High")]
    [string]$Priority = "Normal"
)

# Configuration
$ErrorActionPreference = "Stop"
$script:ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
$script:LogPath = Join-Path $env:TEMP "$($script:ScriptName)_$(Get-Date -Format 'yyyyMMdd').log"
$script:IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

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

function Test-AdminRights {
    if (-not $script:IsAdmin) {
        Write-Log "⚠️  Certaines opérations nécessitent des droits administrateur" -Level "WARN"
        return $false
    }
    return $true
}

function Get-TaskTemplates {
    return @{
        "Backup" = @{
            Name = "Sauvegarde automatique"
            Description = "Sauvegarde quotidienne des données importantes"
            Script = "C:\Scripts\backup.ps1"
            Schedule = "Daily"
            Time = "02:00"
            Arguments = "-Full -Compress"
        }
        "Cleanup" = @{
            Name = "Nettoyage système"
            Description = "Nettoyage automatique des fichiers temporaires"
            Script = "C:\Scripts\cleanup.ps1"
            Schedule = "Weekly"
            Time = "03:00"
            Days = @("Sunday")
            Arguments = "-Deep -LogCleanup"
        }
        "SystemCheck" = @{
            Name = "Vérification système"
            Description = "Contrôle de santé du système"
            Script = "C:\Scripts\system-check.ps1"
            Schedule = "Daily"
            Time = "01:00"
            Arguments = "-FullCheck -EmailReport"
        }
        "LogRotation" = @{
            Name = "Rotation des logs"
            Description = "Archivage et rotation des fichiers de log"
            Script = "C:\Scripts\log-rotation.ps1"
            Schedule = "Weekly"
            Time = "04:00"
            Days = @("Monday")
            Arguments = "-ArchiveDays 30 -Compress"
        }
        "Update" = @{
            Name = "Mise à jour système"
            Description = "Installation automatique des mises à jour"
            Script = "C:\Scripts\update-system.ps1"
            Schedule = "Weekly"
            Time = "05:00"
            Days = @("Wednesday")
            Arguments = "-AutoReboot -SecurityOnly"
        }
        "Monitoring" = @{
            Name = "Surveillance système"
            Description = "Surveillance continue des performances"
            Script = "C:\Scripts\monitoring.ps1"
            Schedule = "Daily"
            Time = "00:30"
            Arguments = "-CheckDisk -CheckMemory -CheckServices"
        }
    }
}

function New-ScheduledTaskFromTemplate {
    param([string]$TemplateName)
    
    $templates = Get-TaskTemplates
    
    if (-not $templates.ContainsKey($TemplateName)) {
        throw "Template '$TemplateName' non trouvé. Templates disponibles: $($templates.Keys -join ', ')"
    }
    
    $template = $templates[$TemplateName]
    
    Write-Log "Création de la tâche à partir du template '$TemplateName'..." -Level "INFO"
    
    # Utiliser les valeurs du template
    $script:TaskName = if ($TaskName) { $TaskName } else { $template.Name }
    $script:ScriptPath = if ($ScriptPath) { $ScriptPath } else { $template.Script }
    $script:Schedule = if ($Schedule -ne "Daily") { $Schedule } else { $template.Schedule }
    $script:Time = if ($Time -ne "02:00") { $Time } else { $template.Time }
    $script:Description = if ($Description) { $Description } else { $template.Description }
    
    if ($template.Days) {
        $script:Days = $template.Days
    }
    
    # Créer la tâche
    New-CustomScheduledTask -TaskName $script:TaskName -ScriptPath $script:ScriptPath -Schedule $script:Schedule -Time $script:Time -Days $script:Days -Description $script:Description -Arguments $template.Arguments
}

function New-CustomScheduledTask {
    param(
        [string]$TaskName,
        [string]$ScriptPath,
        [string]$Schedule,
        [string]$Time,
        [string[]]$Days,
        [string]$Description,
        [string]$Arguments = ""
    )
    
    try {
        Write-Log "Création de la tâche planifiée '$TaskName'..." -Level "INFO"
        
        # Vérifier si la tâche existe déjà
        $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            $response = Read-Host "La tâche '$TaskName' existe déjà. Remplacer ? (o/N)"
            if ($response -ne 'o' -and $response -ne 'O') {
                Write-Log "Création annulée par l'utilisateur" -Level "INFO"
                return
            }
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }
        
        # Créer l'action
        $actionArgs = if ($Arguments) { "-File `"$ScriptPath`" $Arguments" } else { "-File `"$ScriptPath`"" }
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $actionArgs
        
        # Créer le déclencheur selon le type de planification
        $trigger = switch ($Schedule) {
            "Daily" {
                New-ScheduledTaskTrigger -Daily -At $Time
            }
            "Weekly" {
                if ($Days.Count -gt 0) {
                    $daysOfWeek = $Days | ForEach-Object {
                        switch ($_) {
                            "Monday" { "Monday" }
                            "Tuesday" { "Tuesday" }
                            "Wednesday" { "Wednesday" }
                            "Thursday" { "Thursday" }
                            "Friday" { "Friday" }
                            "Saturday" { "Saturday" }
                            "Sunday" { "Sunday" }
                            "1" { "Monday" }
                            "2" { "Tuesday" }
                            "3" { "Wednesday" }
                            "4" { "Thursday" }
                            "5" { "Friday" }
                            "6" { "Saturday" }
                            "7" { "Sunday" }
                            default { $_ }
                        }
                    }
                    New-ScheduledTaskTrigger -Weekly -DaysOfWeek $daysOfWeek -At $Time
                } else {
                    New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At $Time
                }
            }
            "Monthly" {
                if ($Days.Count -gt 0) {
                    $daysOfMonth = $Days | ForEach-Object { [int]$_ }
                    New-ScheduledTaskTrigger -Monthly -DaysOfMonth $daysOfMonth -At $Time
                } else {
                    New-ScheduledTaskTrigger -Monthly -DaysOfMonth 1 -At $Time
                }
            }
            "Startup" {
                New-ScheduledTaskTrigger -AtStartup
            }
            "Logon" {
                New-ScheduledTaskTrigger -AtLogOn
            }
            "OnIdle" {
                New-ScheduledTaskTrigger -OnIdle
            }
            default {
                New-ScheduledTaskTrigger -Daily -At $Time
            }
        }
        
        # Créer les paramètres
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        # Définir le principal (utilisateur)
        $principal = if ($User -eq "SYSTEM") {
            New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        } else {
            New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive
        }
        
        # Enregistrer la tâche
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $Description
        
        Write-Log "✅ Tâche '$TaskName' créée avec succès" -Level "SUCCESS"
        Write-Log "   Planification: $Schedule à $Time" -Level "INFO"
        Write-Log "   Script: $ScriptPath" -Level "INFO"
        Write-Log "   Utilisateur: $User" -Level "INFO"
        
        if ($Days.Count -gt 0) {
            Write-Log "   Jours: $($Days -join ', ')" -Level "INFO"
        }
    }
    catch {
        Write-Log "Erreur lors de la création de la tâche: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Get-ScheduledTasksList {
    Write-Log "📋 Liste des tâches planifiées..." -Level "INFO"
    
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
        
        if ($tasks.Count -eq 0) {
            Write-Log "Aucune tâche planifiée active trouvée" -Level "INFO"
            return
        }
        
        Write-Host "`n" + "="*100 -ForegroundColor Cyan
        Write-Host "📅 TÂCHES PLANIFIÉES ACTIVES" -ForegroundColor Cyan
        Write-Host "="*100 -ForegroundColor Cyan
        
        $taskInfo = @()
        foreach ($task in $tasks) {
            try {
                $taskInfo += [PSCustomObject]@{
                    Nom = $task.TaskName
                    État = $task.State
                    Chemin = $task.TaskPath
                    Description = $task.Description
                    Auteur = $task.Author
                    DernièreExécution = (Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue).LastRunTime
                    ProchaineExécution = (Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue).NextRunTime
                    RésultatDernier = (Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue).LastTaskResult
                }
            }
            catch {
                Write-Log "Erreur lors de la récupération des infos pour '$($task.TaskName)': $($_.Exception.Message)" -Level "WARN"
            }
        }
        
        $taskInfo | Format-Table -Property Nom, État, Description, DernièreExécution, ProchaineExécution -AutoSize
        
        Write-Host "`n📊 RÉSUMÉ:" -ForegroundColor Yellow
        Write-Host "   Total des tâches: $($tasks.Count)" -ForegroundColor White
        Write-Host "   Actives: $(($tasks | Where-Object { $_.State -eq 'Ready' }).Count)" -ForegroundColor Green
        Write-Host "   En cours: $(($tasks | Where-Object { $_.State -eq 'Running' }).Count)" -ForegroundColor Yellow
        
        return $taskInfo
    }
    catch {
        Write-Log "Erreur lors de la récupération des tâches: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Remove-ScheduledTaskByName {
    param([string]$TaskName)
    
    try {
        Write-Log "Suppression de la tâche '$TaskName'..." -Level "INFO"
        
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (-not $task) {
            Write-Log "Tâche '$TaskName' non trouvée" -Level "WARN"
            return
        }
        
        $confirmation = Read-Host "Confirmer la suppression de la tâche '$TaskName' ? (o/N)"
        if ($confirmation -ne 'o' -and $confirmation -ne 'O') {
            Write-Log "Suppression annulée" -Level "INFO"
            return
        }
        
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Log "✅ Tâche '$TaskName' supprimée avec succès" -Level "SUCCESS"
    }
    catch {
        Write-Log "Erreur lors de la suppression: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Get-TaskStatus {
    param([string]$TaskName)
    
    try {
        Write-Log "📊 Statut de la tâche '$TaskName'..." -Level "INFO"
        
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (-not $task) {
            Write-Log "Tâche '$TaskName' non trouvée" -Level "ERROR"
            return
        }
        
        $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName
        
        Write-Host "`n" + "="*60 -ForegroundColor Cyan
        Write-Host "📋 DÉTAILS DE LA TÂCHE: $TaskName" -ForegroundColor Cyan
        Write-Host "="*60 -ForegroundColor Cyan
        
        Write-Host "État: $($task.State)" -ForegroundColor $(if($task.State -eq "Ready"){"Green"}else{"Yellow"})
        Write-Host "Description: $($task.Description)" -ForegroundColor White
        Write-Host "Auteur: $($task.Author)" -ForegroundColor White
        Write-Host "Chemin: $($task.TaskPath)" -ForegroundColor White
        
        if ($taskInfo.LastRunTime) {
            Write-Host "Dernière exécution: $($taskInfo.LastRunTime)" -ForegroundColor White
            Write-Host "Résultat: $($taskInfo.LastTaskResult)" -ForegroundColor $(if($taskInfo.LastTaskResult -eq 0){"Green"}else{"Red"})
        }
        
        if ($taskInfo.NextRunTime) {
            Write-Host "Prochaine exécution: $($taskInfo.NextRunTime)" -ForegroundColor Green
        }
        
        # Afficher les déclencheurs
        $triggers = $task.Triggers
        if ($triggers) {
            Write-Host "`nDéclencheurs:" -ForegroundColor Yellow
            foreach ($trigger in $triggers) {
                Write-Host "  - Type: $($trigger.CimClass.CimClassName)" -ForegroundColor White
                if ($trigger.StartBoundary) {
                    Write-Host "    Début: $($trigger.StartBoundary)" -ForegroundColor White
                }
            }
        }
        
        # Afficher les actions
        $actions = $task.Actions
        if ($actions) {
            Write-Host "`nActions:" -ForegroundColor Yellow
            foreach ($action in $actions) {
                Write-Host "  - Exécuter: $($action.Execute)" -ForegroundColor White
                if ($action.Arguments) {
                    Write-Host "    Arguments: $($action.Arguments)" -ForegroundColor White
                }
            }
        }
        
        Write-Host "`n" + "="*60 -ForegroundColor Cyan
    }
    catch {
        Write-Log "Erreur lors de la récupération du statut: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Export-TasksConfiguration {
    param([string]$ExportPath)
    
    try {
        Write-Log "📤 Export des configurations de tâches..." -Level "INFO"
        
        $tasks = Get-ScheduledTask
        $exportData = @()
        
        foreach ($task in $tasks) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue
            
            $exportData += [PSCustomObject]@{
                Name = $task.TaskName
                State = $task.State
                Description = $task.Description
                Author = $task.Author
                TaskPath = $task.TaskPath
                Triggers = $task.Triggers | ConvertTo-Json -Depth 3
                Actions = $task.Actions | ConvertTo-Json -Depth 3
                Settings = $task.Settings | ConvertTo-Json -Depth 3
                Principal = $task.Principal | ConvertTo-Json -Depth 3
                LastRunTime = $taskInfo.LastRunTime
                NextRunTime = $taskInfo.NextRunTime
                LastTaskResult = $taskInfo.LastTaskResult
            }
        }
        
        $exportFile = Join-Path $ExportPath "scheduled_tasks_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $exportFile -Encoding UTF8
        
        Write-Log "✅ Configuration exportée: $exportFile" -Level "SUCCESS"
        Write-Log "   Nombre de tâches: $($exportData.Count)" -Level "INFO"
    }
    catch {
        Write-Log "Erreur lors de l'export: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Show-TemplateList {
    Write-Log "📋 Templates disponibles..." -Level "INFO"
    
    $templates = Get-TaskTemplates
    
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "📝 TEMPLATES DE TÂCHES DISPONIBLES" -ForegroundColor Cyan
    Write-Host "="*80 -ForegroundColor Cyan
    
    foreach ($templateName in $templates.Keys) {
        $template = $templates[$templateName]
        Write-Host "`n🔧 $templateName" -ForegroundColor Yellow
        Write-Host "   Nom: $($template.Name)" -ForegroundColor White
        Write-Host "   Description: $($template.Description)" -ForegroundColor White
        Write-Host "   Planification: $($template.Schedule) à $($template.Time)" -ForegroundColor White
        Write-Host "   Script: $($template.Script)" -ForegroundColor White
        if ($template.Days) {
            Write-Host "   Jours: $($template.Days -join ', ')" -ForegroundColor White
        }
        if ($template.Arguments) {
            Write-Host "   Arguments: $($template.Arguments)" -ForegroundColor White
        }
    }
    
    Write-Host "`n💡 Utilisation:" -ForegroundColor Cyan
    Write-Host "   .\planificateur.ps1 -Action Create -Template <NomTemplate> [-Time HH:mm] [-TaskName 'Nom personnalisé']" -ForegroundColor White
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
}

# Script principal
try {
    Write-Log "🚀 Planificateur de tâches Windows" -Level "SUCCESS"
    Write-Log "Action: $Action | Admin: $script:IsAdmin"
    
    switch ($Action) {
        "Create" {
            if ($Template) {
                New-ScheduledTaskFromTemplate -TemplateName $Template
            } else {
                if (-not $TaskName -or -not $ScriptPath) {
                    throw "TaskName et ScriptPath sont requis pour créer une tâche personnalisée"
                }
                New-CustomScheduledTask -TaskName $TaskName -ScriptPath $ScriptPath -Schedule $Schedule -Time $Time -Days $Days -Description $Description
            }
        }
        
        "List" {
            Get-ScheduledTasksList
        }
        
        "Delete" {
            if (-not $TaskName) {
                throw "TaskName est requis pour supprimer une tâche"
            }
            Remove-ScheduledTaskByName -TaskName $TaskName
        }
        
        "Status" {
            if (-not $TaskName) {
                throw "TaskName est requis pour afficher le statut"
            }
            Get-TaskStatus -TaskName $TaskName
        }
        
        "Export" {
            Export-TasksConfiguration -ExportPath $ExportPath
        }
        
        "Template" {
            Show-TemplateList
        }
        
        default {
            throw "Action non supportée: $Action"
        }
    }
    
    Write-Log "✅ Opération terminée avec succès" -Level "SUCCESS"
}
catch {
    Write-Log "Erreur: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Utilisez Get-Help .\planificateur.ps1 -Full pour plus d'informations" -Level "INFO"
    exit 1
}