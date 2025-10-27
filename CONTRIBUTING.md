# Guide de Contribution

Merci de votre intérêt pour contribuer au projet **Panel d'Outils PowerShell Professionnels** ! 🎉

## 📋 Comment contribuer

### 1. Fork et Clone
```powershell
# Fork le projet sur GitHub, puis :
git clone https://github.com/VOTRE-USERNAME/Projet-PowerShell-Windows.git
cd Projet-PowerShell-Windows
```

### 2. Créer une branche
```powershell
git checkout -b feature/nom-de-votre-fonctionnalite
```

### 3. Standards de code

#### Structure des scripts PowerShell
```powershell
<#
.SYNOPSIS
    Description courte du script

.DESCRIPTION
    Description détaillée de ce que fait le script

.PARAMETER ParameterName
    Description du paramètre

.EXAMPLE
    .\script.ps1 -Parameter "value"
    Description de l'exemple

.NOTES
    Auteur: Votre Nom
    Date: DD/MM/YYYY
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Parameter = "DefaultValue"
)

# Configuration
$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

# Fonctions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $(
        switch($Level) {
            "ERROR" { "Red" }
            "WARN"  { "Yellow" }
            "INFO"  { "Green" }
            default { "White" }
        }
    )
}

# Script principal
try {
    Write-Log "Début du script"
    
    # Votre code ici
    
    Write-Log "Script terminé avec succès"
}
catch {
    Write-Log "Erreur: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}
```

#### Conventions de nommage
- **Fichiers** : `verbe-nom.ps1` (ex: `analyse-log.ps1`)
- **Fonctions** : `Verb-Noun` (ex: `Get-SystemInfo`)
- **Variables** : `$camelCase` (ex: `$logFilePath`)
- **Constantes** : `$UPPER_CASE` (ex: `$MAX_FILE_SIZE`)

#### Bonnes pratiques
- ✅ Utilisez `[CmdletBinding()]` pour tous les scripts
- ✅ Gérez les erreurs avec `try/catch`
- ✅ Ajoutez des logs informatifs
- ✅ Validez les paramètres d'entrée
- ✅ Documentez avec des commentaires `<# #>`
- ✅ Testez sur Windows 10/11 et Server
- ❌ N'utilisez pas `Write-Host` sauf pour l'affichage coloré
- ❌ Évitez les chemins codés en dur
- ❌ Ne pas ignorer les erreurs silencieusement

### 4. Organisation des dossiers

```
contributeur_nom/
├── script1.ps1
├── script2.ps1
├── config/
│   └── default.json
├── lib/
│   └── common-functions.ps1
└── README.md
```

### 5. Tests

Avant de soumettre :
```powershell
# Test de syntaxe
Get-Command .\votre-script.ps1 -Syntax

# Test d'exécution
.\votre-script.ps1 -WhatIf

# Test avec différents paramètres
.\votre-script.ps1 -Verbose
```

### 6. Documentation

Chaque nouveau script doit inclure :
- Synopsis et description détaillée
- Exemples d'utilisation
- Liste des paramètres
- Prérequis système
- Notes sur les permissions requises

### 7. Commit et Pull Request

#### Messages de commit
```
type(scope): description courte

Description plus détaillée si nécessaire

- Changement 1
- Changement 2
```

**Types de commit :**
- `feat`: nouvelle fonctionnalité
- `fix`: correction de bug
- `docs`: documentation
- `style`: formatage, pas de changement de code
- `refactor`: refactorisation
- `test`: ajout de tests
- `chore`: maintenance

#### Exemple
```
feat(sameer): ajout du script de nettoyage automatique

Nouveau script cleanFiles.ps1 qui :
- Nettoie les fichiers temporaires Windows
- Vide la corbeille
- Nettoie le cache des navigateurs
- Génère un rapport de l'espace libéré
```

### 8. Pull Request

1. **Titre clair** : `[CONTRIBUTEUR] Description de la fonctionnalité`
2. **Description** :
   - Qu'est-ce qui a été ajouté/modifié ?
   - Pourquoi ce changement ?
   - Comment tester ?
3. **Checklist** :
   - [ ] Code testé sur Windows 10/11
   - [ ] Documentation mise à jour
   - [ ] Respect des conventions de nommage
   - [ ] Gestion d'erreurs implémentée
   - [ ] Logs ajoutés

## 🐛 Signaler un bug

Utilisez le template d'issue avec :
- **Environnement** : Version Windows, PowerShell
- **Étapes** : Comment reproduire le bug
- **Résultat attendu** vs **Résultat obtenu**
- **Logs** : Messages d'erreur complets

## 💡 Proposer une fonctionnalité

1. Vérifiez qu'elle n'existe pas déjà
2. Ouvrez une issue avec le label `enhancement`
3. Décrivez le cas d'usage
4. Proposez une implémentation

## 📞 Contact

- **Issues GitHub** : Pour bugs et fonctionnalités
- **Discussions** : Pour questions générales
- **Email** : jimmy.ramsamynaick@example.com

## 🏆 Reconnaissance

Tous les contributeurs seront ajoutés au README principal avec leurs contributions.

---

Merci de contribuer à rendre ce projet encore meilleur ! 🚀