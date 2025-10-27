# 🛠️ Panel d'Outils PowerShell Professionnels (Version Windows)

Ce dépôt regroupe une suite de scripts PowerShell conçus pour automatiser et simplifier des tâches systèmes courantes dans un environnement professionnel Windows. Les scripts sont organisés par contributeurs et thématiques afin de garantir modularité, lisibilité et efficacité.

## 📁 Structure du dépôt

```
Projet-PowerShell-Windows/
├── sameer/
│   ├── analysSSH.ps1           # Analyse des connexions SSH
│   ├── cleanFiles.ps1          # Nettoyage automatique de fichiers temporaires/inutiles
│   ├── majPackages.ps1         # Mise à jour automatisée des paquets système
│   └── templateGenerator.ps1   # Génération de templates de scripts PowerShell
│
├── script_alex/
│   ├── disque.ps1             # Vérification et rapport de l'espace disque
│   ├── optimisation.ps1       # Optimisations système simples
│   ├── planificateur.ps1      # Planification de tâches récurrentes (Task Scheduler)
│   └── sauvegarde.ps1         # Script de sauvegarde automatique
│
├── script_jimmy/
│   ├── analyse_log.ps1        # Analyse automatisée de fichiers de logs
│   ├── rapport_sys.ps1        # Génération de rapports système
│   ├── synch_repertoire.ps1   # Synchronisation de répertoires distants
│   └── test_reseaux.ps1       # Outils de test réseau de base
│
├── menu.ps1                   # Menu principal d'accès aux différents scripts
├── mini_jeu/                  # Mini-jeux (Space Invader, Nombre Mystère)
├── README.md                  # Présentation du projet
├── LICENSE                    # Licence MIT
├── CONTRIBUTING.md            # Guide de contribution
└── .gitignore                 # Fichiers à ignorer par Git
```

## ✅ Objectifs

- Fournir un **ensemble de scripts prêts à l'emploi** pour la gestion système Windows
- **Automatiser les tâches courantes** d'un administrateur ou technicien Windows
- Servir de **base pédagogique** pour apprendre le scripting PowerShell

## 🚀 Utilisation

### Prérequis
- Windows 10/11 ou Windows Server 2016+
- PowerShell 5.1 ou PowerShell Core 7+
- Droits d'administrateur pour certains scripts

### Installation

1. **Cloner le dépôt :**
```powershell
git clone https://github.com/JimmyRamsamynaick/Projet-PowerShell-Windows.git
cd Projet-PowerShell-Windows
```

2. **Configurer la politique d'exécution (si nécessaire) :**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

3. **Lancer un script :**
```powershell
.\sameer\cleanFiles.ps1
```

4. **Utiliser le menu principal :**
```powershell
.\menu.ps1
```

### Mini-Jeux

Le projet inclut un petit panneau de mini-jeux en console:

- `Space Invader` — déplacement `←/→`, tir `Espace`, `Q` pour quitter.
- `Nombre Mystère` — entrez un nombre (1..100), `q` pour quitter.

Lancement direct:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\mini_jeu\mini_jeu.ps1
```

Ou depuis le menu principal (`5. Mini Jeux`).

Commandes directes:

```powershell
# Space Invader (jeu)
pwsh -NoProfile -ExecutionPolicy Bypass -File .\mini_jeu\game.ps1

# Space Invader (menu dédié du mini-jeu)
pwsh -NoProfile -ExecutionPolicy Bypass -File .\mini_jeu\space_invader.ps1

# Nombre Mystère
pwsh -NoProfile -ExecutionPolicy Bypass -File .\mini_jeu\guess.ps1
```

### Dépannage

- Préférez l’exécution inline du mini-jeu (défaut actuel) au lieu d’un `Start-Process`.
- Sur certaines consoles, `QuickEdit` peut bloquer l’entrée clavier quand une sélection est active — appuyez sur `Échap` pour revenir.
- PowerShell 7 (`pwsh`) est recommandé pour une meilleure compatibilité.

## 📋 Scripts disponibles

### 👤 Sameer - Outils système généraux
- **analysSSH.ps1** : Analyse des connexions SSH actives et historique
- **cleanFiles.ps1** : Nettoyage intelligent des fichiers temporaires
- **majPackages.ps1** : Mise à jour des paquets via Chocolatey/Winget
- **templateGenerator.ps1** : Générateur de templates PowerShell

### 👤 Alex - Maintenance et planification
- **disque.ps1** : Analyse de l'espace disque avec alertes
- **optimisation.ps1** : Optimisations système automatiques
- **planificateur.ps1** : Interface pour Task Scheduler
- **sauvegarde.ps1** : Système de sauvegarde incrémentale

### 👤 Jimmy - Surveillance et réseau
- **analyse_log.ps1** : Analyseur de logs Windows (Event Viewer, IIS, etc.)
- **rapport_sys.ps1** : Rapport système complet (CPU, RAM, disque, réseau)
- **synch_repertoire.ps1** : Synchronisation avec Robocopy avancé
- **test_reseaux.ps1** : Suite d'outils de diagnostic réseau

## 🔧 Fonctionnalités

- ✅ **Scripts interactifs** avec menus et confirmations
- ✅ **Logging détaillé** avec horodatage
- ✅ **Gestion d'erreurs** robuste
- ✅ **Paramètres configurables** via fichiers de configuration
- ✅ **Compatibilité** Windows 10/11 et Server
- ✅ **Documentation** intégrée (Get-Help)
- ✅ **Mini-jeux** en console pour démonstrations et tests (Snake, etc.)

## 💡 Exemples d'utilisation

```powershell
# Nettoyage rapide du système
.\sameer\cleanFiles.ps1 -Mode Quick

# Rapport système complet
.\script_jimmy\rapport_sys.ps1 -Export HTML

# Sauvegarde avec compression
.\script_alex\sauvegarde.ps1 -Source "C:\Data" -Destination "D:\Backup" -Compress
```

## 🤝 Contribution

Les contributions sont les bienvenues ! Consultez [CONTRIBUTING.md](CONTRIBUTING.md) pour les guidelines.

## 👥 Contributeurs

- **Sameer** : Outils système généraux, gestion de paquets et génération de templates
- **Alex** : Scripts de maintenance, planification, sauvegarde et création du menu principal
- **Jimmy** : Scripts de surveillance, journalisation et tests réseau

## 📄 Licence

Ce projet est sous licence MIT — voir le fichier [LICENSE](LICENSE) pour plus d'informations.

## 🆘 Support

Pour signaler un bug ou demander une fonctionnalité, ouvrez une [issue](https://github.com/JimmyRamsamynaick/Projet-PowerShell-Windows/issues).

---

**⚠️ Avertissement :** Ces scripts peuvent modifier votre système. Testez-les d'abord dans un environnement de développement.