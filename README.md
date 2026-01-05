# Satellite-Telemetry-Analyzer


# 🛰️ Satellite Hijacking Lab

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)]()

Un laboratoire éducatif pour comprendre, analyser et interagir avec les protocoles de télémesure satellitaire, avec un focus sur la sécurité et les vulnérabilités de hijacking.

## 📖 Description

Ce projet est né d'un cours sur les systèmes satellitaires et explore la partie "hijacking" (détournement) souvent oubliée. Il comprend :

- **Analyse de fichiers XTCE** (XML Telemetry and Command Exchange)
- **Décodage de paquets CCSDS** (standard spatial)
- **Communication avec des simulateurs de satellites**
- **Techniques de sécurité et vulnérabilités** des systèmes spatiaux
- **Composant DIY** utilisant des SDR (Software Defined Radio)

Le projet a permis de résoudre un challenge pratique : se connecter à un simulateur de satellite, comprendre sa télémétrie, et extraire un flag de sécurité.

## 🎯 Fonctionnalités

- ✅ **Décodage XTCE** : Analyse des fichiers de définition de télémétrie
- ✅ **Paquets CCSDS** : Décodage des en-têtes et données satellitaires
- ✅ **Client TCP/IP** : Communication avec des simulateurs de satellites
- ✅ **Décodage 7-bit** : Pour les paquets de type "FLAG" (selon spécification XTCE)
- ✅ **Recherche de flags** : Automatisation d'interactions pour CTF
- ✅ **Analyse hexadécimale** : Outils de diagnostic des flux binaires

## 🚀 Installation

### Prérequis
- Python 3.8 ou supérieur
- pip (gestionnaire de paquets Python)

### Installation
```bash
# Cloner le dépôt
git clone https://github.com/tonusername/satellite-hijacking-lab.git
cd satellite-hijacking-lab

# Installer les dépendances
pip install -r requirements.txt

# Dépendances minimales
pip install socket struct re

```

