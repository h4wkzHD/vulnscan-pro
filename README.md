# VulnScan Pro 🔍

Outil d'audit de sécurité automatisé — scan de vulnérabilités et génération de rapports PDF professionnels.

> **by hawkz** — v1.0

---

## ⚡ Installation Windows

### 1. Télécharger et installer

👉 Télécharger **`VulnScanPro_Setup_v1_0.exe`** depuis la section [Releases](../../releases) de ce dépôt et lancer l'installateur.

> L'installateur s'occupe de tout — **Nmap est installé automatiquement**, aucune configuration supplémentaire requise.

### 2. Ouvrir un PowerShell en administrateur

Appuyer sur `Windows + X` puis cliquer sur **"Terminal (administrateur)"** ou **"Windows PowerShell (administrateur)"**.

### 3. Se rendre dans le dossier Downloads

Copier-coller cette commande — elle s'adapte automatiquement à ton nom d'utilisateur :

```powershell
cd "$env:USERPROFILE\Downloads"
```

### 4. Lancer un scan

```powershell
vulnscan-pro 192.168.1.1
```

> 💡 Remplacer `192.168.1.1` par l'IP ou l'URL cible.

**Autres exemples :**

```powershell
# Scanner un site web avec nom d'entreprise et auditeur
vulnscan-pro https://exemple.com -c "Acme Corp" -a "Jean Dupont"

# Scan rapide (sans CVE ni scripts NSE)
vulnscan-pro 192.168.1.1 --no-cve --no-vuln

# Scan avec plage de ports complète
vulnscan-pro 10.0.0.1 --ports 1-65535
```

### 5. Récupérer le rapport

Une fois le scan terminé, le rapport PDF est généré automatiquement dans :

```
C:\Users\<VotreNom>\Downloads\vulnscan_reports\
```

Le dossier s'ouvre automatiquement à la fin du scan avec le rapport sélectionné. 📂

---

## 🐧 Installation Linux / Kali (depuis le code source)

```bash
git clone https://github.com/h4wkzHD/vulnscan-pro.git
cd vulnscan-pro
sudo bash install.sh
```

La commande `vulnscan` est ensuite disponible partout sur le système.

---

## Ce que ça fait

VulnScan Pro analyse une IP ou une URL et génère un rapport PDF complet style pentest incluant :

- **Scan réseau Nmap** — ports ouverts, services, versions, OS fingerprinting
- **Scripts NSE** — Heartbleed, EternalBlue, Shellshock, FTP backdoor, SMTP relay...
- **Analyse HTTP** — headers de sécurité (CSP, HSTS, X-Frame-Options...), CORS, cookies, technologies
- **Analyse SSL/TLS** — certificat (expiration, auto-signé), protocoles obsolètes, cipher suites faibles
- **Scan DNS** — enregistrements, zone transfer, SPF/DKIM/DMARC, sous-domaines courants
- **WHOIS** — registrar, dates, expiration domaine, emails exposés
- **CVE Lookup** — croisement des versions détectées avec NVD + base locale intégrée
- **Score de risque global** — pondération CVSS (0-100)
- **Rapport PDF professionnel** — page de garde, résumé exécutif, findings détaillés, recommandations

---

## Toutes les options

| Option | Raccourci | Description | Défaut |
|--------|-----------|-------------|--------|
| `--company` | `-c` | Nom de l'entreprise dans le rapport | `Confidentiel` |
| `--auditor` | `-a` | Nom de l'auditeur | `VulnScan Pro` |
| `--ports` | `-p` | Plage de ports à scanner | `1-10000` |
| `--output` | `-o` | Dossier de sortie des rapports | `~/Downloads/vulnscan_reports` |
| `--timeout` | `-t` | Timeout en secondes | `10` |
| `--no-cve` | — | Désactiver la lookup CVE (plus rapide) | — |
| `--no-vuln` | — | Désactiver les scripts NSE vulnérabilités | — |
| `--json` | — | Exporter aussi en JSON | — |

---

## Le rapport PDF

Le rapport généré est de qualité professionnelle (dark mode, style cabinet de pentest) :

1. **Page de garde** — cible, entreprise, auditeur, score de risque, répartition par sévérité
2. **Table des matières**
3. **Résumé exécutif** — contexte, résultat global, tableau synthèse par module
4. **Détail des vulnérabilités** — regroupées par sévérité (CRITICAL → INFO), description, recommandation, CVEs
5. **Analyse réseau & ports** — tableau de tous les ports ouverts avec niveau de risque
6. **Analyse HTTP** — technologies détectées, headers de sécurité
7. **Analyse SSL/TLS** — infos certificat, configuration TLS
8. **Analyse DNS & WHOIS** — enregistrements, sous-domaines découverts
9. **CVEs identifiées** — tableau trié par score CVSS
10. **Recommandations prioritaires** — top 20 actions immédiates + bonnes pratiques
11. **Méthodologie** — phases, outils utilisés

---

## Structure du projet

```
vulnscan/
├── main.py                  # Point d'entrée principal
├── requirements.txt         # Dépendances Python
├── install.sh               # Script d'installation Debian/Ubuntu/Kali
├── build.sh                 # Script de build exécutable standalone
├── README.md                # Ce fichier
└── modules/
    ├── network_scanner.py   # Nmap — services, OS, versions
    ├── port_scanner.py      # Scan de ports TCP + banner grabbing
    ├── http_scanner.py      # Headers HTTP, CORS, cookies, technologies
    ├── ssl_scanner.py       # Certificat SSL/TLS, protocoles, ciphers
    ├── dns_scanner.py       # DNS, zone transfer, SPF/DKIM/DMARC
    ├── whois_scanner.py     # WHOIS, résolution DNS, reverse DNS
    ├── cve_lookup.py        # Recherche CVE (NVD API + base locale)
    ├── vuln_scanner.py      # Scripts NSE Nmap de vulnérabilités
    └── report_generator.py  # Génération du rapport PDF
```

---

## ⚠️ Avertissement légal

> **VulnScan Pro doit être utilisé exclusivement sur des systèmes dont vous êtes propriétaire ou pour lesquels vous avez une autorisation écrite explicite.**
>
> L'utilisation non autorisée de cet outil sur des systèmes tiers est illégale dans la plupart des pays et peut entraîner des poursuites pénales.
>
> Les auteurs déclinent toute responsabilité en cas d'utilisation malveillante ou illégale de cet outil.

---

*VulnScan Pro v1.0 — by hawkz — Usage légal uniquement*
