# VulnScan Pro 🔍

Outil d'audit de sécurité automatisé — scan de vulnérabilités et génération de rapports PDF professionnels.

---

## Ce que ça fait

VulnScan Pro analyse une IP ou une URL et génère un rapport PDF complet style pentest incluant :

- **Scan réseau Nmap** — ports ouverts, services, versions, OS fingerprinting
- **Scripts NSE** — Heartbleed, EternalBlue, Shellshock, FTP backdoor, SMTP relay...
- **Analyse HTTP** — headers de sécurité (CSP, HSTS, X-Frame-Options...), CORS, cookies, technologies détectées
- **Analyse SSL/TLS** — certificat (expiration, auto-signé), protocoles obsolètes, cipher suites faibles
- **Scan DNS** — tous les enregistrements, zone transfer, SPF/DKIM/DMARC, sous-domaines courants
- **WHOIS** — registrar, dates, expiration domaine, emails exposés
- **CVE Lookup** — croisement des versions détectées avec NVD + base locale intégrée
- **Score de risque global** — pondération CVSS (0-100)
- **Rapport PDF professionnel** — page de garde, résumé exécutif, détail des findings, recommandations priorisées

---

## Prérequis

- Debian / Ubuntu (Kali Linux recommandé)
- Python 3.8+
- Nmap installé
- Accès root (pour les scans Nmap complets)

---

## Installation rapide (Debian/Ubuntu/Kali)

**Copier-coller ces commandes en une fois :**

```bash
# 1. Cloner / copier le projet dans un dossier
cd ~
# (si tu as le zip) unzip vulnscan.zip && cd vulnscan
# (si tu clones git) git clone https://... && cd vulnscan

# 2. Lancer le script d'installation
sudo bash install.sh
```

C'est tout. La commande `vulnscan` est ensuite disponible partout.

---

## Installation manuelle (si tu ne veux pas utiliser install.sh)

```bash
# Dépendances système
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv nmap dnsutils whois

# Environnement virtuel Python
python3 -m venv venv
source venv/bin/activate

# Dépendances Python
pip install -r requirements.txt

# Lancer directement
sudo python3 main.py <cible>
```

---

## Utilisation

### Syntaxe

```bash
vulnscan <ip_ou_url> [options]
```

### Exemples concrets

```bash
# Scan basique d'une IP
sudo vulnscan 192.168.1.1

# Scan d'un site web avec infos entreprise pour le rapport
sudo vulnscan https://exemple.com -c "Acme Corp" -a "Jean Dupont"

# Scan avec plage de ports complète
sudo vulnscan 10.0.0.1 --ports 1-65535

# Scan rapide (sans CVE ni scripts NSE)
sudo vulnscan 192.168.1.50 --no-cve --no-vuln

# Exporter aussi en JSON
sudo vulnscan exemple.com --json -o ./rapports/

# Scan avec timeout personnalisé
sudo vulnscan 192.168.1.1 --timeout 15
```

### Toutes les options

| Option | Raccourci | Description | Défaut |
|--------|-----------|-------------|--------|
| `--company` | `-c` | Nom de l'entreprise dans le rapport | `Confidentiel` |
| `--auditor` | `-a` | Nom de l'auditeur | `VulnScan Pro` |
| `--ports` | `-p` | Plage de ports à scanner | `1-10000` |
| `--output` | `-o` | Dossier de sortie des rapports | `./output` |
| `--timeout` | `-t` | Timeout en secondes | `10` |
| `--no-cve` | — | Désactiver la lookup CVE | — |
| `--no-vuln` | — | Désactiver les scripts NSE | — |
| `--json` | — | Exporter aussi en JSON | — |

---

## Générer un exécutable standalone (.exe / binaire Linux)

Pour distribuer VulnScan Pro à d'autres personnes sans qu'elles aient besoin d'installer Python :

```bash
# Depuis le dossier du projet
bash build.sh
```

Le binaire est généré dans `dist/vulnscan`. Il suffit de le copier sur n'importe quelle machine Linux (Nmap doit quand même être installé sur la machine cible).

**Pour un .exe Windows :**
```bash
# Nécessite Wine installé sur Debian
sudo apt-get install wine wine64
bash build.sh --windows
```

---

## Structure du projet

```
vulnscan/
├── main.py                  # Point d'entrée principal
├── requirements.txt         # Dépendances Python
├── install.sh               # Script d'installation Debian
├── build.sh                 # Script de build exécutable
├── README.md                # Ce fichier
├── output/                  # Rapports générés (PDF, JSON)
└── modules/
    ├── __init__.py
    ├── network_scanner.py   # Nmap — services, OS, versions
    ├── port_scanner.py      # Scan de ports TCP rapide + banner grabbing
    ├── http_scanner.py      # Headers HTTP, CORS, cookies, technologies
    ├── ssl_scanner.py       # Certificat SSL/TLS, protocoles, ciphers
    ├── dns_scanner.py       # DNS, zone transfer, SPF/DKIM/DMARC, sous-domaines
    ├── whois_scanner.py     # WHOIS, résolution DNS, reverse DNS
    ├── cve_lookup.py        # Recherche CVE (NVD API + base locale)
    ├── vuln_scanner.py      # Scripts NSE Nmap de vulnérabilités
    └── report_generator.py  # Génération du rapport PDF professionnel
```

---

## Modules de scan détaillés

### 🌐 WHOIS
- Registrar, dates de création/expiration
- IP résolue + reverse DNS
- Emails exposés dans WHOIS
- Alerte si le domaine expire bientôt

### 🔎 DNS
- Tous les enregistrements (A, AAAA, MX, NS, TXT, CNAME, SOA)
- Test de zone transfer (AXFR) sur chaque serveur NS
- Vérification SPF (présence, syntaxe, +all dangereux)
- Vérification DMARC (p=none / quarantine / reject)
- Vérification DKIM (sélecteurs courants)
- Brute-force de 60+ sous-domaines courants
- Détection DNS wildcard

### 🔌 Ports
- Scan TCP parallèle (200 threads)
- Banner grabbing sur chaque port ouvert
- Détection de 80+ services connus
- Alerte sur ports dangereux (Redis sans auth, MongoDB, Docker API...)

### 🗺 Réseau (Nmap)
- Détection précise des versions de services (`-sV`)
- OS fingerprinting (`-O`)
- Scripts NSE par défaut (`-sC`)
- Analyse des résultats de scripts (CVE détectées)

### 💥 Vulnérabilités NSE
- Suite complète `vuln`
- Heartbleed (CVE-2014-0160)
- EternalBlue MS17-010
- Shellshock (CVE-2014-6271)
- SSL POODLE, DROWN
- FTP backdoor vsftpd 2.3.4
- SMTP open relay
- RDP MS12-020
- Injection SQL HTTP
- XSS stocké/réfléchi

### 🌍 HTTP
- Présence/absence de 9 headers de sécurité (CSP, HSTS, X-Frame-Options...)
- Analyse HSTS (max-age, includeSubDomains)
- Analyse CORS (wildcard, credentials)
- Attributs des cookies (Secure, HttpOnly, SameSite)
- Détection de 15+ technologies (WordPress, Django, Laravel, React...)
- Exposition version serveur (Server, X-Powered-By)
- Détection de credentials, clés API, stack traces dans le HTML
- Vérification redirection HTTP→HTTPS

### 🔒 SSL/TLS
- Protocole utilisé (TLSv1.3, TLSv1.2, TLSv1.1...)
- Cipher suite (détection RC4, DES, NULL, EXPORT...)
- Expiration du certificat (jours restants)
- Certificat auto-signé
- Test actif des protocoles obsolètes TLSv1 / TLSv1.1
- Informations complètes du certificat (CN, SAN, émetteur...)

### 🛡 CVE
- Requête sur l'API NVD v2 (NIST)
- Base locale intégrée pour Apache, Nginx, OpenSSH, MySQL, PHP, Redis...
- Comparaison des versions détectées
- Score CVSS, sévérité, lien direct NVD

---

## Le rapport PDF

Le rapport généré est de qualité professionnelle :

1. **Page de garde** — cible, entreprise, auditeur, date, score de risque, répartition par sévérité
2. **Table des matières**
3. **Résumé exécutif** — contexte, périmètre, résultat global, tableau de synthèse par module
4. **Détail des vulnérabilités** — regroupées par sévérité (CRITICAL → INFO), avec description, recommandation, CVE associées
5. **Analyse réseau & ports** — tableau de tous les ports ouverts avec niveau de risque
6. **Analyse HTTP** — technologies, headers de sécurité
7. **Analyse SSL/TLS** — infos certificat, configuration TLS
8. **Analyse DNS** — WHOIS, enregistrements, sous-domaines
9. **CVEs identifiées** — tableau trié par score CVSS
10. **Recommandations prioritaires** — top 20 actions immédiates + bonnes pratiques
11. **Méthodologie** — phases, outils utilisés

---

## Avertissement légal

> **VulnScan Pro doit être utilisé exclusivement sur des systèmes dont vous êtes propriétaire ou pour lesquels vous avez une autorisation écrite explicite.**
>
> L'utilisation non autorisée de cet outil sur des systèmes tiers est illégale dans la plupart des pays et peut entraîner des poursuites pénales.
>
> Les auteurs déclinent toute responsabilité en cas d'utilisation malveillante ou illégale de cet outil.

---

## Dépendances

| Librairie | Version | Rôle |
|-----------|---------|------|
| python-nmap | 0.7.1 | Interface Python → Nmap |
| requests | 2.31.0 | Requêtes HTTP |
| dnspython | 2.4.2 | Requêtes DNS |
| python-whois | 0.8.0 | Lookups WHOIS |
| reportlab | 4.0.9 | Génération PDF |
| rich | 13.7.0 | Interface terminal |
| urllib3 | 2.1.0 | Client HTTP bas niveau |

---

*VulnScan Pro v1.0 — Usage légal uniquement*
