# Changelog — VulnScan Pro

Toutes les modifications notables sont documentées ici.
Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/).

---

## [1.0.0] — 2025-05-04

### Ajouté
- Scan réseau complet via Nmap (services, versions, OS fingerprinting)
- Scan de ports TCP parallèle avec banner grabbing (200 threads)
- Analyse HTTP : 9 headers de sécurité, CORS, cookies, technologies
- Analyse SSL/TLS : certificat, protocoles obsolètes, cipher suites
- Scan DNS : tous enregistrements, zone transfer, SPF/DKIM/DMARC, sous-domaines
- Informations WHOIS (registrar, dates, expiration)
- Scripts NSE de vulnérabilités (Heartbleed, EternalBlue, Shellshock...)
- Lookup CVE via NVD API v2 + base locale intégrée
- Score de risque global pondéré (0-100)
- Rapport PDF professionnel (page de garde, résumé exécutif, findings détaillés)
- Export JSON optionnel
- Interface terminal colorée (Rich)
- Script d'installation Debian/Ubuntu (`install.sh`)
- Script de build exécutable standalone (`build.sh`)
