"""
Module: cve_lookup.py
Recherche de CVEs via la base NVD (National Vulnerability Database)
"""

import requests
import time
from typing import List, Optional


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Base de données locale de CVEs importantes pour services courants
# Utilisée en fallback si NVD n'est pas accessible
LOCAL_CVE_DB = {
    "openssh": [
        {"id": "CVE-2023-38408", "severity": "CRITICAL", "score": 9.8,
         "description": "Exécution de code à distance dans OpenSSH via ssh-agent forwarding.",
         "versions_affected": ["< 9.3p2"]},
        {"id": "CVE-2023-51385", "severity": "MEDIUM", "score": 6.5,
         "description": "Injection de commandes OS dans OpenSSH via noms d'hôtes avec espaces.",
         "versions_affected": ["< 9.6"]},
    ],
    "apache": [
        {"id": "CVE-2021-41773", "severity": "CRITICAL", "score": 9.8,
         "description": "Path traversal et RCE dans Apache HTTP Server 2.4.49.",
         "versions_affected": ["2.4.49"]},
        {"id": "CVE-2021-42013", "severity": "CRITICAL", "score": 9.8,
         "description": "Path traversal dans Apache 2.4.49 et 2.4.50 (bypass du fix CVE-2021-41773).",
         "versions_affected": ["2.4.49", "2.4.50"]},
        {"id": "CVE-2022-31813", "severity": "HIGH", "score": 9.1,
         "description": "Contournement de contrôle d'accès dans Apache mod_proxy.",
         "versions_affected": ["< 2.4.55"]},
    ],
    "nginx": [
        {"id": "CVE-2021-23017", "severity": "HIGH", "score": 7.7,
         "description": "Off-by-one dans le résolveur DNS de nginx.",
         "versions_affected": ["< 1.21.0"]},
        {"id": "CVE-2022-41741", "severity": "HIGH", "score": 7.8,
         "description": "Corruption mémoire dans le module MP4 de nginx.",
         "versions_affected": ["< 1.23.2"]},
    ],
    "mysql": [
        {"id": "CVE-2023-21912", "severity": "HIGH", "score": 7.5,
         "description": "Vulnérabilité dans MySQL Server permettant un déni de service.",
         "versions_affected": ["<= 5.7.41", "<= 8.0.32"]},
    ],
    "php": [
        {"id": "CVE-2023-3823", "severity": "HIGH", "score": 7.5,
         "description": "Vulnérabilité XML External Entity dans PHP.",
         "versions_affected": ["< 8.0.30", "< 8.1.22", "< 8.2.8"]},
        {"id": "CVE-2024-4577", "severity": "CRITICAL", "score": 9.8,
         "description": "Injection d'argument dans PHP-CGI sur Windows.",
         "versions_affected": ["< 8.1.29", "< 8.2.20", "< 8.3.8"]},
    ],
    "wordpress": [
        {"id": "CVE-2023-2745", "severity": "MEDIUM", "score": 5.4,
         "description": "Path traversal dans WordPress via wp_validate_redirect.",
         "versions_affected": ["< 6.2.1"]},
    ],
    "openssl": [
        {"id": "CVE-2022-0778", "severity": "HIGH", "score": 7.5,
         "description": "Boucle infinie dans BN_mod_sqrt() d'OpenSSL — DoS.",
         "versions_affected": ["< 1.0.2zd", "< 1.1.1n", "< 3.0.2"]},
        {"id": "CVE-2022-3786", "severity": "HIGH", "score": 7.5,
         "description": "Stack overflow dans le traitement des certificats X.509.",
         "versions_affected": ["3.0.0 - 3.0.6"]},
    ],
    "redis": [
        {"id": "CVE-2022-0543", "severity": "CRITICAL", "score": 10.0,
         "description": "Fuite de sandbox Lua dans Redis — RCE possible.",
         "versions_affected": ["< 6.2.6"]},
    ],
    "samba": [
        {"id": "CVE-2017-7494", "severity": "CRITICAL", "score": 9.8,
         "description": "SambaCry — RCE dans Samba via upload de shared library.",
         "versions_affected": ["3.5.0 - 4.6.4"]},
    ],
    "vsftpd": [
        {"id": "CVE-2011-2523", "severity": "CRITICAL", "score": 10.0,
         "description": "Backdoor dans vsftpd 2.3.4 — shell root sur port 6200.",
         "versions_affected": ["2.3.4"]},
    ],
}


class CVELookup:
    def __init__(self, services: List[dict], timeout: int = 10):
        self.services = services
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "VulnScanPro/1.0"})

    def lookup(self) -> dict:
        all_cves = []
        lookup_results = []

        for service in self.services:
            service_name = service.get("name", "").lower()
            version = service.get("version", "")
            port = service.get("port", 0)

            # 1. Essayer NVD API
            nvd_cves = self._query_nvd(service_name, version)

            # 2. Fallback base locale
            local_cves = self._query_local(service_name, version)

            # Dédupliquer
            seen_ids = set()
            merged = []
            for cve in nvd_cves + local_cves:
                cve_id = cve.get("id", "")
                if cve_id not in seen_ids:
                    seen_ids.add(cve_id)
                    merged.append(cve)

            if merged:
                lookup_results.append({
                    "service": service_name,
                    "version": version,
                    "port": port,
                    "cves_found": len(merged),
                    "cves": merged
                })
                all_cves.extend(merged)

            time.sleep(0.2)  # Rate limiting NVD

        return {
            "findings": self._cves_to_findings(all_cves),
            "cves": all_cves,
            "services_analyzed": len(self.services),
            "lookup_results": lookup_results,
            "total_cves": len(all_cves)
        }

    def _query_nvd(self, keyword: str, version: str) -> list:
        """Requête à la NVD API v2."""
        cves = []
        try:
            params = {
                "keywordSearch": f"{keyword} {version}".strip(),
                "resultsPerPage": 10,
                "startIndex": 0
            }

            resp = self.session.get(NVD_API_URL, params=params, timeout=self.timeout)
            if resp.status_code != 200:
                return []

            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")

                # Sévérité (CVSS v3 préféré)
                severity = "UNKNOWN"
                score = 0.0
                metrics = cve_data.get("metrics", {})

                if "cvssMetricV31" in metrics:
                    m = metrics["cvssMetricV31"][0]
                    severity = m.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                    score = m.get("cvssData", {}).get("baseScore", 0.0)
                elif "cvssMetricV30" in metrics:
                    m = metrics["cvssMetricV30"][0]
                    severity = m.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                    score = m.get("cvssData", {}).get("baseScore", 0.0)
                elif "cvssMetricV2" in metrics:
                    m = metrics["cvssMetricV2"][0]
                    score = m.get("cvssData", {}).get("baseScore", 0.0)
                    severity = "HIGH" if score >= 7 else ("MEDIUM" if score >= 4 else "LOW")

                # Description
                descriptions = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

                # Filtrer les CVEs peu pertinentes (score < 4)
                if score < 4.0 and severity not in ["CRITICAL", "HIGH"]:
                    continue

                cves.append({
                    "id": cve_id,
                    "severity": severity,
                    "score": score,
                    "description": desc[:500],
                    "source": "NVD",
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })

        except Exception:
            pass  # NVD injoignable → on utilise la base locale

        return cves[:5]  # Limiter à 5 CVEs par service pour le rapport

    def _query_local(self, service_name: str, version: str) -> list:
        """Recherche dans la base locale."""
        cves = []
        service_lower = service_name.lower()

        for db_key, db_cves in LOCAL_CVE_DB.items():
            if db_key in service_lower or service_lower in db_key:
                for cve in db_cves:
                    # Vérifier si la version est affectée
                    affected = cve.get("versions_affected", [])
                    if not affected or not version:
                        cves.append({**cve, "source": "Local DB",
                                     "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"})
                    else:
                        for v_condition in affected:
                            if self._version_matches(version, v_condition):
                                cves.append({**cve, "source": "Local DB",
                                             "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"})
                                break

        return cves

    def _version_matches(self, version: str, condition: str) -> bool:
        """Vérifie si une version correspond à une condition (simplifiée)."""
        if not version:
            return True  # On ne sait pas, inclure par précaution

        try:
            condition = condition.strip()
            if condition.startswith("< "):
                target = condition[2:].strip()
                return self._version_less_than(version, target)
            elif condition.startswith("<= "):
                target = condition[3:].strip()
                return self._version_less_than(version, target) or version.startswith(target)
            else:
                return version.startswith(condition) or condition in version
        except Exception:
            return False

    def _version_less_than(self, v1: str, v2: str) -> bool:
        """Compare deux versions."""
        try:
            v1_parts = [int(x) for x in v1.split(".")[:3]]
            v2_parts = [int(x) for x in v2.split(".")[:3]]
            # Padding
            while len(v1_parts) < 3:
                v1_parts.append(0)
            while len(v2_parts) < 3:
                v2_parts.append(0)
            return v1_parts < v2_parts
        except Exception:
            return False

    def _cves_to_findings(self, cves: list) -> list:
        findings = []
        for cve in cves:
            severity = cve.get("severity", "MEDIUM")
            if severity == "UNKNOWN":
                severity = "MEDIUM"
            findings.append({
                "title": f"CVE détectée: {cve['id']}",
                "severity": severity,
                "description": cve.get("description", ""),
                "cve_id": cve["id"],
                "score": cve.get("score", 0),
                "url": cve.get("url", ""),
                "recommendation": f"Consulter {cve.get('url', 'https://nvd.nist.gov')} et appliquer les correctifs disponibles."
            })
        return findings
