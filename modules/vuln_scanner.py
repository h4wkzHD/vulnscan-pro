"""
Module: vuln_scanner.py
Scripts NSE de vulnérabilités Nmap
"""

import nmap
import re
from typing import Optional


class VulnScanner:
    def __init__(self, target: str, timeout: int = 10):
        self.target = self._clean_target(target)
        self.timeout = timeout
        self.nm = nmap.PortScanner()

    def _clean_target(self, target: str) -> str:
        target = target.strip()
        for prefix in ["https://", "http://"]:
            if target.startswith(prefix):
                target = target[len(prefix):]
        return target.split("/")[0].split("?")[0]

    def scan(self) -> dict:
        findings = []
        vuln_details = []

        vuln_scripts = [
            "vuln",           # Suite complète de scripts vulnérabilités
            "ftp-vsftpd-backdoor",
            "ftp-anon",
            "smtp-open-relay",
            "smb-vuln-ms17-010",  # EternalBlue
            "smb-vuln-ms08-067",
            "smb-vuln-cve2009-3103",
            "rdp-vuln-ms12-020",
            "ssl-heartbleed",     # Heartbleed
            "ssl-poodle",
            "ssl-drown",
            "http-shellshock",    # Shellshock
            "http-sql-injection",
            "http-csrf",
            "http-dombased-xss",
            "http-stored-xss",
        ]

        script_arg = ",".join(vuln_scripts)

        try:
            self.nm.scan(
                hosts=self.target,
                arguments=f"--script={script_arg} -T4 --host-timeout {self.timeout * 3}s -p 21,22,23,25,53,80,110,139,443,445,3306,3389,5432"
            )
        except Exception as e:
            return {"findings": [], "error": str(e), "vuln_details": []}

        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    port_data = self.nm[host][proto][port]
                    scripts = port_data.get("script", {})

                    for script_name, output in scripts.items():
                        parsed = self._parse_script_output(script_name, output, port)
                        if parsed:
                            vuln_details.append(parsed)
                            findings.append({
                                "title": parsed["title"],
                                "severity": parsed["severity"],
                                "description": parsed["description"],
                                "port": port,
                                "script": script_name,
                                "cves": parsed.get("cves", []),
                                "recommendation": parsed.get("recommendation", "Appliquer les correctifs disponibles.")
                            })

        return {
            "findings": findings,
            "vuln_details": vuln_details,
            "scripts_run": vuln_scripts
        }

    def _parse_script_output(self, script_name: str, output: str, port: int) -> Optional[dict]:
        output_upper = output.upper()
        output_str = str(output)

        # Ignorer les outputs "non vulnérable"
        if any(phrase in output_upper for phrase in [
            "NOT VULNERABLE", "NOT AFFECTED", "ERROR:", "FAILED:",
            "TIMEOUT", "NO RESPONSE"
        ]):
            return None

        # Ne retourner que si vraiment vulnérable
        is_vulnerable = any(phrase in output_upper for phrase in [
            "VULNERABLE", "STATE: VULNERABLE", "LIKELY VULNERABLE",
            "CVE-", "EXPLOIT", "BACKDOOR", "CRITICAL", "RISK:"
        ])

        if not is_vulnerable:
            return None

        # Extraire CVEs
        cves = re.findall(r"CVE-\d{4}-\d+", output_str)

        # Mapping scripts → infos
        script_info = {
            "ssl-heartbleed": {
                "title": "Heartbleed (CVE-2014-0160) — Fuite mémoire OpenSSL",
                "severity": "CRITICAL",
                "description": "Le serveur est vulnérable à Heartbleed. Un attaquant peut lire 64KB de mémoire du serveur, exposant clés privées, mots de passe et sessions.",
                "recommendation": "Mettre à jour OpenSSL vers 1.0.1g ou supérieur, révoquer et renouveler tous les certificats."
            },
            "smb-vuln-ms17-010": {
                "title": "EternalBlue (MS17-010) — RCE via SMB",
                "severity": "CRITICAL",
                "description": "Le serveur est vulnérable à EternalBlue, exploité par WannaCry et NotPetya. Permet une exécution de code à distance sans authentification.",
                "recommendation": "Appliquer le patch MS17-010, désactiver SMBv1, bloquer le port 445 sur Internet."
            },
            "smb-vuln-ms08-067": {
                "title": "MS08-067 — RCE via SMB (Conficker)",
                "severity": "CRITICAL",
                "description": "Vulnérabilité critique dans le service Server de Windows, exploitée par le ver Conficker.",
                "recommendation": "Appliquer le patch MS08-067 immédiatement."
            },
            "ftp-vsftpd-backdoor": {
                "title": "Backdoor vsftpd 2.3.4",
                "severity": "CRITICAL",
                "description": "Version vsftpd 2.3.4 avec backdoor intégrée. Un attaquant peut obtenir un shell root sur le port 6200.",
                "recommendation": "Mettre à jour vsftpd immédiatement vers une version sans backdoor."
            },
            "ftp-anon": {
                "title": "FTP anonyme autorisé",
                "severity": "HIGH",
                "description": "Le serveur FTP accepte les connexions anonymes sans authentification.",
                "recommendation": "Désactiver l'accès FTP anonyme dans la configuration vsftpd/proftpd."
            },
            "smtp-open-relay": {
                "title": "SMTP Open Relay",
                "severity": "HIGH",
                "description": "Le serveur SMTP relaie les emails pour n'importe quel domaine — risque d'utilisation pour le spam.",
                "recommendation": "Configurer le serveur SMTP pour refuser le relayage non autorisé."
            },
            "ssl-poodle": {
                "title": "POODLE (CVE-2014-3566) — SSLv3 vulnérable",
                "severity": "HIGH",
                "description": "Le serveur supporte SSLv3 et est vulnérable à l'attaque POODLE permettant le déchiffrement des sessions.",
                "recommendation": "Désactiver SSLv3 complètement sur le serveur."
            },
            "ssl-drown": {
                "title": "DROWN Attack — SSLv2 vulnérable",
                "severity": "CRITICAL",
                "description": "Le serveur supporte SSLv2 et est vulnérable à DROWN, permettant de déchiffrer les connexions TLS.",
                "recommendation": "Désactiver SSLv2 sur tous les services et régénérer les clés privées."
            },
            "http-shellshock": {
                "title": "Shellshock (CVE-2014-6271) — RCE via Bash",
                "severity": "CRITICAL",
                "description": "L'application web est vulnérable à Shellshock. Un attaquant peut exécuter des commandes arbitraires via des en-têtes HTTP.",
                "recommendation": "Mettre à jour bash vers une version corrigée (4.3-027 ou supérieur)."
            },
            "http-sql-injection": {
                "title": "Injection SQL détectée",
                "severity": "CRITICAL",
                "description": "Une injection SQL a été détectée dans l'application web, permettant potentiellement l'accès à la base de données.",
                "recommendation": "Utiliser des requêtes préparées/paramétrées, valider toutes les entrées utilisateur."
            },
            "rdp-vuln-ms12-020": {
                "title": "MS12-020 — Vulnérabilité RDP (DoS/RCE)",
                "severity": "CRITICAL",
                "description": "Le service RDP est vulnérable à MS12-020, pouvant causer un déni de service ou une exécution de code.",
                "recommendation": "Appliquer le patch MS12-020 et envisager de désactiver RDP si non nécessaire."
            },
        }

        if script_name in script_info:
            info = script_info[script_name].copy()
            info["cves"] = cves or []
            info["raw_output"] = output_str[:300]
            return info

        # Script générique
        return {
            "title": f"Vulnérabilité détectée: {script_name}",
            "severity": "HIGH",
            "description": output_str[:400],
            "cves": cves,
            "raw_output": output_str[:300],
            "recommendation": "Analyser la sortie du script et appliquer les correctifs appropriés."
        }
