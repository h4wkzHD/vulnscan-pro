"""
Module: network_scanner.py
Scan réseau via python-nmap — détection de services, versions, OS fingerprinting
"""

import nmap
import re
from typing import Optional


class NetworkScanner:
    def __init__(self, target: str, timeout: int = 10):
        self.target = self._clean_target(target)
        self.timeout = timeout
        self.nm = nmap.PortScanner()

    def _clean_target(self, target: str) -> str:
        target = target.strip()
        for prefix in ["https://", "http://"]:
            if target.startswith(prefix):
                target = target[len(prefix):]
        target = target.split("/")[0].split("?")[0]
        return target

    def scan(self) -> dict:
        findings = []
        open_ports = []
        os_info = {}
        raw_output = ""

        try:
            # Scan de service et version
            self.nm.scan(
                hosts=self.target,
                arguments=f"-sV -sC -O --osscan-guess -T4 --host-timeout {self.timeout*2}s"
            )
        except Exception as e:
            # Fallback sans -O (pas root)
            try:
                self.nm.scan(
                    hosts=self.target,
                    arguments=f"-sV -sC -T4 --host-timeout {self.timeout*2}s"
                )
            except Exception as e2:
                return {"error": str(e2), "findings": [], "open_ports": []}

        for host in self.nm.all_hosts():
            host_info = self.nm[host]

            # OS fingerprint
            if "osmatch" in host_info and host_info["osmatch"]:
                best_os = host_info["osmatch"][0]
                os_info = {
                    "name": best_os.get("name", "Inconnu"),
                    "accuracy": best_os.get("accuracy", "0"),
                    "osclass": best_os.get("osclass", [])
                }

            # Parcours des ports
            for proto in host_info.all_protocols():
                ports = host_info[proto].keys()
                for port in sorted(ports):
                    port_data = host_info[proto][port]
                    state = port_data.get("state", "")

                    if state != "open":
                        continue

                    service = port_data.get("name", "")
                    version = port_data.get("version", "")
                    product = port_data.get("product", "")
                    extra = port_data.get("extrainfo", "")
                    script_output = port_data.get("script", {})

                    full_version = " ".join(filter(None, [product, version, extra])).strip()

                    port_entry = {
                        "port": port,
                        "protocol": proto,
                        "state": state,
                        "service": service,
                        "product": product,
                        "version": version,
                        "full_version": full_version,
                        "scripts": script_output
                    }
                    open_ports.append(port_entry)

                    # Findings spécifiques
                    findings += self._analyze_port(port, service, full_version, script_output)

        return {
            "findings": findings,
            "open_ports": open_ports,
            "os_info": os_info,
            "target": self.target,
            "hosts_up": len(self.nm.all_hosts())
        }

    def _analyze_port(self, port: int, service: str, version: str, scripts: dict) -> list:
        findings = []

        # Ports dangereux exposés
        dangerous_ports = {
            21: ("FTP exposé", "HIGH", "FTP en clair transmet identifiants sans chiffrement."),
            23: ("Telnet exposé", "CRITICAL", "Telnet en clair — remplacer par SSH immédiatement."),
            25: ("SMTP exposé", "MEDIUM", "Port SMTP accessible publiquement, risque de spam relay."),
            53: ("DNS exposé", "LOW", "Port DNS ouvert, vérifier si zone transfer est désactivé."),
            69: ("TFTP exposé", "HIGH", "TFTP sans authentification."),
            110: ("POP3 non chiffré", "MEDIUM", "POP3 en clair détecté."),
            111: ("RPC portmapper exposé", "HIGH", "RPC portmapper peut révéler des services internes."),
            135: ("RPC/MSRPC exposé", "HIGH", "Port MSRPC exposé, risque d'exploitation."),
            137: ("NetBIOS exposé", "HIGH", "NetBIOS exposé publiquement."),
            139: ("SMB (NetBIOS) exposé", "CRITICAL", "SMB exposé — risque EternalBlue/WannaCry."),
            389: ("LDAP non chiffré exposé", "HIGH", "LDAP en clair peut exposer l'annuaire."),
            443: ("HTTPS", "INFO", "Port HTTPS standard."),
            445: ("SMB exposé", "CRITICAL", "Port SMB 445 exposé publiquement — risque critique."),
            512: ("rexec exposé", "CRITICAL", "Service rexec très dangereux."),
            513: ("rlogin exposé", "HIGH", "Service rlogin sans chiffrement."),
            514: ("rsh exposé", "CRITICAL", "rsh sans authentification forte."),
            1099: ("Java RMI exposé", "HIGH", "Java RMI peut permettre l'exécution de code."),
            1433: ("MSSQL exposé", "HIGH", "Base de données MSSQL accessible depuis l'extérieur."),
            1521: ("Oracle DB exposé", "HIGH", "Base Oracle accessible depuis l'extérieur."),
            2049: ("NFS exposé", "HIGH", "NFS exposé peut permettre l'accès aux fichiers."),
            3306: ("MySQL exposé", "HIGH", "Base MySQL accessible depuis l'extérieur."),
            3389: ("RDP exposé", "HIGH", "Bureau à distance RDP exposé, risque de brute-force."),
            4444: ("Metasploit/Backdoor potentiel", "CRITICAL", "Port 4444 souvent utilisé par malwares."),
            5432: ("PostgreSQL exposé", "HIGH", "Base PostgreSQL accessible depuis l'extérieur."),
            5900: ("VNC exposé", "HIGH", "VNC exposé, risque d'accès non autorisé."),
            5985: ("WinRM exposé", "HIGH", "Windows Remote Management exposé."),
            6379: ("Redis exposé sans auth", "CRITICAL", "Redis souvent configuré sans authentification."),
            7070: ("AJP/autre service exposé", "MEDIUM", "Vérifier le service sur ce port."),
            8080: ("HTTP alternatif exposé", "LOW", "Port HTTP alternatif ouvert."),
            8443: ("HTTPS alternatif exposé", "LOW", "Port HTTPS alternatif ouvert."),
            9200: ("Elasticsearch exposé", "CRITICAL", "Elasticsearch souvent sans auth par défaut."),
            27017: ("MongoDB exposé", "CRITICAL", "MongoDB souvent sans authentification."),
        }

        if port in dangerous_ports:
            title, sev, desc = dangerous_ports[port]
            if port not in [80, 443, 8080, 8443] or sev != "INFO":
                findings.append({
                    "title": title,
                    "severity": sev,
                    "description": desc,
                    "port": port,
                    "service": service,
                    "version": version,
                    "recommendation": f"Fermer le port {port} si non nécessaire, ou restreindre l'accès via firewall."
                })

        # Analyse des scripts NSE
        for script_name, script_output in scripts.items():
            if "VULNERABLE" in str(script_output).upper() or "CVE-" in str(script_output):
                cves = re.findall(r"CVE-\d{4}-\d+", str(script_output))
                findings.append({
                    "title": f"Vulnérabilité détectée par NSE: {script_name}",
                    "severity": "HIGH",
                    "description": str(script_output)[:500],
                    "port": port,
                    "service": service,
                    "cves": cves,
                    "recommendation": "Appliquer les correctifs de sécurité disponibles."
                })

        return findings
