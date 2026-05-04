"""
Module: port_scanner.py
Scan de ports rapide avec socket (complément à nmap)
"""

import socket
import concurrent.futures
from typing import List, Tuple


COMMON_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP",
    135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 162: "SNMP-trap", 179: "BGP", 194: "IRC",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    515: "LPD", 587: "SMTP-submission", 631: "IPP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "OracleDB", 1723: "PPTP", 2049: "NFS",
    2082: "cPanel", 2083: "cPanelSSL", 2181: "Zookeeper", 2375: "Docker",
    2376: "Docker-TLS", 3000: "Dev-server", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit", 4848: "GlassFish", 5000: "UPnP/Dev", 5432: "PostgreSQL",
    5672: "RabbitMQ", 5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6379: "Redis", 6443: "Kubernetes-API", 7001: "WebLogic", 7077: "Spark",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 8888: "Jupyter", 9000: "PHP-FPM",
    9090: "Prometheus", 9200: "Elasticsearch", 9300: "Elasticsearch-cluster",
    27017: "MongoDB", 27018: "MongoDB-shard", 50000: "SAP", 50070: "Hadoop-HDFS",
}


class PortScanner:
    def __init__(self, target: str, port_range: str = "1-10000", timeout: int = 1):
        self.target = self._resolve_target(target)
        self.port_range = port_range
        self.timeout = timeout

    def _resolve_target(self, target: str) -> str:
        target = target.strip()
        for prefix in ["https://", "http://"]:
            if target.startswith(prefix):
                target = target[len(prefix):]
        target = target.split("/")[0].split("?")[0]
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return target

    def _parse_port_range(self) -> List[int]:
        ports = []
        for part in self.port_range.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports

    def _scan_port(self, port: int) -> Tuple[int, bool, str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            if result == 0:
                banner = self._grab_banner(port)
                return port, True, banner
            return port, False, ""
        except Exception:
            return port, False, ""

    def _grab_banner(self, port: int) -> str:
        """Tente de récupérer le banner du service."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            banner_probes = {
                21: b"",
                22: b"",
                25: b"EHLO test\r\n",
                80: b"HEAD / HTTP/1.0\r\n\r\n",
                110: b"",
                143: b"",
                443: b"",
            }
            probe = banner_probes.get(port, b"\r\n")
            if probe:
                sock.send(probe)
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            return banner[:200]
        except Exception:
            return ""

    def scan(self) -> dict:
        ports_to_scan = self._parse_port_range()
        open_ports = []
        findings = []

        # Scan parallèle
        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
            futures = {executor.submit(self._scan_port, p): p for p in ports_to_scan}
            for future in concurrent.futures.as_completed(futures):
                port, is_open, banner = future.result()
                if is_open:
                    service_name = COMMON_SERVICES.get(port, "unknown")
                    open_ports.append({
                        "port": port,
                        "service": service_name,
                        "banner": banner,
                        "state": "open"
                    })

        open_ports.sort(key=lambda x: x["port"])

        # Analyser les ports suspects
        suspicious = [22, 23, 21, 3389, 5900, 4444, 6379, 9200, 27017, 2375]
        for p in open_ports:
            port_num = p["port"]
            if port_num in suspicious:
                sev = "CRITICAL" if port_num in [23, 4444, 6379, 9200, 27017, 2375] else "HIGH"
                findings.append({
                    "title": f"Port sensible ouvert: {port_num}/{p['service']}",
                    "severity": sev,
                    "description": f"Le port {port_num} ({p['service']}) est ouvert. Banner: {p['banner'][:100] if p['banner'] else 'N/A'}",
                    "port": port_num,
                    "recommendation": f"Vérifier si le service sur le port {port_num} est nécessaire et restreindre l'accès."
                })

        # Vérifier Docker API exposée
        docker_ports = [p for p in open_ports if p["port"] in [2375, 2376]]
        if any(p["port"] == 2375 for p in docker_ports):
            findings.append({
                "title": "Docker API non chiffrée exposée",
                "severity": "CRITICAL",
                "description": "Le port 2375 (Docker API sans TLS) est accessible. Cela permet une prise de contrôle totale du serveur.",
                "port": 2375,
                "recommendation": "Désactiver l'accès réseau à Docker API ou activer TLS sur le port 2376."
            })

        return {
            "findings": findings,
            "open_ports": open_ports,
            "total_scanned": len(ports_to_scan),
            "total_open": len(open_ports)
        }
