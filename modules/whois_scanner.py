"""
Module: whois_scanner.py
Informations WHOIS sur la cible
"""

import whois
import socket
import subprocess
import re
from datetime import datetime


class WhoisScanner:
    def __init__(self, target: str, timeout: int = 10):
        self.target = self._clean_target(target)
        self.timeout = timeout

    def _clean_target(self, target: str) -> str:
        target = target.strip()
        for prefix in ["https://", "http://"]:
            if target.startswith(prefix):
                target = target[len(prefix):]
        return target.split("/")[0].split("?")[0]

    def _is_ip(self, target: str) -> bool:
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False

    def scan(self) -> dict:
        findings = []
        whois_info = {}

        # Résolution DNS
        try:
            ip = socket.gethostbyname(self.target)
            whois_info["resolved_ip"] = ip
        except Exception:
            whois_info["resolved_ip"] = "Non résolvable"

        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(whois_info.get("resolved_ip", self.target))[0]
            whois_info["reverse_dns"] = hostname
        except Exception:
            whois_info["reverse_dns"] = "N/A"

        # WHOIS
        try:
            if self._is_ip(self.target):
                w = whois.whois(self.target)
            else:
                w = whois.whois(self.target)

            if w:
                # Dates
                creation = w.creation_date
                expiration = w.expiration_date
                updated = w.updated_date

                def fmt_date(d):
                    if isinstance(d, list):
                        d = d[0]
                    if isinstance(d, datetime):
                        return d.strftime("%d/%m/%Y")
                    return str(d) if d else "N/A"

                whois_info["domain"] = str(w.domain_name or self.target)
                whois_info["registrar"] = str(w.registrar or "N/A")
                whois_info["creation_date"] = fmt_date(creation)
                whois_info["expiration_date"] = fmt_date(expiration)
                whois_info["updated_date"] = fmt_date(updated)
                whois_info["name_servers"] = [str(ns) for ns in (w.name_servers or [])][:6]
                whois_info["status"] = str(w.status or "N/A")
                whois_info["org"] = str(w.org or w.registrant_name or "N/A")
                whois_info["country"] = str(w.country or "N/A")
                whois_info["emails"] = list(set(w.emails or []))[:5]

                # Vérifier expiration domaine
                if isinstance(expiration, list):
                    expiration = expiration[0]
                if isinstance(expiration, datetime):
                    days_left = (expiration - datetime.utcnow()).days
                    if days_left < 0:
                        findings.append({
                            "title": "Domaine expiré",
                            "severity": "CRITICAL",
                            "description": f"Le domaine a expiré il y a {abs(days_left)} jours.",
                            "recommendation": "Renouveler le domaine immédiatement."
                        })
                    elif days_left < 30:
                        findings.append({
                            "title": "Domaine expire bientôt",
                            "severity": "HIGH",
                            "description": f"Le domaine expire dans {days_left} jours.",
                            "recommendation": "Renouveler le domaine dès que possible."
                        })
                    elif days_left < 90:
                        findings.append({
                            "title": "Domaine expire dans moins de 90 jours",
                            "severity": "MEDIUM",
                            "description": f"Le domaine expire dans {days_left} jours.",
                            "recommendation": "Planifier le renouvellement du domaine."
                        })

                # Vérifier si WHOIS privacy activé
                if any(keyword in str(w.org or "").lower() for keyword in
                       ["privacy", "protect", "whoisguard", "redacted"]):
                    whois_info["privacy_enabled"] = True
                else:
                    whois_info["privacy_enabled"] = False

                # Emails exposés dans WHOIS
                if whois_info["emails"] and not whois_info.get("privacy_enabled"):
                    findings.append({
                        "title": "Emails exposés dans WHOIS",
                        "severity": "LOW",
                        "description": f"Les emails suivants sont visibles publiquement: {', '.join(whois_info['emails'])}",
                        "recommendation": "Activer la protection WHOIS/Privacy Shield chez votre registrar."
                    })

        except Exception as e:
            whois_info["error"] = str(e)

        return {
            "findings": findings,
            "whois_info": whois_info,
            "target": self.target
        }
