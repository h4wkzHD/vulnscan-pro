"""
Module: dns_scanner.py
Scan DNS : enregistrements, zone transfer, SPF, DKIM, DMARC, sous-domaines
"""

import dns.resolver
import dns.zone
import dns.query
import dns.exception
import socket
from typing import Optional


class DNSScanner:
    def __init__(self, target: str, timeout: int = 10):
        self.target = self._clean_target(target)
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout

    def _clean_target(self, target: str) -> str:
        target = target.strip()
        for prefix in ["https://", "http://"]:
            if target.startswith(prefix):
                target = target[len(prefix):]
        return target.split("/")[0].split("?")[0]

    def scan(self) -> dict:
        findings = []
        dns_records = {}

        # Si c'est une IP, pas de scan DNS
        try:
            socket.inet_aton(self.target)
            return {
                "findings": [],
                "records": {},
                "note": "Cible est une IP — scan DNS ignoré"
            }
        except socket.error:
            pass

        # Enregistrements DNS de base
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        for rtype in record_types:
            records = self._query(rtype)
            if records:
                dns_records[rtype] = records

        # SPF
        spf_finding = self._check_spf(dns_records.get("TXT", []))
        findings += spf_finding

        # DMARC
        dmarc_findings = self._check_dmarc()
        findings += dmarc_findings

        # DKIM (tentative sur _domainkey)
        dkim_findings = self._check_dkim()
        findings += dkim_findings

        # Zone transfer
        zone_findings = self._test_zone_transfer(dns_records.get("NS", []))
        findings += zone_findings

        # Sous-domaines communs
        subdomain_findings, found_subdomains = self._bruteforce_subdomains()
        findings += subdomain_findings

        # Vérifier DNS Wildcard
        wildcard_findings = self._check_wildcard()
        findings += wildcard_findings

        # Vérifier si IPv6 disponible
        if "AAAA" not in dns_records:
            findings.append({
                "title": "Pas d'enregistrement AAAA (IPv6)",
                "severity": "INFO",
                "description": "Le domaine n'a pas d'enregistrement IPv6.",
                "recommendation": "Considérer l'ajout d'un enregistrement AAAA pour le support IPv6."
            })

        return {
            "findings": findings,
            "records": dns_records,
            "subdomains_found": found_subdomains,
            "domain": self.target
        }

    def _query(self, record_type: str) -> list:
        try:
            answers = self.resolver.resolve(self.target, record_type)
            return [str(r) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        except Exception:
            return []

    def _check_spf(self, txt_records: list) -> list:
        findings = []
        spf_records = [r for r in txt_records if r.startswith('"v=spf1') or r.startswith('v=spf1')]

        if not spf_records:
            findings.append({
                "title": "Pas d'enregistrement SPF",
                "severity": "HIGH",
                "description": "Aucun enregistrement SPF trouvé. Le domaine peut être utilisé pour du spoofing d'email.",
                "recommendation": "Ajouter un enregistrement SPF: v=spf1 include:_spf.google.com ~all"
            })
        elif len(spf_records) > 1:
            findings.append({
                "title": "Enregistrements SPF multiples",
                "severity": "MEDIUM",
                "description": "Plusieurs enregistrements SPF détectés — seul le premier sera utilisé.",
                "recommendation": "Consolider en un seul enregistrement SPF."
            })
        else:
            spf = spf_records[0]
            if "+all" in spf:
                findings.append({
                    "title": "SPF trop permissif (+all)",
                    "severity": "HIGH",
                    "description": "L'enregistrement SPF utilise +all qui autorise n'importe qui à envoyer des emails.",
                    "recommendation": "Remplacer +all par ~all (soft fail) ou -all (hard fail)."
                })
            elif "?all" in spf:
                findings.append({
                    "title": "SPF neutre (?all)",
                    "severity": "MEDIUM",
                    "description": "SPF utilise ?all (neutre) — peu de protection contre le spoofing.",
                    "recommendation": "Remplacer ?all par -all pour une protection maximale."
                })

        return findings

    def _check_dmarc(self) -> list:
        findings = []
        try:
            dmarc_domain = f"_dmarc.{self.target}"
            answers = self.resolver.resolve(dmarc_domain, "TXT")
            dmarc_records = [str(r) for r in answers if "v=DMARC1" in str(r)]

            if not dmarc_records:
                raise dns.resolver.NoAnswer

            dmarc = dmarc_records[0]

            # Vérifier la politique
            if "p=none" in dmarc:
                findings.append({
                    "title": "DMARC en mode monitoring (p=none)",
                    "severity": "MEDIUM",
                    "description": "DMARC est configuré avec p=none — les emails non conformes ne sont pas bloqués.",
                    "recommendation": "Passer à p=quarantine puis p=reject après analyse des rapports."
                })
            elif "p=quarantine" in dmarc:
                findings.append({
                    "title": "DMARC en quarantaine (p=quarantine)",
                    "severity": "LOW",
                    "description": "DMARC est configuré en quarantaine — bonne pratique, considérer p=reject.",
                    "recommendation": "Après validation, passer à p=reject pour une protection maximale."
                })
            # p=reject est la meilleure config, pas de finding

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            findings.append({
                "title": "Pas d'enregistrement DMARC",
                "severity": "HIGH",
                "description": "Aucun enregistrement DMARC trouvé — pas de politique d'authentification email.",
                "recommendation": "Créer l'enregistrement: _dmarc.domaine.com TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@domaine.com\""
            })
        except Exception:
            pass

        return findings

    def _check_dkim(self) -> list:
        findings = []
        selectors = ["default", "google", "mail", "dkim", "selector1", "selector2", "k1", "smtp"]

        found_dkim = False
        for selector in selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{self.target}"
                answers = self.resolver.resolve(dkim_domain, "TXT")
                for r in answers:
                    if "v=DKIM1" in str(r) or "p=" in str(r):
                        found_dkim = True
                        break
                if found_dkim:
                    break
            except Exception:
                continue

        if not found_dkim:
            findings.append({
                "title": "DKIM non détecté",
                "severity": "MEDIUM",
                "description": "Aucun enregistrement DKIM trouvé pour les sélecteurs communs. Les emails peuvent être falsifiés.",
                "recommendation": "Configurer DKIM avec votre fournisseur email et publier la clé publique dans un enregistrement TXT."
            })

        return findings

    def _test_zone_transfer(self, ns_records: list) -> list:
        findings = []
        for ns in ns_records[:3]:  # Tester les 3 premiers NS
            ns = ns.rstrip(".")
            try:
                z = dns.zone.from_xfr(
                    dns.query.xfr(ns, self.target, timeout=5, lifetime=5)
                )
                if z:
                    findings.append({
                        "title": f"Zone Transfer DNS possible via {ns}",
                        "severity": "CRITICAL",
                        "description": f"Le serveur DNS {ns} autorise le transfert de zone complet — révèle toute l'infrastructure DNS.",
                        "recommendation": "Désactiver le zone transfer sur tous les serveurs DNS publics. Autoriser uniquement entre serveurs NS légitimes."
                    })
            except Exception:
                pass  # Normal, le zone transfer est refusé

        return findings

    def _bruteforce_subdomains(self) -> tuple:
        """Tente de découvrir des sous-domaines courants."""
        common_subdomains = [
            "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
            "admin", "administrator", "panel", "cpanel", "whm",
            "api", "api2", "dev", "development", "staging", "stage",
            "test", "beta", "demo", "old", "legacy",
            "shop", "store", "blog", "cms", "wp",
            "vpn", "remote", "rdp", "ssh",
            "db", "database", "mysql", "postgres", "redis", "mongo",
            "cdn", "static", "assets", "img", "images",
            "git", "gitlab", "jenkins", "ci", "jira", "confluence",
            "portal", "secure", "login", "auth",
            "backup", "bak", "archive",
            "internal", "intranet", "corp",
            "monitor", "metrics", "grafana", "kibana",
            "mx", "mx1", "mx2", "ns1", "ns2",
        ]

        found = []
        findings = []

        for sub in common_subdomains:
            hostname = f"{sub}.{self.target}"
            try:
                answers = self.resolver.resolve(hostname, "A")
                ips = [str(r) for r in answers]
                found.append({"subdomain": hostname, "ips": ips})

                # Sous-domaines sensibles
                sensitive = ["admin", "panel", "cpanel", "phpmyadmin", "database",
                             "db", "internal", "intranet", "vpn", "backup",
                             "git", "jenkins", "staging", "dev"]
                if sub in sensitive:
                    findings.append({
                        "title": f"Sous-domaine sensible exposé: {hostname}",
                        "severity": "MEDIUM",
                        "description": f"Le sous-domaine {hostname} est résolvable ({', '.join(ips)}). Ce type de sous-domaine peut exposer des interfaces d'administration.",
                        "recommendation": f"Vérifier si {hostname} est intentionnellement public et sécurisé."
                    })
            except Exception:
                continue

        return findings, found

    def _check_wildcard(self) -> list:
        findings = []
        test_domain = f"_nonexistent_vulnscan_test_.{self.target}"
        try:
            self.resolver.resolve(test_domain, "A")
            findings.append({
                "title": "DNS Wildcard détecté",
                "severity": "LOW",
                "description": "Le domaine a un enregistrement DNS wildcard — toute requête DNS retourne une réponse.",
                "recommendation": "Vérifier si le wildcard est intentionnel et nécessaire."
            })
        except Exception:
            pass
        return findings
