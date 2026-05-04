"""
Module: ssl_scanner.py
Analyse SSL/TLS : certificat, protocoles, cipher suites, expiration
"""

import ssl
import socket
import datetime
from typing import Optional


WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON",
    "MD5", "ADH", "AECDH", "PSK", "SRP"
]

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]


class SSLScanner:
    def __init__(self, target: str, timeout: int = 10, port: int = 443):
        self.target = self._clean_target(target)
        self.timeout = timeout
        self.port = port

    def _clean_target(self, target: str) -> str:
        target = target.strip()
        for prefix in ["https://", "http://"]:
            if target.startswith(prefix):
                target = target[len(prefix):]
        target = target.split("/")[0].split("?")[0]
        return target

    def scan(self) -> dict:
        findings = []
        cert_info = {}
        tls_info = {}

        # Récupérer le certificat
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    raw_cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    tls_info["protocol"] = protocol
                    tls_info["cipher_suite"] = cipher[0] if cipher else "Inconnu"
                    tls_info["cipher_bits"] = cipher[2] if cipher else 0

                    # Analyser le protocole
                    if protocol in WEAK_PROTOCOLS:
                        findings.append({
                            "title": f"Protocole TLS faible utilisé: {protocol}",
                            "severity": "HIGH",
                            "description": f"Le serveur utilise {protocol} qui est considéré comme non sécurisé.",
                            "recommendation": f"Désactiver {protocol} et utiliser TLSv1.2 minimum (TLSv1.3 recommandé)."
                        })

                    # Analyser le cipher
                    cipher_name = cipher[0] if cipher else ""
                    for weak in WEAK_CIPHERS:
                        if weak.upper() in cipher_name.upper():
                            findings.append({
                                "title": f"Cipher suite faible: {cipher_name}",
                                "severity": "HIGH",
                                "description": f"Le cipher '{cipher_name}' contient un algorithme faible ({weak}).",
                                "recommendation": "Configurer uniquement des cipher suites modernes (AES-GCM, ChaCha20)."
                            })
                            break

                    # Analyser le certificat
                    if cert:
                        cert_info = self._analyze_cert(cert, findings)

        except ssl.SSLError as e:
            findings.append({
                "title": "Erreur SSL/TLS",
                "severity": "HIGH",
                "description": f"Erreur SSL: {str(e)}",
                "recommendation": "Vérifier la configuration SSL/TLS du serveur."
            })
            return {"findings": findings, "cert_info": cert_info, "tls_info": tls_info}
        except ConnectionRefusedError:
            return {
                "findings": [{"title": "Port HTTPS non accessible", "severity": "INFO",
                              "description": "Port 443 fermé ou HTTPS non configuré.",
                              "recommendation": "Configurer HTTPS sur le serveur."}],
                "cert_info": {},
                "tls_info": {}
            }
        except Exception as e:
            return {"findings": findings, "cert_info": cert_info, "tls_info": tls_info,
                    "error": str(e)}

        # Test des protocoles obsolètes
        weak_protos = self._test_weak_protocols()
        for proto_finding in weak_protos:
            findings.append(proto_finding)

        return {
            "findings": findings,
            "cert_info": cert_info,
            "tls_info": tls_info
        }

    def _analyze_cert(self, cert: dict, findings: list) -> dict:
        cert_info = {}

        # Dates d'expiration
        not_after = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")

        if not_after:
            try:
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                days_left = (expiry - now).days
                cert_info["expiry_date"] = expiry.strftime("%d/%m/%Y")
                cert_info["days_until_expiry"] = days_left

                if days_left < 0:
                    findings.append({
                        "title": "Certificat SSL expiré",
                        "severity": "CRITICAL",
                        "description": f"Le certificat a expiré il y a {abs(days_left)} jours ({expiry.strftime('%d/%m/%Y')}).",
                        "recommendation": "Renouveler le certificat immédiatement. Utiliser Let's Encrypt pour automatiser."
                    })
                elif days_left < 14:
                    findings.append({
                        "title": "Certificat SSL expire très bientôt",
                        "severity": "CRITICAL",
                        "description": f"Le certificat expire dans {days_left} jours.",
                        "recommendation": "Renouveler le certificat immédiatement."
                    })
                elif days_left < 30:
                    findings.append({
                        "title": "Certificat SSL expire bientôt",
                        "severity": "HIGH",
                        "description": f"Le certificat expire dans {days_left} jours.",
                        "recommendation": "Planifier le renouvellement du certificat."
                    })
                elif days_left < 90:
                    findings.append({
                        "title": "Certificat SSL expire dans moins de 90 jours",
                        "severity": "MEDIUM",
                        "description": f"Le certificat expire dans {days_left} jours ({expiry.strftime('%d/%m/%Y')}).",
                        "recommendation": "Planifier le renouvellement du certificat."
                    })
            except ValueError:
                pass

        if not_before:
            try:
                start = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                cert_info["valid_from"] = start.strftime("%d/%m/%Y")
            except ValueError:
                pass

        # Subject / Issuer
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        cert_info["subject"] = subject
        cert_info["issuer"] = issuer
        cert_info["common_name"] = subject.get("commonName", "Inconnu")
        cert_info["issuer_name"] = issuer.get("organizationName", "Inconnu")
        cert_info["serial_number"] = cert.get("serialNumber", "Inconnu")

        # Self-signed?
        if subject == issuer:
            findings.append({
                "title": "Certificat auto-signé détecté",
                "severity": "HIGH",
                "description": "Le certificat est auto-signé et ne sera pas approuvé par les navigateurs.",
                "recommendation": "Obtenir un certificat signé par une CA de confiance (ex: Let's Encrypt)."
            })

        # SAN (Subject Alternative Names)
        san = cert.get("subjectAltName", [])
        cert_info["san"] = [v for _, v in san]

        # Version du certificat
        version = cert.get("version", 0)
        cert_info["version"] = version

        # Algorithme de signature
        # Note: python ssl ne retourne pas directement l'algorithme, on l'infère
        cert_info["issuer_cn"] = issuer.get("commonName", "Inconnu")

        return cert_info

    def _test_weak_protocols(self) -> list:
        """Teste si des protocoles TLS anciens sont acceptés."""
        findings = []
        weak_protocol_tests = [
            (ssl.PROTOCOL_TLS, "TLSv1", {"maximum_version": ssl.TLSVersion.TLSv1}),
            (ssl.PROTOCOL_TLS, "TLSv1.1", {"maximum_version": ssl.TLSVersion.TLSv1_1}),
        ]

        for _, proto_name, kwargs in weak_protocol_tests:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                if "maximum_version" in kwargs:
                    try:
                        context.maximum_version = kwargs["maximum_version"]
                    except (AttributeError, ssl.SSLError):
                        continue

                with socket.create_connection((self.target, self.port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        actual = ssock.version()
                        if actual in ["TLSv1", "TLSv1.1"]:
                            findings.append({
                                "title": f"Protocole obsolète supporté: {actual}",
                                "severity": "HIGH",
                                "description": f"Le serveur accepte {actual}, considéré comme non sécurisé (POODLE, BEAST).",
                                "recommendation": f"Désactiver {actual} dans la configuration TLS."
                            })
            except Exception:
                pass  # Connexion refusée = bien, le protocole n'est pas supporté

        return findings
