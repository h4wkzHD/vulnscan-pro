"""
Module: http_scanner.py
Analyse HTTP : headers de sécurité, redirections, technologies, cookies, CORS
"""

import requests
import re
from urllib.parse import urlparse
from typing import Optional


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "required": True,
        "severity": "HIGH",
        "description": "HSTS manquant — le navigateur peut être redirigé vers HTTP non chiffré.",
        "recommendation": "Ajouter: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "required": True,
        "severity": "HIGH",
        "description": "CSP manquant — risque d'injection XSS sans restriction de sources.",
        "recommendation": "Définir une politique CSP stricte: Content-Security-Policy: default-src 'self'"
    },
    "X-Frame-Options": {
        "required": True,
        "severity": "MEDIUM",
        "description": "X-Frame-Options manquant — risque de clickjacking.",
        "recommendation": "Ajouter: X-Frame-Options: DENY ou SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "required": True,
        "severity": "MEDIUM",
        "description": "X-Content-Type-Options manquant — MIME sniffing possible.",
        "recommendation": "Ajouter: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "required": False,
        "severity": "LOW",
        "description": "Referrer-Policy non défini — informations de navigation potentiellement exposées.",
        "recommendation": "Ajouter: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "required": False,
        "severity": "LOW",
        "description": "Permissions-Policy manquant — APIs du navigateur non restreintes.",
        "recommendation": "Ajouter Permissions-Policy pour restreindre caméra, micro, géolocalisation."
    },
    "X-XSS-Protection": {
        "required": False,
        "severity": "LOW",
        "description": "X-XSS-Protection non défini (obsolète mais indicateur de bonne pratique).",
        "recommendation": "Ajouter: X-XSS-Protection: 1; mode=block"
    },
    "Cross-Origin-Opener-Policy": {
        "required": False,
        "severity": "LOW",
        "description": "COOP manquant — risque de fuite d'informations cross-origin.",
        "recommendation": "Ajouter: Cross-Origin-Opener-Policy: same-origin"
    },
    "Cross-Origin-Resource-Policy": {
        "required": False,
        "severity": "LOW",
        "description": "CORP manquant.",
        "recommendation": "Ajouter: Cross-Origin-Resource-Policy: same-origin"
    },
}

TECH_SIGNATURES = {
    "Server": {
        "Apache": "Apache Web Server",
        "nginx": "Nginx Web Server",
        "Microsoft-IIS": "Microsoft IIS",
        "LiteSpeed": "LiteSpeed",
        "Caddy": "Caddy",
        "Gunicorn": "Gunicorn (Python)",
        "uWSGI": "uWSGI",
        "Tomcat": "Apache Tomcat",
        "Jetty": "Eclipse Jetty",
        "Kestrel": "ASP.NET Core Kestrel",
    },
    "X-Powered-By": {
        "PHP": "PHP",
        "ASP.NET": "ASP.NET",
        "Express": "Node.js/Express",
        "Next.js": "Next.js",
    }
}


class HTTPScanner:
    def __init__(self, target: str, timeout: int = 10):
        self.target = target
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; VulnScanPro/1.0; Security-Audit)"
        })
        # Ne pas vérifier SSL pour scanner les sites avec certs expirés aussi
        self.session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _normalize_url(self, target: str) -> list:
        """Retourne une liste d'URLs à tester."""
        target = target.strip()
        urls = []
        if target.startswith("http://") or target.startswith("https://"):
            urls.append(target)
            if target.startswith("http://"):
                urls.append("https://" + target[7:])
        else:
            urls.append(f"https://{target}")
            urls.append(f"http://{target}")
        return urls

    def scan(self) -> dict:
        findings = []
        http_info = {
            "urls_tested": [],
            "responses": [],
            "technologies": [],
            "headers_analysis": [],
            "cors_issues": [],
            "cookies_issues": [],
            "redirects": [],
            "server_info": {}
        }

        urls = self._normalize_url(self.target)
        response = None

        for url in urls:
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=True, stream=False)
                response = r
                http_info["urls_tested"].append(url)
                http_info["responses"].append({
                    "url": url,
                    "status_code": r.status_code,
                    "final_url": r.url
                })

                # Redirections
                if r.history:
                    for redir in r.history:
                        http_info["redirects"].append({
                            "from": redir.url,
                            "to": redir.headers.get("Location", ""),
                            "status": redir.status_code
                        })

                # Vérifier redirection HTTP → HTTPS
                if url.startswith("http://") and r.url.startswith("https://"):
                    pass  # Bonne pratique
                elif url.startswith("http://") and not r.url.startswith("https://"):
                    findings.append({
                        "title": "Pas de redirection HTTP → HTTPS",
                        "severity": "HIGH",
                        "description": "Le site ne redirige pas les connexions HTTP vers HTTPS.",
                        "url": url,
                        "recommendation": "Configurer une redirection 301 de HTTP vers HTTPS."
                    })

                # Analyser les headers
                headers = r.headers
                self._analyze_security_headers(headers, url, findings, http_info)
                self._detect_technologies(headers, r.text, http_info)
                self._analyze_cors(headers, url, findings, http_info)
                self._analyze_cookies(r.cookies, findings, http_info)
                self._check_server_info(headers, findings, http_info)
                self._check_sensitive_disclosure(r.text, url, findings)

                break  # On a eu une réponse, pas besoin de continuer

            except requests.exceptions.SSLError:
                findings.append({
                    "title": "Erreur SSL lors de la connexion",
                    "severity": "HIGH",
                    "description": f"Impossible d'établir une connexion SSL sécurisée à {url}.",
                    "recommendation": "Vérifier le certificat SSL et la configuration TLS."
                })
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                findings.append({
                    "title": "Timeout de connexion HTTP",
                    "severity": "INFO",
                    "description": f"Le serveur n'a pas répondu dans le délai imparti ({self.timeout}s).",
                    "url": url,
                    "recommendation": "Vérifier la disponibilité du service."
                })
            except Exception as e:
                http_info["responses"].append({"url": url, "error": str(e)})

        if not http_info["urls_tested"]:
            return {"findings": findings, "error": "Aucune URL HTTP accessible", **http_info}

        return {"findings": findings, **http_info}

    def _analyze_security_headers(self, headers, url, findings, http_info):
        for header_name, config in SECURITY_HEADERS.items():
            found = False
            for h in headers:
                if h.lower() == header_name.lower():
                    found = True
                    break

            status = "présent" if found else "absent"
            http_info["headers_analysis"].append({
                "header": header_name,
                "status": status,
                "value": headers.get(header_name, "N/A")
            })

            if not found and config["required"]:
                findings.append({
                    "title": f"Header de sécurité manquant: {header_name}",
                    "severity": config["severity"],
                    "description": config["description"],
                    "url": url,
                    "recommendation": config["recommendation"]
                })
            elif not found and not config["required"]:
                findings.append({
                    "title": f"Header recommandé manquant: {header_name}",
                    "severity": config["severity"],
                    "description": config["description"],
                    "url": url,
                    "recommendation": config["recommendation"]
                })

        # Vérification spéciale HSTS
        hsts = headers.get("Strict-Transport-Security", "")
        if hsts:
            if "max-age" in hsts:
                max_age_match = re.search(r"max-age=(\d+)", hsts)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 31536000:
                        findings.append({
                            "title": "HSTS max-age trop court",
                            "severity": "LOW",
                            "description": f"HSTS max-age est {max_age}s, recommandé: 31536000s (1 an).",
                            "url": url,
                            "recommendation": "Augmenter HSTS max-age à 31536000 minimum."
                        })
            if "includeSubDomains" not in hsts:
                findings.append({
                    "title": "HSTS sans includeSubDomains",
                    "severity": "LOW",
                    "description": "HSTS ne couvre pas les sous-domaines.",
                    "url": url,
                    "recommendation": "Ajouter includeSubDomains à la directive HSTS."
                })

    def _detect_technologies(self, headers, body: str, http_info):
        techs = []

        # Via headers
        for header_name, signatures in TECH_SIGNATURES.items():
            header_val = headers.get(header_name, "")
            for sig, tech_name in signatures.items():
                if sig.lower() in header_val.lower():
                    techs.append({"name": tech_name, "source": f"Header: {header_name}", "value": header_val})

        # Via body
        body_signatures = {
            "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
            "Joomla": [r"joomla", r"/components/com_"],
            "Drupal": [r"drupal", r"Drupal\.settings"],
            "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
            "Django": [r"csrfmiddlewaretoken", r"django"],
            "React": [r"__REACT_DEVTOOLS", r"react-root", r"_reactRootContainer"],
            "Vue.js": [r"__vue__", r"data-v-"],
            "Angular": [r"ng-version", r"ng-app", r"\[ngFor\]"],
            "Bootstrap": [r"bootstrap\.min\.css", r"bootstrap\.min\.js"],
            "jQuery": [r"jquery\.min\.js", r"jquery-\d"],
            "Shopify": [r"cdn\.shopify\.com", r"shopify"],
            "Magento": [r"mage/", r"Magento"],
        }

        for tech_name, patterns in body_signatures.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    if not any(t["name"] == tech_name for t in techs):
                        techs.append({"name": tech_name, "source": "Body HTML", "value": "Pattern détecté"})
                    break

        http_info["technologies"] = techs

    def _analyze_cors(self, headers, url, findings, http_info):
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")

        if acao:
            http_info["cors_issues"].append({
                "header": "Access-Control-Allow-Origin",
                "value": acao
            })

            if acao == "*":
                if acac.lower() == "true":
                    findings.append({
                        "title": "CORS: Wildcard avec credentials activés",
                        "severity": "CRITICAL",
                        "description": "Access-Control-Allow-Origin: * avec Allow-Credentials: true — combinaison interdite par les specs mais peut indiquer une mauvaise configuration grave.",
                        "url": url,
                        "recommendation": "Ne jamais utiliser wildcard CORS avec credentials. Spécifier les origines autorisées explicitement."
                    })
                else:
                    findings.append({
                        "title": "CORS: Wildcard origin permissive",
                        "severity": "MEDIUM",
                        "description": "L'API accepte des requêtes cross-origin depuis n'importe quelle origine.",
                        "url": url,
                        "recommendation": "Restreindre CORS aux origines spécifiquement autorisées."
                    })

    def _analyze_cookies(self, cookies, findings, http_info):
        for cookie in cookies:
            issues = []

            if not cookie.secure:
                issues.append("attribut Secure manquant")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("attribut HttpOnly manquant")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("attribut SameSite manquant")

            if issues:
                severity = "HIGH" if "Secure" in str(issues) or "HttpOnly" in str(issues) else "MEDIUM"
                findings.append({
                    "title": f"Cookie non sécurisé: {cookie.name}",
                    "severity": severity,
                    "description": f"Cookie '{cookie.name}': {', '.join(issues)}.",
                    "recommendation": "Configurer tous les cookies avec Secure; HttpOnly; SameSite=Strict"
                })
                http_info["cookies_issues"].append({
                    "name": cookie.name,
                    "issues": issues
                })

    def _check_server_info(self, headers, findings, http_info):
        server = headers.get("Server", "")
        x_powered = headers.get("X-Powered-By", "")

        if server:
            http_info["server_info"]["server"] = server
            # Vérifier si la version est exposée
            if any(char.isdigit() for char in server):
                findings.append({
                    "title": "Version du serveur web exposée",
                    "severity": "LOW",
                    "description": f"Le header Server révèle la version: '{server}'. Facilite le ciblage de vulnérabilités connues.",
                    "recommendation": "Masquer ou anonymiser le header Server."
                })

        if x_powered:
            http_info["server_info"]["x_powered_by"] = x_powered
            findings.append({
                "title": "Technologie backend exposée (X-Powered-By)",
                "severity": "LOW",
                "description": f"X-Powered-By révèle: '{x_powered}'.",
                "recommendation": "Supprimer le header X-Powered-By."
            })

    def _check_sensitive_disclosure(self, body: str, url, findings):
        patterns = {
            r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[\w@#$%^&*]{4,}": ("Mot de passe potentiel dans la page", "CRITICAL"),
            r"(?i)api[_-]?key\s*[:=]\s*['\"]?[\w\-]{16,}": ("Clé API exposée dans la page", "CRITICAL"),
            r"(?i)secret[_-]?key\s*[:=]\s*['\"]?[\w\-]{16,}": ("Clé secrète exposée dans la page", "CRITICAL"),
            r"(?i)access[_-]?token\s*[:=]\s*['\"]?[\w\-\.]{20,}": ("Token d'accès exposé", "CRITICAL"),
            r"AKIA[0-9A-Z]{16}": ("Clé AWS potentiellement exposée", "CRITICAL"),
            r"(?i)begin (rsa|dsa|ec) private key": ("Clé privée exposée", "CRITICAL"),
            r"(?i)(sql syntax|mysql error|ora-\d{5}|syntax error.*sql)": ("Message d'erreur SQL exposé", "HIGH"),
            r"(?i)(stack trace|traceback|exception in thread|at com\.|at java\.)": ("Stack trace exposée", "MEDIUM"),
            r"(?i)(phpinfo\(\)|php version|php/\d)": ("Informations PHP exposées", "MEDIUM"),
        }

        for pattern, (title, severity) in patterns.items():
            if re.search(pattern, body[:50000]):
                findings.append({
                    "title": title,
                    "severity": severity,
                    "description": f"Données sensibles potentiellement exposées dans le contenu HTML de {url}.",
                    "recommendation": "Retirer immédiatement les données sensibles du code source côté client."
                })
