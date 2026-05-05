#!/usr/bin/env python3
"""
VulnScan Pro - Outil de scan de vulnérabilités professionnel
Usage: python3 main.py <ip_or_url> [options]
"""

import sys
import os
import argparse
import time
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich import box

# Modules de scan
from modules.network_scanner import NetworkScanner
from modules.http_scanner import HTTPScanner
from modules.ssl_scanner import SSLScanner
from modules.dns_scanner import DNSScanner
from modules.cve_lookup import CVELookup
from modules.port_scanner import PortScanner
from modules.vuln_scanner import VulnScanner
from modules.whois_scanner import WhoisScanner
from modules.report_generator import ReportGenerator

console = Console()

def print_banner():
    console.print()
    console.print("  [bold cyan]██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗  ██╗[/bold cyan]")
    console.print("  [bold cyan]██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗ ██║[/bold cyan]")
    console.print("  [bold cyan]██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗██║[/bold cyan]")
    console.print("  [bold cyan]╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚████║[/bold cyan]")
    console.print("  [bold cyan] ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚███║[/bold cyan]")
    console.print("  [bold cyan]  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝[/bold cyan]")
    console.print()
    console.print("  [bold white]          P R O[/bold white]   [dim]│[/dim]   [bold cyan]v1.0[/bold cyan]   [dim]│[/dim]   [dim]by[/dim] [bold white]hawkz[/bold white]")
    console.print("  [dim]  ─────────────────────────────────────────────────────────────[/dim]")
    console.print("  [dim]  Outil d'audit de sécurité automatisé — Usage légal uniquement[/dim]")
    console.print()

def parse_args():
    parser = argparse.ArgumentParser(
        description="VulnScan Pro — Scanner de vulnérabilités professionnel",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("target", help="IP ou URL cible (ex: 192.168.1.1 ou https://exemple.com)")
    parser.add_argument("--output", "-o", default="./output", help="Dossier de sortie des rapports")
    parser.add_argument("--company", "-c", default="Confidentiel", help="Nom de l'entreprise pour le rapport")
    parser.add_argument("--auditor", "-a", default="VulnScan Pro", help="Nom de l'auditeur")
    parser.add_argument("--no-cve", action="store_true", help="Désactiver la lookup CVE (plus rapide)")
    parser.add_argument("--no-vuln", action="store_true", help="Désactiver les scripts NSE vulnérabilités")
    parser.add_argument("--ports", "-p", default="1-10000", help="Plage de ports (défaut: 1-10000)")
    parser.add_argument("--timeout", "-t", default=10, type=int, help="Timeout en secondes")
    parser.add_argument("--json", action="store_true", help="Exporter aussi en JSON")
    return parser.parse_args()

def run_scan(target: str, args) -> dict:
    """Lance tous les modules de scan et agrège les résultats."""
    results = {
        "target": target,
        "scan_date": datetime.now().isoformat(),
        "auditor": args.auditor,
        "company": args.company,
        "modules": {}
    }

    total_steps = 8
    step = 0

    def print_step(name: str, emoji: str = "🔍"):
        nonlocal step
        step += 1
        console.print(f"\n  [{step}/{total_steps}] {emoji} [bold cyan]{name}[/bold cyan]")

    # ─── 1. WHOIS ──────────────────────────────────────────────────────────────
    print_step("WHOIS & Informations sur la cible", "🌐")
    try:
        scanner = WhoisScanner(target, timeout=args.timeout)
        results["modules"]["whois"] = scanner.scan()
        _print_result_summary("WHOIS", results["modules"]["whois"])
    except Exception as e:
        results["modules"]["whois"] = {"error": str(e)}
        console.print(f"    [yellow]⚠ WHOIS indisponible: {e}[/yellow]")

    # ─── 2. DNS ────────────────────────────────────────────────────────────────
    print_step("Scan DNS (enregistrements, zone transfer, SPF/DKIM)", "🔎")
    try:
        scanner = DNSScanner(target, timeout=args.timeout)
        results["modules"]["dns"] = scanner.scan()
        _print_result_summary("DNS", results["modules"]["dns"])
    except Exception as e:
        results["modules"]["dns"] = {"error": str(e)}
        console.print(f"    [yellow]⚠ DNS indisponible: {e}[/yellow]")

    # ─── 3. PORTS ──────────────────────────────────────────────────────────────
    print_step(f"Scan de ports ({args.ports})", "🔌")
    try:
        scanner = PortScanner(target, port_range=args.ports, timeout=args.timeout)
        results["modules"]["ports"] = scanner.scan()
        _print_port_summary(results["modules"]["ports"])
    except Exception as e:
        results["modules"]["ports"] = {"error": str(e)}
        console.print(f"    [yellow]⚠ Port scan indisponible: {e}[/yellow]")

    # ─── 4. RÉSEAU / NMAP ──────────────────────────────────────────────────────
    print_step("Scan réseau Nmap (services, OS, versions)", "🗺")
    try:
        scanner = NetworkScanner(target, timeout=args.timeout)
        results["modules"]["network"] = scanner.scan()
        _print_result_summary("Réseau", results["modules"]["network"])
    except Exception as e:
        results["modules"]["network"] = {"error": str(e)}
        console.print(f"    [yellow]⚠ Nmap indisponible: {e}[/yellow]")

    # ─── 5. VULNÉRABILITÉS NSE ────────────────────────────────────────────────
    if not args.no_vuln:
        print_step("Scripts NSE Nmap (vulnérabilités connues)", "💥")
        try:
            scanner = VulnScanner(target, timeout=args.timeout)
            results["modules"]["vulns"] = scanner.scan()
            _print_result_summary("Vulnérabilités", results["modules"]["vulns"])
        except Exception as e:
            results["modules"]["vulns"] = {"error": str(e)}
            console.print(f"    [yellow]⚠ NSE vuln indisponible: {e}[/yellow]")
    else:
        results["modules"]["vulns"] = {"skipped": True}

    # ─── 6. HTTP ───────────────────────────────────────────────────────────────
    print_step("Analyse HTTP (headers, redirections, technologies)", "🌍")
    try:
        scanner = HTTPScanner(target, timeout=args.timeout)
        results["modules"]["http"] = scanner.scan()
        _print_result_summary("HTTP", results["modules"]["http"])
    except Exception as e:
        results["modules"]["http"] = {"error": str(e)}
        console.print(f"    [yellow]⚠ HTTP indisponible: {e}[/yellow]")

    # ─── 7. SSL/TLS ────────────────────────────────────────────────────────────
    print_step("Analyse SSL/TLS (certificat, protocoles, cipher suites)", "🔒")
    try:
        scanner = SSLScanner(target, timeout=args.timeout)
        results["modules"]["ssl"] = scanner.scan()
        _print_result_summary("SSL/TLS", results["modules"]["ssl"])
    except Exception as e:
        results["modules"]["ssl"] = {"error": str(e)}
        console.print(f"    [yellow]⚠ SSL indisponible: {e}[/yellow]")

    # ─── 8. CVE LOOKUP ────────────────────────────────────────────────────────
    if not args.no_cve:
        print_step("Recherche CVE (NVD / base publique)", "🛡")
        try:
            services = _extract_services(results)
            lookup = CVELookup(services, timeout=args.timeout)
            results["modules"]["cve"] = lookup.lookup()
            _print_cve_summary(results["modules"]["cve"])
        except Exception as e:
            results["modules"]["cve"] = {"error": str(e)}
            console.print(f"    [yellow]⚠ CVE lookup indisponible: {e}[/yellow]")
    else:
        results["modules"]["cve"] = {"skipped": True}

    return results

def _extract_services(results: dict) -> list:
    """Extrait la liste des services détectés pour la lookup CVE."""
    services = []
    network = results.get("modules", {}).get("network", {})
    ports = results.get("modules", {}).get("ports", {})

    for port_data in network.get("open_ports", []):
        if port_data.get("service") and port_data.get("version"):
            services.append({
                "name": port_data["service"],
                "version": port_data["version"],
                "port": port_data["port"]
            })

    return services

def _print_result_summary(module: str, data: dict):
    if "error" in data:
        return
    findings = data.get("findings", [])
    issues = [f for f in findings if f.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]]
    if issues:
        console.print(f"    [red]⚠ {len(issues)} problème(s) détecté(s)[/red]")
    else:
        console.print(f"    [green]✓ Aucun problème majeur[/green]")

def _print_port_summary(data: dict):
    if "error" in data:
        return
    open_ports = data.get("open_ports", [])
    console.print(f"    [green]✓ {len(open_ports)} port(s) ouvert(s) détecté(s)[/green]")

def _print_cve_summary(data: dict):
    if "error" in data:
        return
    cves = data.get("cves", [])
    critical = sum(1 for c in cves if c.get("severity") == "CRITICAL")
    high = sum(1 for c in cves if c.get("severity") == "HIGH")
    if critical or high:
        console.print(f"    [red]⚠ {critical} CRITICAL, {high} HIGH CVEs trouvées[/red]")
    else:
        console.print(f"    [green]✓ {len(cves)} CVE(s) trouvée(s)[/green]")

def compute_risk_score(results: dict) -> dict:
    """Calcule un score de risque global."""
    score = 0
    max_score = 100
    breakdown = []

    severity_weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 2, "INFO": 0}

    for module_name, module_data in results.get("modules", {}).items():
        if isinstance(module_data, dict):
            for finding in module_data.get("findings", []):
                sev = finding.get("severity", "INFO")
                w = severity_weights.get(sev, 0)
                if w > 0:
                    score += w
                    breakdown.append({
                        "module": module_name,
                        "finding": finding.get("title", ""),
                        "severity": sev,
                        "weight": w
                    })

            # CVE lookup
            for cve in module_data.get("cves", []):
                sev = cve.get("severity", "INFO")
                w = severity_weights.get(sev, 0)
                score += w

    score = min(score, max_score)

    if score >= 75:
        level = "CRITIQUE"
        color = "red"
    elif score >= 50:
        level = "ÉLEVÉ"
        color = "orange3"
    elif score >= 25:
        level = "MOYEN"
        color = "yellow"
    elif score >= 10:
        level = "FAIBLE"
        color = "green"
    else:
        level = "MINIMAL"
        color = "bright_green"

    return {
        "score": score,
        "max": max_score,
        "level": level,
        "color": color,
        "breakdown": breakdown
    }

def print_final_summary(results: dict, risk: dict):
    """Affiche le résumé final dans le terminal."""
    console.print("\n")
    console.rule("[bold cyan]RÉSUMÉ DU SCAN[/bold cyan]")

    # Score de risque
    score_panel = Panel(
        f"[bold {risk['color']}]{risk['score']}/100 — {risk['level']}[/bold {risk['color']}]",
        title="[bold]Score de Risque Global[/bold]",
        border_style=risk['color']
    )
    console.print(score_panel)

    # Tableau des findings
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("Module", style="dim", width=15)
    table.add_column("Problème", width=45)
    table.add_column("Sévérité", justify="center", width=12)

    sev_colors = {
        "CRITICAL": "bold red",
        "HIGH": "bold orange3",
        "MEDIUM": "bold yellow",
        "LOW": "dim green",
        "INFO": "dim"
    }

    for module_name, module_data in results.get("modules", {}).items():
        if isinstance(module_data, dict):
            for finding in module_data.get("findings", []):
                sev = finding.get("severity", "INFO")
                color = sev_colors.get(sev, "dim")
                table.add_row(
                    module_name.upper(),
                    finding.get("title", ""),
                    f"[{color}]{sev}[/{color}]"
                )

    console.print(table)

def main():
    print_banner()
    args = parse_args()
    target = args.target.strip()

    # Toujours convertir en chemin absolu pour éviter les chemins relatifs
    args.output = os.path.abspath(args.output)
    os.makedirs(args.output, exist_ok=True)

    console.print(Panel(
        f"[bold]Cible:[/bold] {target}\n"
        f"[bold]Entreprise:[/bold] {args.company}\n"
        f"[bold]Auditeur:[/bold] {args.auditor}\n"
        f"[bold]Ports:[/bold] {args.ports}\n"
        f"[bold]Rapport:[/bold] {args.output}\n"
        f"[bold]Date:[/bold] {datetime.now().strftime('%d/%m/%Y %H:%M')}",
        title="[bold cyan]Paramètres du scan[/bold cyan]",
        border_style="cyan"
    ))

    console.print("\n[bold yellow]⚠  Ce scan doit être effectué uniquement sur des systèmes dont vous avez l'autorisation.[/bold yellow]\n")

    start_time = time.time()

    # Lancement du scan
    results = run_scan(target, args)

    # Score de risque
    risk = compute_risk_score(results)
    results["risk"] = risk

    elapsed = time.time() - start_time
    results["scan_duration_seconds"] = round(elapsed, 2)

    # Résumé terminal
    print_final_summary(results, risk)

    console.print(f"\n  ⏱ Scan terminé en [bold]{elapsed:.1f}s[/bold]")

    # Export JSON
    if args.json:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(args.output, f"vulnscan_{ts}.json")
        with open(json_path, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        console.print(f"  📄 JSON exporté: [dim]{json_path}[/dim]")

    # Génération du rapport PDF
    console.print("\n[bold cyan]  📊 Génération du rapport PDF professionnel...[/bold cyan]")
    try:
        generator = ReportGenerator(results, output_dir=args.output)
        pdf_path = generator.generate()
        pdf_path_abs = os.path.abspath(pdf_path)
        console.print(f"\n  ✅ [bold green]Rapport généré:[/bold green]")
        console.print(f"     [underline cyan]{pdf_path_abs}[/underline cyan]\n")
        # Ouvrir automatiquement le dossier de sortie sur Windows
        if platform.system() == "Windows":
            import subprocess
            subprocess.Popen(f'explorer /select,"{pdf_path_abs}"')
    except Exception as e:
        console.print(f"\n  [red]❌ Erreur lors de la génération du rapport: {e}[/red]\n")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()