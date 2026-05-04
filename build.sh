#!/bin/bash
# ============================================================
#  VulnScan Pro — Script de build exécutable standalone
#  Génère un binaire autonome (Linux ou Windows via Wine)
#  Usage : bash build.sh [--windows]
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

BUILD_DIR="$(pwd)/build"
DIST_DIR="$(pwd)/dist"
VENV_DIR="$(pwd)/venv_build"

step()  { echo -e "\n${CYAN}[*]${NC} ${BOLD}$1${NC}"; }
ok()    { echo -e "  ${GREEN}✓${NC} $1"; }
warn()  { echo -e "  ${YELLOW}⚠${NC} $1"; }
err()   { echo -e "  ${RED}✗${NC} $1"; exit 1; }

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║   VulnScan Pro — Build Script        ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${NC}"

# ── Arguments ────────────────────────────────────────────────────────────────
BUILD_WINDOWS=false
if [[ "$1" == "--windows" ]]; then
  BUILD_WINDOWS=true
  warn "Mode Windows activé (nécessite Wine + python-mingw)"
fi

# ── Environnement virtuel de build ───────────────────────────────────────────
step "Création de l'environnement virtuel de build"
python3 -m venv "$VENV_DIR"
ok "Virtualenv de build créé"

step "Installation des dépendances + PyInstaller"
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r requirements.txt -q
"$VENV_DIR/bin/pip" install pyinstaller==6.3.0 -q
ok "PyInstaller installé"

# ── Nettoyage builds précédents ───────────────────────────────────────────────
step "Nettoyage des builds précédents"
rm -rf "$BUILD_DIR" "$DIST_DIR"
mkdir -p "$DIST_DIR"
ok "Nettoyé"

# ── Création du fichier .spec PyInstaller ────────────────────────────────────
step "Génération du fichier .spec PyInstaller"

cat > vulnscan.spec << 'SPECEOF'
# -*- mode: python ; coding: utf-8 -*-
import sys
import os

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('modules/', 'modules/'),
    ],
    hiddenimports=[
        'nmap',
        'requests',
        'urllib3',
        'dns',
        'dns.resolver',
        'dns.zone',
        'dns.query',
        'dns.exception',
        'whois',
        'reportlab',
        'reportlab.lib',
        'reportlab.lib.pagesizes',
        'reportlab.lib.styles',
        'reportlab.lib.units',
        'reportlab.lib.enums',
        'reportlab.lib.colors',
        'reportlab.platypus',
        'reportlab.platypus.flowables',
        'reportlab.pdfgen',
        'reportlab.pdfgen.canvas',
        'rich',
        'rich.console',
        'rich.panel',
        'rich.progress',
        'rich.table',
        'rich.text',
        'ssl',
        'socket',
        'concurrent.futures',
        'json',
        'datetime',
        'hashlib',
        're',
        'os',
        'sys',
        'time',
        'argparse',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas', 'scipy'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='vulnscan',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
SPECEOF

ok "Fichier vulnscan.spec créé"

# ── Build Linux ───────────────────────────────────────────────────────────────
step "Build de l'exécutable Linux"
"$VENV_DIR/bin/pyinstaller" \
  --clean \
  --noconfirm \
  --distpath "$DIST_DIR" \
  --workpath "$BUILD_DIR" \
  vulnscan.spec 2>&1 | tail -5

if [ -f "$DIST_DIR/vulnscan" ]; then
  chmod +x "$DIST_DIR/vulnscan"
  SIZE=$(du -sh "$DIST_DIR/vulnscan" | cut -f1)
  ok "Exécutable Linux généré : $DIST_DIR/vulnscan ($SIZE)"
else
  err "Échec du build Linux"
fi

# ── Build Windows (optionnel via Wine) ───────────────────────────────────────
if [ "$BUILD_WINDOWS" = true ]; then
  step "Build Windows via Wine"
  if command -v wine &>/dev/null; then
    # Nécessite python Windows installé dans Wine
    WINE_PYTHON="$HOME/.wine/drive_c/Python311/python.exe"
    if [ -f "$WINE_PYTHON" ]; then
      wine "$WINE_PYTHON" -m PyInstaller \
        --clean \
        --noconfirm \
        --onefile \
        --console \
        --name vulnscan_windows \
        --distpath "$DIST_DIR" \
        main.py 2>&1 | tail -5
      ok "Exécutable Windows généré : $DIST_DIR/vulnscan_windows.exe"
    else
      warn "Python Windows non trouvé dans Wine — build Windows ignoré"
      warn "Installer Python dans Wine : wine python-3.11.x-amd64.exe"
    fi
  else
    warn "Wine non installé — build Windows ignoré"
    warn "Pour cross-compiler Windows : apt-get install wine wine64"
  fi
fi

# ── Packaging ─────────────────────────────────────────────────────────────────
step "Création du package de distribution"
PACKAGE_DIR="$DIST_DIR/vulnscan_package"
mkdir -p "$PACKAGE_DIR"
cp "$DIST_DIR/vulnscan" "$PACKAGE_DIR/"
cp README.md "$PACKAGE_DIR/" 2>/dev/null || true
mkdir -p "$PACKAGE_DIR/output"

# Créer un README rapide dans le package
cat > "$PACKAGE_DIR/UTILISATION.txt" << 'READMEEOF'
==================================================
  VulnScan Pro — Outil d'audit de sécurité
==================================================

UTILISATION :
  Linux/Mac :  ./vulnscan <cible> [options]
  Windows  :   vulnscan.exe <cible> [options]

EXEMPLES :
  ./vulnscan 192.168.1.1
  ./vulnscan https://exemple.com
  ./vulnscan 10.0.0.1 -c "Acme Corp" -a "John Doe"
  ./vulnscan exemple.com --ports 1-65535 --json

OPTIONS :
  -c, --company   Nom de l'entreprise (rapport)
  -a, --auditor   Nom de l'auditeur (rapport)
  -p, --ports     Plage de ports (défaut: 1-10000)
  -o, --output    Dossier de sortie (défaut: ./output)
  --no-cve        Désactiver lookup CVE (plus rapide)
  --no-vuln       Désactiver scripts NSE vuln
  --json          Exporter aussi en JSON
  -t, --timeout   Timeout en secondes (défaut: 10)

IMPORTANT :
  - Nmap doit être installé sur le système
  - Linux : sudo apt-get install nmap
  - Windows : https://nmap.org/download.html
  - Utilisation légale uniquement sur vos propres systèmes

RAPPORTS :
  Les rapports PDF sont générés dans le dossier ./output/
==================================================
READMEEOF

# Archive tar.gz
cd "$DIST_DIR"
tar czf "vulnscan_linux_$(date +%Y%m%d).tar.gz" vulnscan_package/
ok "Archive créée : $DIST_DIR/vulnscan_linux_$(date +%Y%m%d).tar.gz"

# ── Résumé ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅  Build terminé avec succès !             ${NC}"
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Fichiers générés :${NC}"
echo -e "  ${CYAN}$DIST_DIR/vulnscan${NC}                 (exécutable Linux)"
echo -e "  ${CYAN}$DIST_DIR/vulnscan_linux_*.tar.gz${NC}  (archive distribuable)"
echo ""
echo -e "  ${BOLD}Pour distribuer :${NC}"
echo -e "  Copier le fichier ${CYAN}vulnscan${NC} sur n'importe quelle machine Linux"
echo -e "  S'assurer que ${CYAN}nmap${NC} est installé sur la machine cible"
echo ""
echo -e "  ${BOLD}Pour Windows :${NC}"
echo -e "  Relancer avec : ${CYAN}bash build.sh --windows${NC}"
echo -e "  (Nécessite Wine + Python Windows installé dans Wine)"
echo ""
