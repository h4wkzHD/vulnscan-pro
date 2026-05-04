#!/bin/bash
# ============================================================
#  VulnScan Pro — Script d'installation pour Debian/Ubuntu
#  Usage : sudo bash install.sh
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/opt/vulnscan"
BIN_LINK="/usr/local/bin/vulnscan"

banner() {
echo -e "${CYAN}"
cat << 'EOF'
╦  ╦╦ ╦╦  ╔╗╔╔═╗╔═╗╔═╗╔╗╔  ╔═╗╦═╗╔═╗
╚╗╔╝║ ║║  ║║║╚═╗║  ╠═╣║║║  ╠═╝╠╦╝║ ║
 ╚╝ ╚═╝╩═╝╝╚╝╚═╝╚═╝╩ ╩╝╚╝  ╩  ╩╚═╚═╝
  Installation Script — Debian/Ubuntu
EOF
echo -e "${NC}"
}

step() { echo -e "\n${CYAN}[*]${NC} ${BOLD}$1${NC}"; }
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
err()  { echo -e "  ${RED}✗${NC} $1"; exit 1; }

# ── Vérification root ─────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  err "Ce script doit être lancé en root : sudo bash install.sh"
fi

banner

# ── Détection OS ─────────────────────────────────────────────────────────────
step "Détection du système"
if [ -f /etc/debian_version ]; then
  ok "Debian/Ubuntu détecté"
else
  warn "Système non-Debian — le script peut ne pas fonctionner correctement"
fi

# ── Mise à jour des paquets ───────────────────────────────────────────────────
step "Mise à jour des paquets système"
apt-get update -qq
ok "Index des paquets mis à jour"

# ── Installation des dépendances système ─────────────────────────────────────
step "Installation des dépendances système"
apt-get install -y -qq \
  python3 \
  python3-pip \
  python3-venv \
  nmap \
  dnsutils \
  whois \
  curl \
  wget \
  git \
  libssl-dev \
  gcc \
  build-essential \
  > /dev/null 2>&1

ok "python3, pip, venv installés"
ok "nmap installé"
ok "dnsutils, whois, curl installés"
ok "Dépendances de compilation installées"

# ── Vérification Python 3.8+ ─────────────────────────────────────────────────
step "Vérification de la version Python"
PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 8 ]; then
  ok "Python $PY_VERSION détecté (OK)"
else
  err "Python 3.8+ requis, version détectée: $PY_VERSION"
fi

# ── Création du dossier d'installation ───────────────────────────────────────
step "Création du répertoire d'installation : $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/output"
ok "Répertoire créé"

# ── Copie des fichiers du projet ──────────────────────────────────────────────
step "Copie des fichiers du projet"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cp -r "$SCRIPT_DIR/main.py" "$INSTALL_DIR/"
cp -r "$SCRIPT_DIR/modules/" "$INSTALL_DIR/"
cp -r "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"
ok "Fichiers copiés dans $INSTALL_DIR"

# ── Création de l'environnement virtuel Python ────────────────────────────────
step "Création de l'environnement virtuel Python"
python3 -m venv "$INSTALL_DIR/venv"
ok "Virtualenv créé dans $INSTALL_DIR/venv"

# ── Installation des dépendances Python ──────────────────────────────────────
step "Installation des dépendances Python (peut prendre 1-2 minutes)"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
ok "Toutes les dépendances Python installées"

# ── Création du wrapper de lancement ─────────────────────────────────────────
step "Création du script de lancement"
cat > "$BIN_LINK" << EOF
#!/bin/bash
# VulnScan Pro — Wrapper de lancement
exec "$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/main.py" "\$@"
EOF
chmod +x "$BIN_LINK"
ok "Commande 'vulnscan' disponible globalement"

# ── Permissions ───────────────────────────────────────────────────────────────
step "Configuration des permissions"
chmod -R 755 "$INSTALL_DIR"
chmod -R 777 "$INSTALL_DIR/output"
ok "Permissions configurées"

# ── Test de l'installation ────────────────────────────────────────────────────
step "Test de l'installation"
if "$INSTALL_DIR/venv/bin/python3" -c "import nmap, requests, dns.resolver, reportlab, rich, whois; print('OK')" 2>/dev/null | grep -q "OK"; then
  ok "Tous les modules Python importés avec succès"
else
  warn "Un ou plusieurs modules Python ont des problèmes — vérifier manuellement"
fi

if command -v nmap &>/dev/null; then
  NMAP_VER=$(nmap --version | head -1)
  ok "Nmap disponible: $NMAP_VER"
else
  warn "Nmap non trouvé dans le PATH"
fi

# ── Résumé final ─────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅  VulnScan Pro installé avec succès !     ${NC}"
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Utilisation :${NC}"
echo -e "  ${CYAN}vulnscan <ip_ou_url>${NC}"
echo -e "  ${CYAN}vulnscan 192.168.1.1${NC}"
echo -e "  ${CYAN}vulnscan https://exemple.com -c \"Ma Société\" -a \"John Doe\"${NC}"
echo ""
echo -e "  ${BOLD}Options :${NC}"
echo -e "  ${YELLOW}--company, -c${NC}   Nom de l'entreprise pour le rapport"
echo -e "  ${YELLOW}--auditor, -a${NC}   Nom de l'auditeur"
echo -e "  ${YELLOW}--ports, -p${NC}     Plage de ports (défaut: 1-10000)"
echo -e "  ${YELLOW}--output, -o${NC}    Dossier de sortie des rapports"
echo -e "  ${YELLOW}--no-cve${NC}        Désactiver la lookup CVE"
echo -e "  ${YELLOW}--no-vuln${NC}       Désactiver les scripts NSE"
echo -e "  ${YELLOW}--json${NC}          Exporter aussi en JSON"
echo ""
echo -e "  ${BOLD}Rapports générés dans :${NC} ${CYAN}$INSTALL_DIR/output/${NC}"
echo -e "  ${BOLD}Ou dans le dossier courant avec${NC} ${CYAN}-o ./mes_rapports${NC}"
echo ""
echo -e "  ${RED}⚠  Usage légal uniquement — Uniquement sur vos propres systèmes${NC}"
echo ""
