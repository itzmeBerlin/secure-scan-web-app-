#!/bin/bash
# =============================================================================
# setup.sh — Kali Linux one-shot setup for SecureScan Platform
# Run: chmod +x setup.sh && sudo ./setup.sh
# =============================================================================

set -e  # Exit immediately on error
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ █████╗ ███╗  ██╗"
echo "  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝██╔══██╗████╗ ██║"
echo "  ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ╚█████╗ ██║  ╚═╝██╔██╗██║"
echo "  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝   ╚═══██╗██║  ██╗██║╚████║"
echo "  ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗██████╔╝╚█████╔╝██║ ╚███║"
echo "  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝  ╚════╝ ╚═╝  ╚══╝"
echo -e "${NC}"
echo -e "${GREEN}${BOLD}  Intelligent Web Application Security Testing Platform — Setup${NC}"
echo ""

# ── 1. System Packages ────────────────────────────────────────────────────────
echo -e "${CYAN}[1/4] Installing system packages...${NC}"
apt-get update -qq
apt-get install -y -qq nmap curl python3 python3-pip python3-venv

echo -e "${GREEN}  ✓ System packages installed${NC}"

# ── 2. Python Virtual Environment ─────────────────────────────────────────────
echo -e "${CYAN}[2/4] Creating Python virtual environment...${NC}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

python3 -m venv .venv
source .venv/bin/activate

echo -e "${GREEN}  ✓ Virtual environment created at .venv/${NC}"

# ── 3. Python Dependencies ────────────────────────────────────────────────────
echo -e "${CYAN}[3/4] Installing Python dependencies...${NC}"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo -e "${GREEN}  ✓ Python packages installed${NC}"

# ── 4. Permissions ────────────────────────────────────────────────────────────
echo -e "${CYAN}[4/4] Setting up permissions for nmap...${NC}"
chmod +s /usr/bin/nmap 2>/dev/null || echo "  (setuid not needed on this system)"
mkdir -p reports
echo -e "${GREEN}  ✓ Permissions configured${NC}"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  ✓ Setup complete!${NC}"
echo ""
echo -e "  To start the platform:"
echo -e "  ${CYAN}source .venv/bin/activate${NC}"
echo -e "  ${CYAN}python app.py${NC}"
echo ""
echo -e "  Then open: ${BOLD}http://localhost:5000${NC}"
echo ""
