#!/usr/bin/env bash
# VAJRA Setup Script — v1.4.0
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC}  $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $1"; }
fail() { echo -e "  ${RED}✗${NC}  $1"; exit 1; }

clear
echo -e "${RED}${BOLD}"
cat << 'BANNER'
  ██╗   ██╗ █████╗      ██╗██████╗  █████╗
  ██║   ██║██╔══██╗     ██║██╔══██╗██╔══██╗
  ██║   ██║███████║     ██║██████╔╝███████║
  ╚██╗ ██╔╝██╔══██║██   ██║██╔══██╗██╔══██║
   ╚████╔╝ ██║  ██║╚█████╔╝██║  ██║██║  ██║
    ╚═══╝  ╚═╝  ╚═╝ ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
BANNER
echo -e "${NC}  VAJRA Setup — v1.4.0\n"

# Python check
command -v python3 &>/dev/null || fail "Python 3 not found. Install: https://python.org"
ok "Python $(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"

# Node check
command -v node &>/dev/null || fail "Node.js not found. Install: https://nodejs.org"
ok "Node.js $(node --version)"

# Python deps
echo -e "\n${BOLD}Installing Python packages...${NC}"
pip3 install -r requirements.txt -q && ok "Python packages installed"

# Node deps
echo -e "\n${BOLD}Installing Node.js packages...${NC}"
cd docx_builder && npm install --silent && cd .. && ok "Node packages installed"

# .env setup
echo -e "\n${BOLD}Setting up config...${NC}"
if [ -f ".env" ]; then
    warn ".env already exists — keeping your existing config"
else
    cp .env.example .env
    ok ".env created from template"
    warn "Edit .env and set your AI_API_KEY and AI_BASE_URL before running."
fi

# Runtime directories
mkdir -p reports database ui/static/logos
ok "Runtime directories ready"

# Optional: PDF export via weasyprint
python3 -c "import weasyprint" 2>/dev/null && ok "weasyprint installed — PDF export ready" || \
    warn "PDF export unavailable (optional): pip3 install weasyprint markdown --break-system-packages"

echo -e "\n${GREEN}${BOLD}  VAJRA is ready!${NC}"
echo -e "\n  1. Edit ${CYAN}.env${NC} — set AI_API_KEY, AI_BASE_URL, AI_PROVIDER, AI_MODEL"
echo -e "  2. Run:  ${CYAN}python3 app.py${NC}"
echo -e "  3. Open: ${CYAN}http://localhost:5000${NC}\n"
echo -e "  Docs:    ${CYAN}README.md${NC} | Custom templates: ${CYAN}CUSTOM_TEMPLATE_GUIDE.md${NC}\n"
