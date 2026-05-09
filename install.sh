#!/bin/bash

# ReconLite Installation Script
# Offers a Docker-first workflow or a local pip-based installation

echo "🔍 ReconLite Installation"
echo "========================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

CURRENT_DIR=$(pwd)
SCRIPT_PATH="$CURRENT_DIR/reconlite.py"
IMAGE_NAME="ghcr.io/debaa17/reconlite:latest"

if [ ! -f "$SCRIPT_PATH" ]; then
    echo -e "${RED}❌ reconlite.py not found in current directory${NC}"
    echo -e "${YELLOW}💡 Run this script from the reconlite repository root${NC}"
    exit 1
fi

PYTHON_CMD=""
PIP_CMD=""

if [ -n "$VIRTUAL_ENV" ]; then
    PYTHON_CMD="python"
    PIP_CMD="pip"
else
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_CMD="python3"
        PIP_CMD="python3 -m pip"
    elif command -v python >/dev/null 2>&1; then
        PYTHON_CMD="python"
        PIP_CMD="python -m pip"
    fi
fi

if [ -z "$PYTHON_CMD" ]; then
    echo -e "${RED}❌ Python 3 is not installed. Install Python 3.7+ or use the Docker option.${NC}"
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
if ! $PYTHON_CMD -c "import sys; exit(0 if sys.version_info >= (3, 7) else 1)"; then
    echo -e "${RED}❌ Python 3.7+ is required. Current version: $PYTHON_VERSION${NC}"
    exit 1
fi

echo -e "${BLUE}Choose an installation method:${NC}"
echo "  1) Docker (recommended, uses GHCR image)"
echo "  2) Local pip install"
printf "Select an option [1-2]: "
read -r INSTALL_MODE

if [ "$INSTALL_MODE" = "1" ]; then
    echo ""
    echo -e "${GREEN}✅ Docker installation selected${NC}"
    echo -e "${BLUE}Run ReconLite from GHCR with:${NC}"
    echo "   docker run --rm $IMAGE_NAME example.com"
    echo ""
    echo -e "${BLUE}To save results to your current directory:${NC}"
    echo "   docker run --rm -v \"$PWD:/work\" $IMAGE_NAME example.com -o /work/results.json"
    echo ""
    echo -e "${YELLOW}Note: Docker is recommended because it avoids local dependency setup.${NC}"
    exit 0
fi

if [ "$INSTALL_MODE" != "2" ]; then
    echo -e "${YELLOW}⚠️  No valid option selected, defaulting to local pip install.${NC}"
fi

echo ""
echo -e "${BLUE}📦 Installing Python dependencies...${NC}"
if ! $PIP_CMD install -r requirements.txt; then
    if [ -n "$VIRTUAL_ENV" ]; then
        echo -e "${RED}❌ Failed to install dependencies in the virtual environment${NC}"
        exit 1
    fi

    echo -e "${YELLOW}⚠️  Standard pip install failed, retrying with --user and --break-system-packages if needed...${NC}"
    if ! $PIP_CMD install -r requirements.txt --user 2>/dev/null; then
        if ! $PIP_CMD install -r requirements.txt --user --break-system-packages 2>/dev/null; then
            echo -e "${RED}❌ Failed to install Python dependencies${NC}"
            exit 1
        fi
    fi
fi

echo -e "${GREEN}✅ Python dependencies installed successfully${NC}"

mkdir -p "$HOME/.local/bin"

cat > "$HOME/.local/bin/reconlite" << EOF
#!/bin/bash
if [ -n "\$VIRTUAL_ENV" ]; then
    exec python "$SCRIPT_PATH" "\$@"
fi

if command -v python3 >/dev/null 2>&1; then
    exec python3 "$SCRIPT_PATH" "\$@"
fi

exec python "$SCRIPT_PATH" "\$@"
EOF

chmod +x "$HOME/.local/bin/reconlite"

SHELL_NAME=$(basename "$SHELL")
case "$SHELL_NAME" in
    zsh)
        SHELL_RC="$HOME/.zshrc"
        ;;
    bash)
        SHELL_RC="$HOME/.bashrc"
        ;;
    fish)
        SHELL_RC="$HOME/.config/fish/config.fish"
        ;;
    *)
        SHELL_RC="$HOME/.profile"
        ;;
esac

mkdir -p "$(dirname "$SHELL_RC")"

case "$SHELL_NAME" in
    fish)
        if ! grep -q 'fish_add_path -m ~/.local/bin' "$SHELL_RC" 2>/dev/null; then
            printf '%s\n' 'fish_add_path -m ~/.local/bin' >> "$SHELL_RC"
            echo -e "${YELLOW}📝 Added ~/.local/bin to your PATH in $SHELL_RC${NC}"
        else
            echo -e "${GREEN}✅ PATH already configured in $SHELL_RC${NC}"
        fi
        ;;
    *)
        if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$SHELL_RC" 2>/dev/null; then
            printf '%s\n' 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
            echo -e "${YELLOW}📝 Added ~/.local/bin to your PATH in $SHELL_RC${NC}"
        else
            echo -e "${GREEN}✅ PATH already configured in $SHELL_RC${NC}"
        fi
        ;;
esac

echo ""
echo -e "${GREEN}✅ ReconLite installed successfully!${NC}"
echo -e "${BLUE}🔧 Reload your shell with:${NC}"
case "$SHELL_NAME" in
    zsh)
        echo "   source ~/.zshrc"
        ;;
    bash)
        echo "   source ~/.bashrc"
        ;;
    fish)
        echo "   source ~/.config/fish/config.fish"
        ;;
    *)
        echo "   source ~/.profile"
        ;;
esac
echo "   reconlite --help"
echo ""
echo -e "${GREEN}🎉 Installation complete!${NC}"
