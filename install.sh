#!/bin/bash

# ReconLite Installation Script
# Creates a global 'reconlite' command for easy usage

echo "🔍 ReconLite Installation"
echo "========================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the current directory
CURRENT_DIR=$(pwd)
SCRIPT_PATH="$CURRENT_DIR/reconlite.py"

# Check if reconlite.py exists
if [ ! -f "$SCRIPT_PATH" ]; then
    echo -e "${RED}❌ reconlite.py not found in current directory${NC}"
    exit 1
fi

# Create local bin directory if it doesn't exist
mkdir -p "$HOME/.local/bin"

# Create a wrapper script
cat > "$HOME/.local/bin/reconlite" << EOF
#!/bin/bash
python3 "$SCRIPT_PATH" "\$@"
EOF

# Make it executable
chmod +x "$HOME/.local/bin/reconlite"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    echo -e "${YELLOW}📝 Added ~/.local/bin to your PATH in ~/.bashrc${NC}"
    echo -e "${BLUE}💡 Run 'source ~/.bashrc' or restart your terminal to use the command${NC}"
fi

echo -e "${GREEN}✅ ReconLite installed successfully!${NC}"
echo ""
echo -e "${YELLOW}📋 Usage Examples:${NC}"
echo "   reconlite example.com"
echo "   reconlite example.com --quick"
echo "   reconlite example.com --resolve-ips"
echo ""
echo -e "${BLUE}🔧 To use immediately in current terminal:${NC}"
echo "   source ~/.bashrc"
echo "   reconlite --help"
echo ""
echo -e "${GREEN}🎉 Installation complete!${NC}"
