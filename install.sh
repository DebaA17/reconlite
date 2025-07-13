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

# Check if we're in a virtual environment
if [ -n "$VIRTUAL_ENV" ]; then
    echo -e "${BLUE}🐍 Virtual environment detected: $VIRTUAL_ENV${NC}"
    PYTHON_CMD="python"
    PIP_CMD="pip"
    INSTALL_LOCATION="virtual environment"
else
    echo -e "${BLUE}🐍 Using system Python${NC}"
    PYTHON_CMD="python3"
    PIP_CMD="python3 -m pip"
    INSTALL_LOCATION="user directory"
fi

# Check if Python 3 is installed
if ! command -v $PYTHON_CMD &> /dev/null; then
    echo -e "${RED}❌ Python 3 is not installed. Please install Python 3.7+ first.${NC}"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
if $PYTHON_CMD -c "import sys; exit(0 if sys.version_info >= (3, 7) else 1)"; then
    echo -e "${GREEN}✅ Python $PYTHON_VERSION detected${NC}"
else
    echo -e "${RED}❌ Python 3.7+ is required. Current version: $PYTHON_VERSION${NC}"
    exit 1
fi

# Get the current directory
CURRENT_DIR=$(pwd)
SCRIPT_PATH="$CURRENT_DIR/reconlite.py"

# Check if reconlite.py exists
if [ ! -f "$SCRIPT_PATH" ]; then
    echo -e "${RED}❌ reconlite.py not found in current directory${NC}"
    echo -e "${YELLOW}💡 Make sure you're running this from the reconlite directory${NC}"
    exit 1
fi

# Check if requirements.txt exists and install dependencies
if [ -f "requirements.txt" ]; then
    echo -e "${BLUE}📦 Installing Python dependencies to $INSTALL_LOCATION...${NC}"
    
    if [ -n "$VIRTUAL_ENV" ]; then
        # In virtual environment - use pip directly
        if $PIP_CMD install -r requirements.txt; then
            echo -e "${GREEN}✅ Dependencies installed successfully in virtual environment${NC}"
        else
            echo -e "${RED}❌ Failed to install dependencies in virtual environment${NC}"
            exit 1
        fi
    else
        # Not in virtual environment - try user installation with fallbacks
        if $PIP_CMD install -r requirements.txt --user 2>/dev/null; then
            echo -e "${GREEN}✅ Dependencies installed successfully${NC}"
        else
            echo -e "${YELLOW}⚠️  Standard pip installation failed. Trying alternative methods...${NC}"
            
            # Try with --break-system-packages for Kali Linux
            if $PIP_CMD install -r requirements.txt --user --break-system-packages 2>/dev/null; then
                echo -e "${GREEN}✅ Dependencies installed successfully (with --break-system-packages)${NC}"
            else
                echo -e "${YELLOW}⚠️  Pip installation failed. Checking if dependencies are already available...${NC}"
                
                # Check if key dependencies are available
                $PYTHON_CMD -c "import whois, ipwhois, dns.resolver, requests" 2>/dev/null
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}✅ Key dependencies are already available${NC}"
                else
                    echo -e "${YELLOW}⚠️  Some dependencies may be missing. You may need to install them manually:${NC}"
                    echo -e "${BLUE}     sudo apt install python3-whois python3-dns python3-requests${NC}"
                    echo -e "${BLUE}     pip install ipwhois --user --break-system-packages${NC}"
                fi
            fi
        fi
    fi
else
    echo -e "${YELLOW}⚠️  requirements.txt not found, skipping dependency installation${NC}"
fi

# Create local bin directory if it doesn't exist
mkdir -p "$HOME/.local/bin"

# Create a wrapper script
cat > "$HOME/.local/bin/reconlite" << EOF
#!/bin/bash
# ReconLite wrapper script
# Auto-detects virtual environment and uses appropriate Python

if [ -n "\$VIRTUAL_ENV" ]; then
    # Use virtual environment's Python
    exec python "$SCRIPT_PATH" "\$@"
else
    # Use system Python
    exec python3 "$SCRIPT_PATH" "\$@"
fi
EOF

# Make it executable
chmod +x "$HOME/.local/bin/reconlite"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    # Check which shell config file to use
    if [ -f "$HOME/.zshrc" ] && [ "$SHELL" = "/bin/zsh" ]; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
        echo -e "${YELLOW}📝 Added ~/.local/bin to your PATH in ~/.zshrc${NC}"
        echo -e "${BLUE}💡 Run 'source ~/.zshrc' or restart your terminal to use the command${NC}"
    elif [ -f "$HOME/.bashrc" ]; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
        echo -e "${YELLOW}📝 Added ~/.local/bin to your PATH in ~/.bashrc${NC}"
        echo -e "${BLUE}💡 Run 'source ~/.bashrc' or restart your terminal to use the command${NC}"
    else
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.profile
        echo -e "${YELLOW}📝 Added ~/.local/bin to your PATH in ~/.profile${NC}"
        echo -e "${BLUE}💡 Restart your terminal to use the command${NC}"
    fi
else
    echo -e "${GREEN}✅ PATH already includes ~/.local/bin${NC}"
fi

echo -e "${GREEN}✅ ReconLite installed successfully!${NC}"
echo ""
echo -e "${YELLOW}📋 Usage Examples:${NC}"
echo "   reconlite example.com"
echo "   reconlite example.com --quick"
echo "   reconlite example.com --resolve-ips"
echo "   reconlite --version"
echo ""
echo -e "${BLUE}🔧 To use immediately in current terminal:${NC}"
if [ "$SHELL" = "/bin/zsh" ]; then
    echo "   source ~/.zshrc"
else
    echo "   source ~/.bashrc"
fi
echo "   reconlite --help"
echo ""
echo -e "${BLUE}🌐 Also available as web version: https://recon.debasisbiswas.me${NC}"
echo -e "${GREEN}🎉 Installation complete!${NC}"
