#!/bin/bash

# HARSH RECON - Elite Reconnaissance Framework Installer
# Author: Harsh
# Version: 1.0

# Colors
GREEN='\033[0;32m'
BRIGHT_GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BRIGHT_GREEN}"
cat << "EOF"
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                       ║
    ║  🔥  ██╗  ██╗ █████╗ ██████╗ ███████╗██╗  ██╗    ██████╗ ███████╗🔥  ║
    ║      ██║  ██║██╔══██╗██╔══██╗██╔════╝██║  ██║    ██╔══██╗██╔════╝   ║
    ║      ███████║███████║██████╔╝███████╗███████║    ██████╔╝█████╗     ║
    ║      ██╔══██║██╔══██║██╔══██╗╚════██║██╔══██║    ██╔══██╗██╔══╝     ║
    ║      ██║  ██║██║  ██║██║  ██║███████║██║  ██║    ██║  ██║███████╗   ║
    ║      ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝   ║
    ║                                                                       ║
    ║                    INSTALLER - RECONNAISSANCE FRAMEWORK               ║
    ╚═══════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BRIGHT_GREEN}Starting Harsh Recon Framework Installation...${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Function to print status
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_warning "This script is running as root. Some tools may need to be installed in user space."
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    DISTRO=$(lsb_release -si 2>/dev/null || echo "Unknown")
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    print_error "Unsupported OS: $OSTYPE"
    exit 1
fi

print_status "Detected OS: $OS ($DISTRO)"

# Update package manager
print_status "Updating package manager..."
if [[ "$OS" == "linux" ]]; then
    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y build-essential git curl wget python3 python3-pip golang jq 2>/dev/null
    elif command -v yum &> /dev/null; then
        sudo yum update -y -q
        sudo yum install -y gcc git curl wget python3 python3-pip golang jq 2>/dev/null
    elif command -v pacman &> /dev/null; then
        sudo pacman -Syu --noconfirm
        sudo pacman -S --noconfirm base-devel git curl wget python python-pip go jq 2>/dev/null
    fi
elif [[ "$OS" == "macos" ]]; then
    if ! command -v brew &> /dev/null; then
        print_status "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew update
    brew install git curl wget python3 go jq
fi

# Set up Go environment
print_status "Setting up Go environment..."
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
echo "export GOPATH=$HOME/go" >> ~/.bashrc
echo "export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin" >> ~/.bashrc

# Create necessary directories
print_status "Creating directory structure..."
mkdir -p $HOME/tools
mkdir -p $HOME/wordlists
mkdir -p $HOME/go/bin

# Install Python dependencies
print_status "Installing Python dependencies..."
pip3 install --upgrade pip
pip3 install requests colorama dnspython

# Function to install Go tools
install_go_tool() {
    local tool_name=$1
    local install_cmd=$2
    
    print_status "Installing $tool_name..."
    eval $install_cmd
    if [ $? -eq 0 ]; then
        print_status "$tool_name installed successfully ✓"
    else
        print_error "Failed to install $tool_name"
    fi
}

# Install Go-based tools
print_status "Installing reconnaissance tools..."

# Core recon tools
install_go_tool "Subfinder" "GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "Httpx" "GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "Dnsx" "GO111MODULE=on go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "Nuclei" "GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
install_go_tool "Assetfinder" "go install github.com/tomnomnom/assetfinder@latest"
install_go_tool "Amass" "GO111MODULE=on go install -v github.com/OWASP/Amass/v3/...@master"
install_go_tool "Puredns" "GO111MODULE=on go install github.com/d3mondev/puredns/v2@latest"
install_go_tool "Subzy" "go install -v github.com/lukasikic/subzy@latest"
install_go_tool "Hakrawler" "go install github.com/hakluke/hakrawler@latest"
install_go_tool "Gobuster" "go install github.com/OJ/gobuster/v3@latest"
install_go_tool "Ffuf" "go install github.com/ffuf/ffuf@latest"

# Install Findomain
print_status "Installing Findomain..."
if [[ "$OS" == "linux" ]]; then
    wget -q https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux -O $HOME/go/bin/findomain
else
    wget -q https://github.com/Findomain/Findomain/releases/latest/download/findomain-osx -O $HOME/go/bin/findomain
fi
chmod +x $HOME/go/bin/findomain

# Install MassDNS
print_status "Installing MassDNS..."
cd /tmp
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
sudo cp bin/massdns /usr/local/bin/
cd ..
rm -rf massdns

# Install Python-based tools
print_status "Installing Python-based tools..."
pip3 install dnsgen py-altdns dirsearch

# Update Nuclei templates
print_status "Updating Nuclei templates..."
nuclei -update-templates

# Clone SecLists
print_status "Cloning SecLists wordlists..."
if [ ! -d "$HOME/wordlists/SecLists" ]; then
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git $HOME/wordlists/SecLists
else
    cd $HOME/wordlists/SecLists && git pull
fi

# Download the main script
print_status "Downloading Harsh Recon main script..."
curl -s https://raw.githubusercontent.com/harsh/harsh-recon/main/harsh_recon.py -o $HOME/tools/harsh_recon.py 2>/dev/null || cp harsh_recon.py $HOME/tools/harsh_recon.py

# Make it executable
chmod +x $HOME/tools/harsh_recon.py

# Create symbolic link
print_status "Creating symbolic link..."
sudo ln -sf $HOME/tools/harsh_recon.py /usr/local/bin/harsh-recon

# Verify installation
print_status "Verifying installation..."
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BRIGHT_GREEN}Installation Summary:${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Check installed tools
tools=("subfinder" "httpx" "dnsx" "nuclei" "assetfinder" "amass" "puredns" "subzy" "hakrawler" "gobuster" "ffuf" "findomain" "massdns")
installed=0
for tool in "${tools[@]}"; do
    if command -v $tool &> /dev/null; then
        echo -e "${GREEN}✓${NC} $tool"
        ((installed++))
    else
        echo -e "${RED}✗${NC} $tool"
    fi
done

echo ""
echo -e "${BRIGHT_GREEN}Installation Complete!${NC}"
echo -e "${GREEN}Installed $installed/${#tools[@]} tools successfully${NC}"
echo ""
echo -e "${BRIGHT_GREEN}Usage:${NC}"
echo -e "  ${GREEN}harsh-recon -d example.com${NC}"
echo -e "  ${GREEN}python3 $HOME/tools/harsh_recon.py -d example.com${NC}"
echo ""
echo -e "${YELLOW}Note: Source ~/.bashrc or restart your terminal to update PATH${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"