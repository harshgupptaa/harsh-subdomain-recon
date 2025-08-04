#!/usr/bin/env python3
"""
HARSH RECON - Elite Reconnaissance Framework
Comprehensive Bug Bounty Reconnaissance & Vulnerability Assessment
Author: Harsh
Version: 1.0
"""

import os
import sys
import subprocess
import time
import json
import threading
import argparse
from datetime import datetime
from pathlib import Path
import requests
import random

# ANSI Color Codes for Stealth Green Theme
class Colors:
    HEADER = '\033[92m'
    GREEN = '\033[32m'
    BRIGHT_GREEN = '\033[92m'
    DARK_GREEN = '\033[2;32m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'

def print_banner():
    """Display the elite banner"""
    banner = f"""
{Colors.BRIGHT_GREEN}
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                       ║
    ║  {Colors.BLINK}🔥{Colors.RESET}{Colors.BRIGHT_GREEN}  ███████ ██      ██ ████████ ███████    ██████  ███████ {Colors.BLINK}🔥{Colors.RESET}{Colors.BRIGHT_GREEN}  ║
    ║      ██      ██      ██    ██    ██      ██   ██ ██               ║
    ║      █████   ██      ██    ██    █████   ██████  █████            ║
    ║      ██      ██      ██    ██    ██      ██   ██ ██               ║
    ║      ███████ ███████ ██    ██    ███████ ██   ██ ███████          ║
    ║                                                                       ║
    ║           ██████  ███████  ██████  ██████  ███    ██                 ║
    ║           ██   ██ ██      ██      ██    ██ ████   ██                 ║
    ║           ██████  █████   ██      ██    ██ ██ ██  ██                 ║
    ║           ██   ██ ██      ██      ██    ██ ██  ██ ██                 ║
    ║           ██   ██ ███████  ██████  ██████  ██   ████                 ║
    ║                                                                       ║
    ║     ███████ ██████   █████  ███    ███ ███████ ██     ██  ██████     ║
    ║     ██      ██   ██ ██   ██ ████  ████ ██      ██     ██ ██    ██    ║
    ║     █████   ██████  ███████ ██ ████ ██ █████   ██  █  ██ ██    ██    ║
    ║     ██      ██   ██ ██   ██ ██  ██  ██ ██      ██ ███ ██ ██    ██    ║
    ║     ██      ██   ██ ██   ██ ██      ██ ███████  ███ ███   ██████     ║
    ║                                                                       ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    
    {Colors.DARK_GREEN}COMPREHENSIVE BUG BOUNTY RECONNAISSANCE & VULNERABILITY ASSESSMENT{Colors.RESET}
    {Colors.GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}
    {Colors.CYAN}Author: {Colors.BRIGHT_GREEN}Harsh{Colors.RESET} | {Colors.CYAN}Version: {Colors.BRIGHT_GREEN}1.0{Colors.RESET} | {Colors.CYAN}Mode: {Colors.BRIGHT_GREEN}STEALTH{Colors.RESET}
    {Colors.GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}
    """
    print(banner)

class HarshRecon:
    def __init__(self, domain, output_dir="harsh_recon_results"):
        self.domain = domain
        self.output_dir = Path(output_dir) / domain / datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Result files
        self.subdomains_file = self.output_dir / "subdomains.txt"
        self.live_subdomains_file = self.output_dir / "live_subdomains.txt"
        self.takeover_file = self.output_dir / "potential_takeovers.txt"
        self.vulnerabilities_file = self.output_dir / "vulnerabilities.txt"
        self.report_file = self.output_dir / "final_report.txt"
        self.flowchart_file = self.output_dir / "recon_flowchart.txt"
        
        # Tool results storage
        self.all_subdomains = set()
        self.live_subdomains = []
        self.potential_takeovers = []
        self.vulnerabilities = []
        
    def print_status(self, message, status="INFO"):
        """Print colored status messages"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if status == "INFO":
            print(f"{Colors.GRAY}[{timestamp}]{Colors.RESET} {Colors.GREEN}[{status}]{Colors.RESET} {message}")
        elif status == "SUCCESS":
            print(f"{Colors.GRAY}[{timestamp}]{Colors.RESET} {Colors.BRIGHT_GREEN}[{status}]{Colors.RESET} {message}")
        elif status == "WARNING":
            print(f"{Colors.GRAY}[{timestamp}]{Colors.RESET} {Colors.YELLOW}[{status}]{Colors.RESET} {message}")
        elif status == "ERROR":
            print(f"{Colors.GRAY}[{timestamp}]{Colors.RESET} {Colors.RED}[{status}]{Colors.RESET} {message}")
        elif status == "FOUND":
            print(f"{Colors.GRAY}[{timestamp}]{Colors.RESET} {Colors.CYAN}[{status}]{Colors.RESET} {message}")

    def check_and_install_tools(self):
        """Check and install required tools"""
        self.print_status("Checking required tools...", "INFO")
        
        tools = {
            "subfinder": "GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "amass": "GO111MODULE=on go install -v github.com/OWASP/Amass/v3/...@master",
            "dnsx": "GO111MODULE=on go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "httpx": "GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
            "findomain": "wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux -O ~/go/bin/findomain && chmod +x ~/go/bin/findomain",
            "puredns": "GO111MODULE=on go install github.com/d3mondev/puredns/v2@latest",
            "massdns": "git clone https://github.com/blechschmidt/massdns.git /tmp/massdns && cd /tmp/massdns && make && sudo cp bin/massdns /usr/local/bin/",
            "dnsgen": "pip3 install dnsgen",
            "altdns": "pip3 install py-altdns",
            "subzy": "go install -v github.com/lukasikic/subzy@latest",
            "nuclei": "GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            "hakrawler": "go install github.com/hakluke/hakrawler@latest",
            "gobuster": "go install github.com/OJ/gobuster/v3@latest",
            "ffuf": "go install github.com/ffuf/ffuf@latest",
            "dirsearch": "pip3 install dirsearch"
        }
        
        missing_tools = []
        for tool, install_cmd in tools.items():
            if not self.is_tool_installed(tool):
                missing_tools.append((tool, install_cmd))
                self.print_status(f"{tool} not found", "WARNING")
            else:
                self.print_status(f"{tool} ✓", "SUCCESS")
        
        if missing_tools:
            self.print_status(f"Installing {len(missing_tools)} missing tools...", "INFO")
            for tool, cmd in missing_tools:
                self.print_status(f"Installing {tool}...", "INFO")
                try:
                    subprocess.run(cmd, shell=True, check=True, capture_output=True)
                    self.print_status(f"{tool} installed successfully", "SUCCESS")
                except:
                    self.print_status(f"Failed to install {tool}. Please install manually: {cmd}", "ERROR")
        
        # Update nuclei templates
        self.print_status("Updating nuclei templates...", "INFO")
        subprocess.run("nuclei -update-templates", shell=True, capture_output=True)
        
        # Clone/Update SecLists
        self.update_seclists()

    def update_seclists(self):
        """Update SecLists wordlists"""
        seclists_path = Path.home() / "wordlists" / "SecLists"
        
        if seclists_path.exists():
            self.print_status("Updating SecLists...", "INFO")
            subprocess.run(f"cd {seclists_path} && git pull", shell=True, capture_output=True)
        else:
            self.print_status("Cloning SecLists...", "INFO")
            subprocess.run(f"git clone https://github.com/danielmiessler/SecLists.git {seclists_path}", 
                         shell=True, capture_output=True)
        
        self.print_status("SecLists ready ✓", "SUCCESS")

    def is_tool_installed(self, tool):
        """Check if a tool is installed"""
        try:
            subprocess.run(f"which {tool}", shell=True, check=True, capture_output=True)
            return True
        except:
            return False

    def run_subdomain_enumeration(self):
        """Run all subdomain enumeration tools"""
        self.print_status(f"\n{Colors.BRIGHT_GREEN}━━━ SUBDOMAIN ENUMERATION ━━━{Colors.RESET}", "INFO")
        
        # Subfinder
        self.print_status("Running Subfinder...", "INFO")
        subfinder_output = self.run_tool(f"subfinder -d {self.domain} -silent")
        self.all_subdomains.update(subfinder_output.strip().split('\n') if subfinder_output else [])
        
        # Amass
        self.print_status("Running Amass (this may take a while)...", "INFO")
        amass_output = self.run_tool(f"amass enum -passive -d {self.domain} -nocolor")
        self.all_subdomains.update(amass_output.strip().split('\n') if amass_output else [])
        
        # Assetfinder
        self.print_status("Running Assetfinder...", "INFO")
        assetfinder_output = self.run_tool(f"assetfinder --subs-only {self.domain}")
        self.all_subdomains.update(assetfinder_output.strip().split('\n') if assetfinder_output else [])
        
        # Findomain
        self.print_status("Running Findomain...", "INFO")
        findomain_output = self.run_tool(f"findomain -t {self.domain} -q")
        self.all_subdomains.update(findomain_output.strip().split('\n') if findomain_output else [])
        
        # Remove empty strings and clean up
        self.all_subdomains = {s.strip() for s in self.all_subdomains if s.strip()}
        
        # Save subdomains
        with open(self.subdomains_file, 'w') as f:
            f.write('\n'.join(sorted(self.all_subdomains)))
        
        self.print_status(f"Found {len(self.all_subdomains)} unique subdomains", "FOUND")

    def run_dns_resolution(self):
        """Resolve subdomains and find live hosts"""
        self.print_status(f"\n{Colors.BRIGHT_GREEN}━━━ DNS RESOLUTION & VALIDATION ━━━{Colors.RESET}", "INFO")
        
        # Use dnsx for resolution
        self.print_status("Resolving subdomains with dnsx...", "INFO")
        dnsx_cmd = f"cat {self.subdomains_file} | dnsx -silent -a -aaaa -cname -mx -txt -srv -ptr"
        dnsx_output = self.run_tool(dnsx_cmd)
        
        # Use httpx to find live hosts
        self.print_status("Checking for live hosts with httpx...", "INFO")
        httpx_cmd = f"cat {self.subdomains_file} | httpx -silent -follow-redirects -status-code -content-length -title -web-server -tech-detect"
        httpx_output = self.run_tool(httpx_cmd)
        
        if httpx_output:
            self.live_subdomains = [line.split()[0] for line in httpx_output.strip().split('\n')]
            
            with open(self.live_subdomains_file, 'w') as f:
                f.write('\n'.join(self.live_subdomains))
            
            self.print_status(f"Found {len(self.live_subdomains)} live subdomains", "FOUND")

    def run_subdomain_takeover_check(self):
        """Check for subdomain takeover vulnerabilities"""
        self.print_status(f"\n{Colors.BRIGHT_GREEN}━━━ SUBDOMAIN TAKEOVER CHECK ━━━{Colors.RESET}", "INFO")
        
        # Subzy
        self.print_status("Running Subzy for takeover detection...", "INFO")
        subzy_cmd = f"subzy run --targets {self.subdomains_file}"
        subzy_output = self.run_tool(subzy_cmd)
        
        if "VULNERABLE" in subzy_output:
            self.potential_takeovers.append(subzy_output)
            self.print_status("Potential subdomain takeover found!", "WARNING")
        
        # Nuclei takeover templates
        self.print_status("Running Nuclei takeover templates...", "INFO")
        nuclei_cmd = f"nuclei -l {self.live_subdomains_file} -t takeovers/ -silent"
        nuclei_output = self.run_tool(nuclei_cmd)
        
        if nuclei_output:
            self.potential_takeovers.append(nuclei_output)

    def run_vulnerability_scanning(self):
        """Run vulnerability scanning on live hosts"""
        self.print_status(f"\n{Colors.BRIGHT_GREEN}━━━ VULNERABILITY SCANNING ━━━{Colors.RESET}", "INFO")
        
        # Nuclei full scan
        self.print_status("Running Nuclei vulnerability scan...", "INFO")
        nuclei_cmd = f"nuclei -l {self.live_subdomains_file} -severity critical,high,medium -silent"
        nuclei_output = self.run_tool(nuclei_cmd)
        
        if nuclei_output:
            self.vulnerabilities.append(nuclei_output)
            vuln_count = len(nuclei_output.strip().split('\n'))
            self.print_status(f"Found {vuln_count} potential vulnerabilities", "FOUND")

    def run_directory_bruteforce(self):
        """Run directory bruteforcing on selected targets"""
        self.print_status(f"\n{Colors.BRIGHT_GREEN}━━━ DIRECTORY DISCOVERY ━━━{Colors.RESET}", "INFO")
        
        # Select top targets for directory bruteforcing (to save time)
        targets = self.live_subdomains[:5] if len(self.live_subdomains) > 5 else self.live_subdomains
        
        wordlist = Path.home() / "wordlists" / "SecLists" / "Discovery" / "Web-Content" / "common.txt"
        
        for target in targets:
            self.print_status(f"Directory bruteforce on {target}...", "INFO")
            
            # Using ffuf for fast bruteforcing
            ffuf_cmd = f"ffuf -u {target}/FUZZ -w {wordlist} -mc 200,301,302,403 -silent"
            self.run_tool(ffuf_cmd)

    def generate_flowchart(self):
        """Generate a beautiful ASCII flowchart of the recon process"""
        flowchart = f"""
{Colors.BRIGHT_GREEN}
╔══════════════════════════════════════════════════════════════════════════════╗
║                         HARSH RECON FLOWCHART                                ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.GREEN}Target Domain:{Colors.RESET} {self.domain}
{Colors.GREEN}Total Subdomains Found:{Colors.RESET} {len(self.all_subdomains)}
{Colors.GREEN}Live Subdomains:{Colors.RESET} {len(self.live_subdomains)}

{Colors.BRIGHT_GREEN}┌─────────────────────┐
│   {self.domain}      │
└──────────┬──────────┘
           │
     ╔═════╧═════╗
     ║ PHASE 1:  ║
     ║ SUBDOMAIN ║
     ║ DISCOVERY ║
     ╚═════╤═════╝
           │
    ┌──────┴──────┬──────────┬──────────┬──────────┐
    │             │          │          │          │
┌───▼───┐    ┌───▼───┐  ┌───▼───┐  ┌───▼───┐  ┌───▼───┐
│Subfinder│    │ Amass │  │Asset- │  │Findo- │  │Others │
│        │    │       │  │finder │  │main   │  │       │
└───┬───┘    └───┬───┘  └───┬───┘  └───┬───┘  └───┬───┘
    │             │          │          │          │
    └─────────────┴──────────┴──────────┴──────────┘
                           │
                    ╔══════╧══════╗
                    ║   MERGE &   ║
                    ║  DEDUPLICATE║
                    ╚══════╤══════╝
                           │
                    ╔══════╧══════╗
                    ║  PHASE 2:   ║
                    ║DNS RESOLVE &║
                    ║ VALIDATION  ║
                    ╚══════╤══════╝
                           │
                    ┌──────┴──────┐
                    │             │
                ┌───▼───┐    ┌───▼───┐
                │ DNSx  │    │ HTTPx │
                └───┬───┘    └───┬───┘
                    │             │
                    └──────┬──────┘
                           │
                    ╔══════╧══════╗
                    ║  PHASE 3:   ║
                    ║  SECURITY   ║
                    ║   CHECKS    ║
                    ╚══════╤══════╝
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    ┌────▼────┐      ┌────▼────┐      ┌────▼────┐
    │Takeover │      │ Nuclei  │      │Directory│
    │  Check  │      │  Scan   │      │Brute    │
    └────┬────┘      └────┬────┘      └────┬────┘
         │                 │                 │
         └─────────────────┴─────────────────┘
                           │
                    ╔══════╧══════╗
                    ║   FINAL     ║
                    ║   REPORT    ║
                    ╚═════════════╝{Colors.RESET}

{Colors.GREEN}━━━ SUBDOMAIN ANALYSIS ━━━{Colors.RESET}
"""
        
        # Add subdomain categorization
        for i, subdomain in enumerate(list(self.live_subdomains)[:10]):
            if i < len(self.live_subdomains):
                flowchart += f"{Colors.CYAN}├─{Colors.RESET} {subdomain}\n"
            else:
                flowchart += f"{Colors.CYAN}└─{Colors.RESET} {subdomain}\n"
        
        if len(self.live_subdomains) > 10:
            flowchart += f"{Colors.GRAY}   ... and {len(self.live_subdomains) - 10} more{Colors.RESET}\n"
        
        # Save flowchart
        with open(self.flowchart_file, 'w') as f:
            f.write(flowchart.replace('\033[', ''))  # Remove color codes for file
        
        print(flowchart)

    def generate_final_report(self):
        """Generate comprehensive final report"""
        self.print_status(f"\n{Colors.BRIGHT_GREEN}━━━ GENERATING FINAL REPORT ━━━{Colors.RESET}", "INFO")
        
        report = f"""
HARSH RECON - FINAL REPORT
==========================
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Target: {self.domain}

EXECUTIVE SUMMARY
-----------------
Total Subdomains Discovered: {len(self.all_subdomains)}
Live Subdomains: {len(self.live_subdomains)}
Potential Takeovers: {len(self.potential_takeovers)}
Vulnerabilities Found: {len(self.vulnerabilities)}

DETAILED FINDINGS
-----------------

1. SUBDOMAIN ENUMERATION
   Total unique subdomains found: {len(self.all_subdomains)}
   
2. LIVE HOST DETECTION
   Active subdomains: {len(self.live_subdomains)}
   
3. SECURITY VULNERABILITIES
   Critical findings that require immediate attention:
   """
        
        # Add vulnerability details
        if self.vulnerabilities:
            for vuln in self.vulnerabilities:
                report += f"\n   - {vuln}"
        else:
            report += "\n   - No critical vulnerabilities found"
        
        # Add takeover findings
        if self.potential_takeovers:
            report += "\n\n4. SUBDOMAIN TAKEOVER RISKS\n"
            for takeover in self.potential_takeovers:
                report += f"   - {takeover}\n"
        
        # Save report
        with open(self.report_file, 'w') as f:
            f.write(report)
        
        # Print summary
        print(f"\n{Colors.BRIGHT_GREEN}╔══════════════════════════════════════════╗")
        print(f"║           SCAN COMPLETE                  ║")
        print(f"╚══════════════════════════════════════════╝{Colors.RESET}")
        print(f"\n{Colors.GREEN}Results saved to:{Colors.RESET} {self.output_dir}")
        print(f"{Colors.CYAN}├─{Colors.RESET} subdomains.txt ({len(self.all_subdomains)} entries)")
        print(f"{Colors.CYAN}├─{Colors.RESET} live_subdomains.txt ({len(self.live_subdomains)} entries)")
        print(f"{Colors.CYAN}├─{Colors.RESET} recon_flowchart.txt")
        print(f"{Colors.CYAN}└─{Colors.RESET} final_report.txt")

    def run_tool(self, command):
        """Execute a tool and return output"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
            return result.stdout
        except subprocess.TimeoutExpired:
            self.print_status(f"Command timed out: {command}", "WARNING")
            return ""
        except Exception as e:
            self.print_status(f"Error running command: {str(e)}", "ERROR")
            return ""

    def run(self):
        """Main execution flow"""
        print_banner()
        
        self.print_status(f"Starting reconnaissance on {Colors.BRIGHT_GREEN}{self.domain}{Colors.RESET}", "INFO")
        self.print_status(f"Output directory: {self.output_dir}", "INFO")
        
        # Check and install tools
        self.check_and_install_tools()
        
        # Run reconnaissance phases
        self.run_subdomain_enumeration()
        self.run_dns_resolution()
        self.run_subdomain_takeover_check()
        self.run_vulnerability_scanning()
        self.run_directory_bruteforce()
        
        # Generate outputs
        self.generate_flowchart()
        self.generate_final_report()

def main():
    parser = argparse.ArgumentParser(
        description='HARSH RECON - Elite Reconnaissance Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.GREEN}Examples:{Colors.RESET}
  python3 harsh_recon.py -d example.com
  python3 harsh_recon.py -d example.com -o custom_output_dir
  
{Colors.GREEN}Features:{Colors.RESET}
  • Automated subdomain enumeration using multiple tools
  • Live host detection and validation
  • Subdomain takeover vulnerability detection
  • Comprehensive vulnerability scanning
  • Directory bruteforcing on live targets
  • Beautiful CLI with stealth green theme
  • Automatic tool installation and updates
  • Detailed flowchart and reporting
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan')
    parser.add_argument('-o', '--output', default='harsh_recon_results', help='Output directory (default: harsh_recon_results)')
    
    args = parser.parse_args()
    
    # Check if running as root (not recommended)
    if os.geteuid() == 0:
        print(f"{Colors.YELLOW}[WARNING] Running as root is not recommended{Colors.RESET}")
    
    # Create and run the reconnaissance
    recon = HarshRecon(args.domain, args.output)
    
    try:
        recon.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan interrupted by user{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()