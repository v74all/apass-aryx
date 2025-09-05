#!/usr/bin/env zsh


GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'


INTERACTIVE=true
EXPORT_FILE=""

for arg in "$@"; do
  case $arg in
    --no-interactive)
      INTERACTIVE=false
      ;;
    --export=*)
      EXPORT_FILE="${arg#*=}"
      ;;
  esac
done

print_header() {
  echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║${NC} ${BOLD}$1${NC}${CYAN} ║${NC}"
  echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
}

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }


check_tool() {
  if command -v $1 &>/dev/null; then
    echo -e "  $1: ${GREEN}✓ Available${NC}"
  else
    echo -e "  $1: ${YELLOW}✗ Missing${NC}"
  fi
}

print_header "APK Analysis Workspace Status - $(date '+%Y-%m-%d %H:%M:%S')"


echo -e "${BOLD}${BLUE}🖥️ System Information:${NC}"
echo -e "  Operating System: $(uname -s) $(uname -r)"
echo -e "  User: $(whoami)@$(hostname)"
echo -e "  Working Directory: $(pwd)"
echo -e "  Available Memory: $(free -h 2>/dev/null | grep Mem | awk '{print $7}' || echo "Unknown")"
echo -e "  Disk Space: $(df -h . | awk 'NR==2 {print $4}' || echo "Unknown") free"

echo -e "\n${BOLD}${BLUE}📁 Directory Structure:${NC}"
echo "  samples/           - APK samples and backups"
echo "  analysis_results/  - All analysis outputs"
echo "    ├── static/      - Static analysis results"
echo "    ├── dynamic/     - Dynamic analysis results"
echo "    ├── network/     - Network analysis results"
echo "    ├── reports/     - Generated reports (json/txt/html)"
echo "    ├── artifacts/   - Extracted artifacts"
echo "    ├── archive/     - Archived old results"
echo "    └── sessions/    - Individual analysis sessions"
echo "  tools/             - Analysis tools and scripts"
echo "    ├── frida/       - Frida scripts"
echo "    ├── python/      - Python analysis tools"
echo "    └── scripts/     - Shell and utility scripts"
echo "  config/            - Analysis configurations"
echo "  logs/              - Analysis logs"
echo "  temp/              - Temporary files"

echo -e "\n${BOLD}${BLUE}📊 Workspace Status:${NC}"

APK_STATUS=$([ -f "samples/apps.apk" ] && echo -e "${GREEN}✓ Present${NC}" || echo -e "${YELLOW}✗ Missing${NC}")
TOOLS_STATUS=$([ -d "tools/frida" ] && echo -e "${GREEN}✓ Organized${NC}" || echo -e "${YELLOW}✗ Missing${NC}")
CONFIG_STATUS=$([ -f "config/analysis_config.json" ] && echo -e "${GREEN}✓ Present${NC}" || echo -e "${YELLOW}✗ Missing${NC}")

echo -e "  APK Sample: $APK_STATUS"
echo -e "  Tools: $TOOLS_STATUS"
echo -e "  Config: $CONFIG_STATUS"


WORKSPACE_SIZE=$(du -sh . 2>/dev/null | cut -f1 || echo "Unknown")
echo -e "  Workspace Size: $WORKSPACE_SIZE"

echo -e "\n${BOLD}${BLUE}📈 Analysis Sessions:${NC}"
if [[ -d "analysis_results/sessions" ]]; then
    session_count=$(find analysis_results/sessions -maxdepth 1 -type d -name "session_*" | wc -l)
    echo "  Total Sessions: $session_count"
    if [[ $session_count -gt 0 ]]; then
        latest_session=$(ls -1t analysis_results/sessions/session_* 2>/dev/null | head -1)
        echo "  Latest: $(basename "$latest_session")"
        

        if [[ -f "$latest_session/analysis_summary.txt" ]]; then
            echo -e "  Latest Status: ${GREEN}✓ Complete${NC}"
            echo -e "  Created: $(stat -c %y "$latest_session" 2>/dev/null || stat -f "%Sm" "$latest_session" 2>/dev/null || echo "Unknown")"
        else
            echo -e "  Latest Status: ${YELLOW}⚠ Incomplete${NC}"
        fi
    fi
else
    echo -e "  ${YELLOW}No sessions found${NC}"
fi

echo -e "\n${BOLD}${BLUE}🔧 Tool Availability:${NC}"
check_tool adb
check_tool frida-ps
check_tool python3
check_tool apktool
check_tool jadx
check_tool jarsigner

echo -e "\n${BOLD}${BLUE}🚀 Available Commands:${NC}"
echo "  ./run_organized_analysis.sh  - Run complete analysis"
echo "  ./workspace_status.sh        - Show this status"
echo "  ./cleanup.sh                 - Clean temporary files"
echo "  ./frida_manager.sh           - Start Frida server"
echo "  ./complete-analysis.sh       - Run comprehensive analysis"

echo -e "\n${BOLD}${BLUE}📝 Recent Reports:${NC}"
if [[ -d "analysis_results/reports" ]]; then

    find analysis_results/reports -name "*.json" -o -name "*.txt" -o -name "*.html" | 
    xargs ls -lt 2>/dev/null | 
    head -5 | 
    awk '{print "  " $9 " (" $5 " bytes, " $6 " " $7 ")"}' || 
    echo "  No reports found"
fi


echo -e "\n${BOLD}${BLUE}📱 Android Device Status:${NC}"
if command -v adb &>/dev/null; then
    device_count=$(adb devices | grep -v "List" | grep device | wc -l)
    if [[ $device_count -gt 0 ]]; then
        echo -e "  ${GREEN}$device_count device(s) connected${NC}"
        adb devices | grep -v "List" | grep device | awk '{print "  - " $1 " (" $2 ")"}'
        

        if command -v frida-ps &>/dev/null; then
            if frida-ps -U &>/dev/null; then
                echo -e "  Frida Status: ${GREEN}✓ Running${NC}"
            else
                echo -e "  Frida Status: ${YELLOW}✗ Not running${NC}"
            fi
        fi
    else
        echo -e "  ${YELLOW}No devices connected${NC}"
    fi
else
    echo -e "  ${YELLOW}ADB not found in PATH${NC}"
fi


if [[ -n "$EXPORT_FILE" ]]; then
    print_status "Exporting status to $EXPORT_FILE..."
    {
        echo "# APK Analysis Workspace Status"
        echo "Date: $(date)"
        echo "Working Directory: $(pwd)"
        echo "Workspace Size: $WORKSPACE_SIZE"
        echo "APK Sample: $([ -f "samples/apps.apk" ] && echo "Present" || echo "Missing")"
        echo "Session Count: $session_count"
        
        echo "## Tool Availability"
        command -v adb &>/dev/null && echo "- adb: Available" || echo "- adb: Missing"
        command -v frida-ps &>/dev/null && echo "- frida-ps: Available" || echo "- frida-ps: Missing"
        command -v python3 &>/dev/null && echo "- python3: Available" || echo "- python3: Missing"
        
        echo "## Recent Reports"
        find analysis_results/reports -name "*.json" -o -name "*.txt" | head -5 2>/dev/null
    } > "$EXPORT_FILE"
    print_success "Status exported to $EXPORT_FILE"
fi


if [[ "$INTERACTIVE" == "true" && -t 0 ]]; then
    echo -e "\n${BOLD}${BLUE}⚙️ Interactive Mode:${NC}"
    echo "Select an action to perform:"
    echo "  1) Run organized analysis"
    echo "  2) Clean workspace"
    echo "  3) Start Frida server"
    echo "  4) Check Android device"
    echo "  5) Export status report"
    echo "  q) Quit"
    
    echo -n "Enter choice [1-5/q]: "
    read choice
    
    case $choice in
        1)
            echo "Running analysis..."
            ./run_organized_analysis.sh
            ;;
        2)
            echo "Cleaning workspace..."
            ./cleanup.sh
            ;;
        3)
            echo "Starting Frida server..."
            ./frida_manager.sh
            ;;
        4)
            echo "Android device status:"
            adb devices -l
            ;;
        5)
            echo -n "Enter export filename: "
            read filename
            ./workspace_status.sh --export="$filename" --no-interactive
            ;;
        q|Q)
            echo "Exiting."
            ;;
        *)
            echo "Invalid choice"
            ;;
    esac
fi


echo -e "\n${GREEN}Workspace status check completed at $(date '+%H:%M:%S')${NC}"
