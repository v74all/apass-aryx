#!/usr/bin/env zsh



set -euo pipefail
setopt null_glob


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() { echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"; echo -e "${CYAN}║${NC} $1${CYAN} ║${NC}"; echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"; }
print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }


TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ROOT_DIR="$(pwd)"

print_header "APK Analysis Workspace Reorganization - Started at $(date)"


print_status "Creating organized directory structure..."


mkdir -p \
    "analysis_results/static" \
    "analysis_results/dynamic" \
    "analysis_results/network" \
    "analysis_results/behavioral" \
    "analysis_results/reports/json" \
    "analysis_results/reports/text" \
    "analysis_results/reports/html" \
    "analysis_results/artifacts/manifests" \
    "analysis_results/artifacts/certificates" \
    "analysis_results/artifacts/resources" \
    "analysis_results/artifacts/metadata" \
    "analysis_results/archive" \
    "analysis_results/sessions" \
    "tools/frida" \
    "tools/python" \
    "tools/scripts" \
    "samples/backup" \
    "config/analysis" \
    "config/yara" \
    "config/templates" \
    "temp" \
    "logs"

print_success "Directory structure created"


print_status "Backing up original APK sample..."
if [[ -f "apps.apk" ]]; then
    cp "apps.apk" "samples/backup/apps_${TIMESTAMP}.apk"

    ln -sf "$(realpath apps.apk)" "samples/apps.apk"
    print_success "APK backed up and linked"
else
    print_warning "Original apps.apk not found"
fi


print_status "Consolidating analysis results..."


if [[ -d "static_analysis_output" ]]; then
    if [[ -d "static_analysis_output/artifacts" ]]; then
        cp -r "static_analysis_output/artifacts"/* "analysis_results/artifacts/" 2>/dev/null || true
    fi

    tar -czf "analysis_results/archive/static_analysis_output_${TIMESTAMP}.tgz" "static_analysis_output" 2>/dev/null || true
    print_success "Static analysis results consolidated"
fi


if [[ -d "analysis_output" ]]; then
    find "analysis_output" -name "*.json" -exec cp {} "analysis_results/reports/json/" \; 2>/dev/null || true
    find "analysis_output" -name "*.txt" -exec cp {} "analysis_results/reports/text/" \; 2>/dev/null || true
    tar -czf "analysis_results/archive/analysis_output_${TIMESTAMP}.tgz" "analysis_output" 2>/dev/null || true
    print_success "Analysis output consolidated"
fi


comprehensive_dirs=($ROOT_DIR/comprehensive_analysis_*)
if (( ${#comprehensive_dirs[@]} > 0 )); then
    for dir in ${comprehensive_dirs[@]}; do
        dir_name=$(basename "$dir")
        if [[ -f "$dir/comprehensive_report.json" ]]; then
            cp "$dir/comprehensive_report.json" "analysis_results/reports/json/${dir_name}_report.json"
        fi
        if [[ -f "$dir/analysis_report.txt" ]]; then
            cp "$dir/analysis_report.txt" "analysis_results/reports/text/${dir_name}_report.txt"
        fi
        if [[ -f "$dir/analysis.log" ]]; then
            cp "$dir/analysis.log" "logs/${dir_name}.log"
        fi
    done

    tar -czf "analysis_results/archive/comprehensive_analysis_${TIMESTAMP}.tgz" "${comprehensive_dirs[@]}" 2>/dev/null || true
    print_success "Comprehensive analysis results consolidated"
fi


print_status "Organizing analysis tools..."


if [[ -d "tools/frida_scripts" ]]; then
    cp -r "tools/frida_scripts"/* "tools/frida/" 2>/dev/null || true
fi


if [[ -d "tools/python_scripts" ]]; then
    cp -r "tools/python_scripts"/* "tools/python/" 2>/dev/null || true
fi


if [[ -d "ENHANCED_MALWARE_ANALYSIS_SUITE" ]]; then

    if [[ -d "ENHANCED_MALWARE_ANALYSIS_SUITE/config" ]]; then
        cp -r "ENHANCED_MALWARE_ANALYSIS_SUITE/config"/* "config/" 2>/dev/null || true
    fi
    

    if [[ -d "ENHANCED_MALWARE_ANALYSIS_SUITE/scripts" ]]; then
        cp -r "ENHANCED_MALWARE_ANALYSIS_SUITE/scripts"/* "tools/scripts/" 2>/dev/null || true
    fi
    

    if [[ -d "ENHANCED_MALWARE_ANALYSIS_SUITE/tools" ]]; then
        cp -r "ENHANCED_MALWARE_ANALYSIS_SUITE/tools"/* "tools/python/" 2>/dev/null || true
    fi
    

    if [[ -f "ENHANCED_MALWARE_ANALYSIS_SUITE/malware_analyzer.py" ]]; then
        cp "ENHANCED_MALWARE_ANALYSIS_SUITE/malware_analyzer.py" "tools/python/"
    fi
    
    print_success "Enhanced malware analysis suite tools organized"
fi


for script in enhanced_data_extractor.py domain_osint.sh; do
    if [[ -f "$script" ]]; then
        cp "$script" "tools/scripts/"
    fi
done

print_success "Tools organized"


print_status "Consolidating reports..."

if [[ -d "reports" ]]; then

    if [[ -d "reports/archive" ]]; then
        cp -r "reports/archive"/* "analysis_results/archive/" 2>/dev/null || true
    fi
fi

print_success "Reports consolidated"


print_status "Cleaning up old directories..."


old_dirs=(
    "static_analysis_output"
    "analysis_output"
    "tools/frida_scripts"
    "tools/python_scripts"
    "reports"
    "${comprehensive_dirs[@]}"
)

for dir in "${old_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
        rm -rf "$dir"
        print_success "Removed old directory: $dir"
    fi
done


find "$ROOT_DIR" -type d -empty -delete 2>/dev/null || true

print_success "Cleanup completed"


print_status "Creating organized analysis runner..."

cat > "run_organized_analysis.sh" << 'EOF'




set -euo pipefail

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
APK_PATH="samples/apps.apk"
PACKAGE_NAME="com.xnotice.app"


GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

echo "🔬 Organized APK Analysis - Started at $(date)"
echo "=================================================="

if [[ ! -f "$APK_PATH" ]]; then
    print_warning "APK not found at $APK_PATH"
    exit 1
fi


SESSION_DIR="analysis_results/sessions/session_${TIMESTAMP}"
mkdir -p "$SESSION_DIR"/{static,dynamic,network,logs}


print_status "Running static analysis..."
if [[ -f "tools/python/enhanced_static_analyzer.py" ]]; then
    python3 "tools/python/enhanced_static_analyzer.py" "$APK_PATH" "$PACKAGE_NAME" > "$SESSION_DIR/static/static_analysis.json" 2>"$SESSION_DIR/logs/static_analysis.log"
    print_success "Static analysis completed"
fi


if [[ -f "tools/scripts/enhanced_data_extractor.py" ]]; then
    python3 "tools/scripts/enhanced_data_extractor.py" "$APK_PATH" "$PACKAGE_NAME"

    if [[ -d "comprehensive_analysis_$(date +%Y%m%d)*" ]]; then
        latest_analysis=$(ls -1t comprehensive_analysis_* | head -1)
        mv "$latest_analysis"/* "$SESSION_DIR/"
        rmdir "$latest_analysis"
    fi
fi


print_status "Generating consolidated report..."
cat > "$SESSION_DIR/analysis_summary.txt" << EOL
APK Analysis Summary
===================
Timestamp: $TIMESTAMP
APK: $APK_PATH
Package: $PACKAGE_NAME
Session: $SESSION_DIR

Analysis Components:
- Static Analysis: $([ -f "$SESSION_DIR/static/static_analysis.json" ] && echo "✓ Completed" || echo "✗ Failed")
- Network Analysis: $([ -f "$SESSION_DIR/network/network_analysis.json" ] && echo "✓ Completed" || echo "✗ Skipped")
- Dynamic Analysis: $([ -f "$SESSION_DIR/dynamic/dynamic_analysis.json" ] && echo "✓ Completed" || echo "✗ Skipped")

Artifacts Location: analysis_results/artifacts/
Reports Location: analysis_results/reports/
Session Data: $SESSION_DIR
EOL

print_success "Analysis session completed: $SESSION_DIR"
echo "📊 View summary: cat $SESSION_DIR/analysis_summary.txt"
EOF

chmod +x "run_organized_analysis.sh"
print_success "Organized analysis runner created"


print_status "Creating analysis configuration..."

cat > "config/analysis_config.json" << 'EOF'
{
  "analysis": {
    "static": {
      "enabled": true,
      "extract_strings": true,
      "analyze_permissions": true,
      "extract_urls": true,
      "analyze_certificates": true
    },
    "dynamic": {
      "enabled": false,
      "runtime_monitoring": true,
      "network_capture": true,
      "behavior_analysis": true
    },
    "network": {
      "enabled": true,
      "domain_analysis": true,
      "ssl_analysis": true,
      "reputation_check": true
    }
  },
  "output": {
    "formats": ["json", "txt", "html"],
    "timestamp": true,
    "detailed_logs": true
  },
  "thresholds": {
    "threat_score": 5,
    "suspicious_permissions": 3,
    "network_connections": 10
  }
}
EOF

print_success "Analysis configuration created"


cat > "workspace_status.sh" << 'EOF'



GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}                 APK Analysis Workspace Status                  ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"

echo -e "${BLUE}📁 Directory Structure:${NC}"
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

echo -e "\n${BLUE}📊 Current Status:${NC}"
echo "  APK Sample: $([ -f "samples/apps.apk" ] && echo -e "${GREEN}✓ Present${NC}" || echo -e "${YELLOW}✗ Missing${NC}")"
echo "  Tools: $([ -d "tools/frida" ] && echo -e "${GREEN}✓ Organized${NC}" || echo -e "${YELLOW}✗ Missing${NC}")"
echo "  Config: $([ -f "config/analysis_config.json" ] && echo -e "${GREEN}✓ Present${NC}" || echo -e "${YELLOW}✗ Missing${NC}")"

echo -e "\n${BLUE}📈 Analysis Sessions:${NC}"
if [[ -d "analysis_results/sessions" ]]; then
    session_count=$(find analysis_results/sessions -maxdepth 1 -type d -name "session_*" | wc -l)
    echo "  Total Sessions: $session_count"
    if [[ $session_count -gt 0 ]]; then
        echo "  Latest: $(ls -1t analysis_results/sessions/session_* 2>/dev/null | head -1 | xargs basename)"
    fi
else
    echo "  No sessions found"
fi

echo -e "\n${BLUE}🔧 Available Tools:${NC}"
echo "  ./run_organized_analysis.sh  - Run complete analysis"
echo "  ./workspace_status.sh        - Show this status"
echo "  ./cleanup.sh                 - Clean temporary files"

echo -e "\n${BLUE}📝 Recent Reports:${NC}"
if [[ -d "analysis_results/reports" ]]; then
    find analysis_results/reports -name "*.json" -o -name "*.txt" | head -5 | sed 's/^/  /'
fi
EOF

chmod +x "workspace_status.sh"
print_success "Workspace status script created"


print_status "Updating .gitignore..."

cat > ".gitignore" << 'EOF'

__pycache__/
*.py[cod]
*.pyo
*.pyd
*.egg-info/
.eggs/
.pytest_cache/
.mypy_cache/


.env
.venv/
venv/


.DS_Store
*.swp
.idea/
.vscode/


*.log
*.tmp
*.bak
logs/
temp/


analysis_results/sessions/*/
analysis_results/archive/
!analysis_results/archive/.gitkeep


comprehensive_analysis_*/
static_analysis_output/
analysis_output/


samples/backup/
!samples/backup/.gitkeep
EOF


touch analysis_results/archive/.gitkeep
touch samples/backup/.gitkeep

print_success ".gitignore updated"


print_header "Reorganization Summary"

echo -e "${GREEN}✓ Workspace successfully reorganized!${NC}\n"

echo -e "${BLUE}Key Improvements:${NC}"
echo "  • Organized directory structure with clear separation"
echo "  • Consolidated all analysis results in analysis_results/"
echo "  • Archived old analysis outputs"
echo "  • Organized tools by type (frida, python, scripts)"
echo "  • Created session-based analysis tracking"
echo "  • Added configuration management"
echo "  • Improved logging and reporting structure"

echo -e "\n${BLUE}Quick Start:${NC}"
echo "  1. Run: ./workspace_status.sh (check current status)"
echo "  2. Run: ./run_organized_analysis.sh (perform analysis)"
echo "  3. View: analysis_results/sessions/latest/ (see results)"

echo -e "\n${BLUE}Next Steps:${NC}"
echo "  • Review the new directory structure"
echo "  • Test the organized analysis runner"
echo "  • Customize config/analysis_config.json as needed"
echo "  • Use session-based analysis for better tracking"

print_success "Reorganization completed at $(date)"


echo -e "\n${CYAN}Running workspace status check...${NC}"
./workspace_status.sh
