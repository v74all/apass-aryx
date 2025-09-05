#!/usr/bin/env zsh

set -euo pipefail

setopt null_glob

root_dir="$(pwd)"


GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

echo -e "${BLUE}🧹 Enhanced Workspace Cleanup${NC}"
echo "================================"


print_status "Cleaning Python cache and compiled files..."
find "$root_dir" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$root_dir" -type f -name "*.pyc" -delete 2>/dev/null || true
find "$root_dir" -type f -name "*.pyo" -delete 2>/dev/null || true
find "$root_dir" -type f -name "*.pyd" -delete 2>/dev/null || true
print_success "Python cache cleaned"


print_status "Cleaning temporary files..."
if [[ -d "$root_dir/temp" ]]; then
    rm -rf "$root_dir/temp"/*
    print_success "Temporary files cleaned"
fi


print_status "Archiving old log files..."
if [[ -d "$root_dir/logs" ]]; then
    TS=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$root_dir/analysis_results/archive"
    

    find "$root_dir/logs" -name "*.log" -mtime +7 -type f > /tmp/old_logs_$$ 2>/dev/null || true
    if [[ -s /tmp/old_logs_$$ ]]; then
        tar -czf "$root_dir/analysis_results/archive/old_logs_${TS}.tgz" -T /tmp/old_logs_$$
        xargs rm -f < /tmp/old_logs_$$
        print_success "Old log files archived"
    else
        print_warning "No old log files to archive"
    fi
    rm -f /tmp/old_logs_$$
fi


print_status "Removing duplicate analysis reports..."
if [[ -d "$root_dir/analysis_results/reports" ]]; then

    cd "$root_dir/analysis_results/reports/json" 2>/dev/null || true
    if [[ $(ls -1 *.json 2>/dev/null | wc -l) -gt 5 ]]; then
        ls -1t *.json | tail -n +6 | xargs rm -f
        print_success "Old JSON reports cleaned"
    fi
    

    cd "$root_dir/analysis_results/reports/text" 2>/dev/null || true
    if [[ $(ls -1 *.txt 2>/dev/null | wc -l) -gt 5 ]]; then
        ls -1t *.txt | tail -n +6 | xargs rm -f
        print_success "Old text reports cleaned"
    fi
    
    cd "$root_dir"
fi


print_status "Cleaning old analysis sessions..."
if [[ -d "$root_dir/analysis_results/sessions" ]]; then
    cd "$root_dir/analysis_results/sessions"
    session_count=$(ls -1d session_* 2>/dev/null | wc -l)
    if [[ $session_count -gt 3 ]]; then
        ls -1td session_* | tail -n +4 | xargs rm -rf
        print_success "Old analysis sessions cleaned (kept latest 3)"
    else
        print_warning "No old sessions to clean (found $session_count sessions)"
    fi
    cd "$root_dir"
fi


print_status "Optimizing sample storage..."
if [[ -d "$root_dir/samples/backup" ]]; then

    cd "$root_dir/samples/backup"
    backup_count=$(ls -1 *.apk 2>/dev/null | wc -l)
    if [[ $backup_count -gt 3 ]]; then
        ls -1t *.apk | tail -n +4 | xargs rm -f
        print_success "Old APK backups cleaned (kept latest 3)"
    fi
    cd "$root_dir"
fi


print_status "Verifying main APK sample..."
if [[ -f "$root_dir/samples/apps.apk" ]]; then
    if [[ -L "$root_dir/samples/apps.apk" ]]; then

        if [[ -f "$root_dir/apps.apk" ]]; then
            print_success "Main APK sample verified (symlinked)"
        else
            print_error "Broken symlink detected - fixing..."
            rm -f "$root_dir/samples/apps.apk"
            if [[ -f "$root_dir/apps.apk" ]]; then
                ln -sf "$(realpath $root_dir/apps.apk)" "$root_dir/samples/apps.apk"
                print_success "Symlink repaired"
            fi
        fi
    else
        print_success "Main APK sample verified (file)"
    fi
else
    print_warning "Main APK sample not found in samples directory"
fi


print_status "Removing empty directories..."
find "$root_dir" -type d -empty -delete 2>/dev/null || true
print_success "Empty directories removed"


print_status "Setting secure file permissions..."

find "$root_dir" -name "*.sh" -type f -exec chmod +x {} \; 2>/dev/null || true

find "$root_dir" -name "*.json" -type f -exec chmod 644 {} \; 2>/dev/null || true
find "$root_dir" -name "*.py" -type f -exec chmod 644 {} \; 2>/dev/null || true
print_success "File permissions secured"


print_status "Generating cleanup summary..."
cat > "$root_dir/analysis_results/reports/text/cleanup_summary_$(date +%Y%m%d_%H%M%S).txt" << EOF
APK Analysis Workspace Cleanup Summary
=====================================
Cleanup performed: $(date)

Directory Structure Status:
- samples/: $(find samples -type f | wc -l) files
- analysis_results/: $(find analysis_results -type f | wc -l) files
- tools/: $(find tools -type f | wc -l) files
- config/: $(find config -type f | wc -l) files
- logs/: $(find logs -type f 2>/dev/null | wc -l) files

Storage Usage:
- Total workspace size: $(du -sh . | cut -f1)
- Analysis results size: $(du -sh analysis_results | cut -f1)
- Tools size: $(du -sh tools | cut -f1)

Recent Analysis Reports:
$(ls -la analysis_results/reports/json/*.json 2>/dev/null | tail -3 || echo "No JSON reports found")

Available Commands:
- ./workspace_status.sh - Check workspace status
- ./run_organized_analysis.sh - Run new analysis
- python3 tools/python/analysis_dashboard.py - Generate dashboard
- ./cleanup.sh - Run this cleanup again

EOF

print_success "Cleanup summary generated"


print_status "Final workspace status..."
total_files=$(find "$root_dir" -type f | wc -l)
total_size=$(du -sh "$root_dir" | cut -f1)

echo -e "\n${GREEN}✓ Cleanup completed successfully!${NC}"
echo -e "${BLUE}📊 Workspace Statistics:${NC}"
echo -e "  Total files: $total_files"
echo -e "  Total size: $total_size"
echo -e "  Structure: Organized ✓"
echo -e "  Security: Permissions set ✓"
echo -e "  Optimization: Cache cleared ✓"

echo -e "\n${BLUE}🎯 Next Steps:${NC}"
echo -e "  1. Run: ./workspace_status.sh"
echo -e "  2. View: analysis_results/reports/html/latest_dashboard.html"
echo -e "  3. Analyze: ./run_organized_analysis.sh"

print_success "Enhanced cleanup completed at $(date)"
