#!/usr/bin/env zsh



set -euo pipefail
setopt null_glob

echo "🔬 Advanced Malware Analysis Suite - Setup & Runner"
echo "=================================================="


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color


print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}


if [[ ! -f "apps.apk" ]]; then
    print_error "Please run this script from the APK analysis directory"
    exit 1
fi

APK_PATH="$(pwd)/apps.apk"
PACKAGE_NAME="com.xnotice.app"


check_prerequisites() {
    local mode=${1:-"all"}
    print_status "Checking prerequisites (mode: $mode)..."
    
    local missing_tools=()
    
    if [[ "$mode" == "static" ]]; then

        for tool in python3; do
            if ! command -v $tool >/dev/null 2>&1; then
                missing_tools+=($tool)
            fi
        done
    else

        for tool in adb frida frida-ps python3 keytool; do
            if ! command -v $tool >/dev/null 2>&1; then
                missing_tools+=($tool)
            fi
        done
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        print_status "Install missing tools and try again"
        exit 1
    fi
    

    if ! command -v aapt >/dev/null 2>&1; then
        print_warning "aapt not found - Android SDK build-tools not in PATH"
        print_status "Some static analysis features may be limited"
    fi
    
    print_success "All required tools found"
}


check_device() {
    print_status "Checking Android device connection..."
    
    local devices=$(adb devices | grep -v "List of devices" | grep "device$" | wc -l)
    
    if [[ $devices -eq 0 ]]; then
        print_error "No Android device connected"
        print_status "Please connect an Android device or start an emulator"
        exit 1
    fi
    
    print_success "Android device connected"
    

    print_status "Checking Frida server..."
    if ! frida-ps -U >/dev/null 2>&1; then
        print_warning "Frida server not responding"
        print_status "Starting frida-server..."
        

        local FRIDA_SERVER=""
        if ls binaries/frida-server-* >/dev/null 2>&1; then
            FRIDA_SERVER=$(ls -1 binaries/frida-server-* 2>/dev/null | head -n1)
        fi
        if [[ -n "$FRIDA_SERVER" ]]; then
            adb push "$FRIDA_SERVER" /data/local/tmp/frida-server 2>/dev/null || true
        else
            print_warning "No frida-server binary found in ./binaries; attempting wildcard push"
            adb push frida-server-* /data/local/tmp/frida-server 2>/dev/null || true
        fi
        adb shell "chmod 755 /data/local/tmp/frida-server" 2>/dev/null || true
        adb shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &" 2>/dev/null || true
        
        sleep 3
        
        if frida-ps -U >/dev/null 2>&1; then
            print_success "Frida server started"
        else
            print_error "Failed to start Frida server"
            exit 1
        fi
    else
        print_success "Frida server is running"
    fi
}


ensure_app_installed() {
    print_status "Ensuring target app ($PACKAGE_NAME) is installed..."
    if adb shell pm list packages | grep -q "$PACKAGE_NAME"; then
        print_success "Package is already installed"
    else
        print_status "Installing APK: $APK_PATH"
        adb install -r -d "$APK_PATH" >/dev/null 2>&1 || {
            print_error "Failed to install APK on device"
            exit 1
        }
        print_success "APK installed"
    fi
}


run_basic_analysis() {
    print_status "Running basic analysis with existing tools..."
    

    print_status "Starting enhanced attribution collector..."
    local FRIDA_SCRIPT="tools/frida_scripts/attribution_collector.js"
    if [[ ! -f "$FRIDA_SCRIPT" ]]; then
        print_warning "Frida script not found at $FRIDA_SCRIPT; skipping Frida step"
    else

        frida -U -f "$PACKAGE_NAME" -l "$FRIDA_SCRIPT" --no-pause &
        FRIDA_PID=$!
        sleep 65

        if kill -0 $FRIDA_PID 2>/dev/null; then
            kill $FRIDA_PID 2>/dev/null || true
        fi
    fi
    

    if [[ -f "enhanced_data_extractor.py" ]]; then
        print_status "Generating static report via enhanced_data_extractor.py"
        python3 enhanced_data_extractor.py "$APK_PATH" "$PACKAGE_NAME" || print_warning "Static extractor encountered an issue"
    fi
    
    print_success "Basic analysis completed"
}


run_comprehensive_analysis() {
    print_status "Running comprehensive analysis with advanced tools..."
    

    local ADV_ORCH="tools/python_scripts/advanced_orchestrator.py"
    if [[ ! -f "$ADV_ORCH" ]]; then
        print_error "Advanced orchestrator not found at $ADV_ORCH"
        print_status "Run setup first or use basic analysis"
        exit 1
    fi
    
    print_status "Starting advanced orchestrator..."
    python3 "$ADV_ORCH" "$APK_PATH" "$PACKAGE_NAME"
    

    if [[ -f "enhanced_data_extractor.py" ]]; then
        print_status "Generating static report via enhanced_data_extractor.py"
        python3 enhanced_data_extractor.py "$APK_PATH" "$PACKAGE_NAME" || print_warning "Static extractor encountered an issue"
    fi
    
    print_success "Comprehensive analysis completed"
}


analyze_results() {
    print_status "Analyzing existing results..."
    

    local analysis_files=$(find . -name "*.json" -o -name "*analysis*" -o -name "*iocs*" | wc -l)
    
    if [[ $analysis_files -eq 0 ]]; then
        print_warning "No analysis results found"
        return 1
    fi
    
    print_success "Found $analysis_files analysis files"
    

    echo ""
    echo "📊 Analysis Results Summary:"
    echo "=========================="
    

    local ioc_files=(iocs_*.txt(N))
    if (( ${#ioc_files[@]} > 0 )); then
        echo "🎯 IOC Files:"
        ls -la -- "${ioc_files[@]}" | awk '{print "   " $9 " (" $5 " bytes)"}'
    fi
    

    local json_reports=(enhanced_attribution_*.json(N))
    if (( ${#json_reports[@]} > 0 )); then
        echo "📋 JSON Reports:"
        ls -la -- "${json_reports[@]}" | awk '{print "   " $9 " (" $5 " bytes)"}'
    fi
    

    local text_reports=(*analysis*.txt(N) *report*.txt(N))
    if (( ${#text_reports[@]} > 0 )); then
        echo "📄 Text Reports:"
        ls -la -- "${text_reports[@]}" 2>/dev/null | awk '{print "   " $9 " (" $5 " bytes)"}'
    fi
    

    local adv_dirs=(advanced_analysis_*(/N))
    if (( ${#adv_dirs[@]} > 0 )); then
        echo "🔬 Advanced Analysis:"
        ls -la -d -- "${adv_dirs[@]}" | awk '{print "   " $9 "/"}'
    fi
    

    local comp_dirs=(comprehensive_analysis_*(/N))
    if (( ${#comp_dirs[@]} > 0 )); then
        echo "🧩 Comprehensive Extractor Outputs:"
        ls -la -d -- "${comp_dirs[@]}" | awk '{print "   " $9 "/"}'
    fi
    
    echo ""
}


generate_report() {
    print_status "Generating consolidated report..."
    
    local report_file="consolidated_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
MALWARE ANALYSIS CONSOLIDATED REPORT
===================================
Generated: $(date)
Target APK: $APK_PATH
Package: $PACKAGE_NAME

ANALYSIS OVERVIEW:
-----------------
EOF


    if [[ -f "$APK_PATH" ]]; then
        echo "APK Size: $(stat -f%z "$APK_PATH" 2>/dev/null || stat -c%s "$APK_PATH" 2>/dev/null || echo "unknown") bytes" >> "$report_file"
        echo "APK MD5: $(md5sum "$APK_PATH" 2>/dev/null | cut -d' ' -f1 || md5 "$APK_PATH" 2>/dev/null | cut -d'=' -f2 | tr -d ' ' || echo "unknown")" >> "$report_file"
    fi
    
    echo "" >> "$report_file"
    

    local comp_dirs=(comprehensive_analysis_*(/N))
    local latest_comp_dir=""
    if (( ${#comp_dirs[@]} > 0 )); then
        latest_comp_dir=$(ls -dt -- "${comp_dirs[@]}" | head -n1)
        if [[ -n "$latest_comp_dir" && -f "$latest_comp_dir/analysis_report.txt" ]]; then
            echo "STATIC ANALYSIS RESULTS (from $latest_comp_dir):" >> "$report_file"
            echo "----------------------------------------------" >> "$report_file"
            cat "$latest_comp_dir/analysis_report.txt" >> "$report_file"
            echo "" >> "$report_file"
        fi
    fi
    

    if ls iocs_*.txt >/dev/null 2>&1; then
        echo "INDICATORS OF COMPROMISE:" >> "$report_file"
        echo "-----------------------" >> "$report_file"
        for ioc_file in iocs_*.txt; do
            echo "From $ioc_file:" >> "$report_file"
            cat "$ioc_file" >> "$report_file"
            echo "" >> "$report_file"
        done
    fi
    

    local adv_dirs=(advanced_analysis_*(/N))
    if (( ${#adv_dirs[@]} > 0 )); then
        echo "ADVANCED ANALYSIS SUMMARY:" >> "$report_file"
        echo "-------------------------" >> "$report_file"
        for dir in "${adv_dirs[@]}"; do
            if [[ -f "$dir/analysis_summary_report.txt" ]]; then
                echo "From $dir:" >> "$report_file"
                cat "$dir/analysis_summary_report.txt" >> "$report_file"
                echo "" >> "$report_file"
            fi
        done
    fi
    

    local comp_dirs2=(comprehensive_analysis_*(/N))
    if (( ${#comp_dirs2[@]} > 0 )); then
        echo "COMPREHENSIVE EXTRACTOR REPORTS:" >> "$report_file"
        echo "--------------------------------" >> "$report_file"
        for dir in "${comp_dirs2[@]}"; do
            if [[ -f "$dir/comprehensive_report.json" ]]; then
                echo "- $dir/comprehensive_report.json" >> "$report_file"
            fi
        done
        echo "" >> "$report_file"
    fi
    
    print_success "Consolidated report generated: $report_file"
}


cleanup() {
    print_status "Cleaning up old analysis results..."
    

    local old_json=(enhanced_attribution_*.json(N))
    if (( ${#old_json[@]} > 0 )); then
        ls -t -- "${old_json[@]}" | tail -n +4 | xargs rm -f 2>/dev/null || true
    fi
    
    local old_iocs=(iocs_*.txt(N))
    if (( ${#old_iocs[@]} > 0 )); then
        ls -t -- "${old_iocs[@]}" | tail -n +4 | xargs rm -f 2>/dev/null || true
    fi
    

    local old_adv=(advanced_analysis_*(/N))
    if (( ${#old_adv[@]} > 0 )); then
        ls -t -d -- "${old_adv[@]}" | tail -n +3 | xargs rm -rf 2>/dev/null || true
    fi
    

    local old_comp=(comprehensive_analysis_*(/N))
    if (( ${#old_comp[@]} > 0 )); then
        ls -t -d -- "${old_comp[@]}" | tail -n +4 | xargs rm -rf 2>/dev/null || true
    fi
    
    print_success "Cleanup completed"
}


show_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  basic       - Run basic malware analysis (existing tools)"
    echo "  advanced    - Run comprehensive analysis (all tools)"
    echo "  static      - Run static analysis only"
    echo "  results     - Analyze existing results"
    echo "  report      - Generate consolidated report"
    echo "  cleanup     - Clean up old analysis files"
    echo "  setup       - Check prerequisites and setup"
    echo "  help        - Show this help message"
    echo ""
    echo "If no command is specified, 'basic' analysis will be run."
}


main() {
    local command=${1:-"basic"}
    
    case $command in
        "setup")
            check_prerequisites
            check_device
            print_success "Setup completed successfully"
            ;;
        "basic")
            check_prerequisites
            check_device
            ensure_app_installed
            run_basic_analysis
            analyze_results
            ;;
        "advanced")
            check_prerequisites
            check_device
            ensure_app_installed
            run_comprehensive_analysis
            analyze_results
            ;;
        "static")
            check_prerequisites static
            local ADV_STATIC="tools/python_scripts/advanced_static_analyzer.py"
            if [[ -f "$ADV_STATIC" ]]; then
                print_status "Running advanced static analysis..."
                python3 "$ADV_STATIC" "$APK_PATH" || print_warning "Advanced static analyzer encountered an issue"
            else
                if [[ -f "enhanced_data_extractor.py" ]]; then
                    print_status "Running minimal static extractor..."
                    python3 enhanced_data_extractor.py "$APK_PATH" "$PACKAGE_NAME" || print_warning "Static extractor encountered an issue"
                else
                    print_warning "No static analyzer found, falling back to aapt badging"

                    if command -v aapt >/dev/null 2>&1; then
                        aapt dump badging "$APK_PATH"
                    fi
                fi
            fi
            ;;
        "results")
            analyze_results
            ;;
        "report")
            generate_report
            ;;
        "cleanup")
            cleanup
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            print_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}


main "$@"
