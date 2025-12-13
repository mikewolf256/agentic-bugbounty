#!/bin/bash
#
# Client Security Assessment Runner
# Usage: ./scripts/run_client_assessment.sh CLIENT_NAME [PROFILE]
#
# This script runs a complete security assessment for a client and generates reports.
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SCOPES_DIR="${PROJECT_ROOT}/data/scopes"
OUTPUT_BASE="${PROJECT_ROOT}/data/output/assessments"
REPORTS_DIR="${PROJECT_ROOT}/reports"
DEFAULT_PROFILE="full"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_usage() {
    echo "Usage: $0 CLIENT_NAME [PROFILE]"
    echo ""
    echo "Arguments:"
    echo "  CLIENT_NAME   Name of the client (used for scope file and output)"
    echo "  PROFILE       Scan profile to use (default: full)"
    echo ""
    echo "Prerequisites:"
    echo "  - Scope file exists at: data/scopes/CLIENT_NAME.json"
    echo "  - MCP server is running (or will be started)"
    echo ""
    echo "Examples:"
    echo "  $0 acme_corp"
    echo "  $0 acme_corp client-assessment"
    echo ""
    echo "Available profiles:"
    ls -1 "${PROJECT_ROOT}/profiles/"*.yaml 2>/dev/null | xargs -n1 basename | sed 's/.yaml$//' || echo "  (none found)"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check scope file exists
    SCOPE_FILE="${SCOPES_DIR}/${CLIENT_NAME}.json"
    if [ ! -f "$SCOPE_FILE" ]; then
        log_error "Scope file not found: $SCOPE_FILE"
        echo ""
        echo "Create a scope file with the client's targets:"
        echo ""
        echo "cat > $SCOPE_FILE << 'EOF'"
        echo '{'
        echo '  "program_name": "'${CLIENT_NAME}'",'
        echo '  "primary_targets": ['
        echo '    "https://example.com",'
        echo '    "https://api.example.com"'
        echo '  ],'
        echo '  "rules": {'
        echo '    "rate_limit": "10 req/sec",'
        echo '    "safe_harbor": true'
        echo '  }'
        echo '}'
        echo 'EOF'
        exit 1
    fi
    
    # Check OpenAI API key
    if [ -z "$OPENAI_API_KEY" ]; then
        log_warning "OPENAI_API_KEY not set. AI triage will fail."
    fi
    
    # Check MCP server
    if ! curl -s http://localhost:8000/health > /dev/null 2>&1; then
        log_warning "MCP server not responding. Starting it..."
        cd "$PROJECT_ROOT"
        python mcp_server.py &
        MCP_PID=$!
        sleep 5
        
        if ! curl -s http://localhost:8000/health > /dev/null 2>&1; then
            log_error "Failed to start MCP server"
            exit 1
        fi
        log_success "MCP server started (PID: $MCP_PID)"
    else
        log_success "MCP server is running"
    fi
    
    log_success "Prerequisites check passed"
}

run_assessment() {
    log_info "Starting assessment for: $CLIENT_NAME"
    log_info "Scope file: $SCOPE_FILE"
    log_info "Profile: $PROFILE"
    log_info "Output directory: $OUTPUT_DIR"
    
    echo ""
    echo "=========================================="
    echo " CLIENT ASSESSMENT: $CLIENT_NAME"
    echo "=========================================="
    echo ""
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Copy scope file to output for reference
    cp "$SCOPE_FILE" "$OUTPUT_DIR/scope.json"
    
    # Record start time
    START_TIME=$(date +%s)
    echo "Start time: $(date)" > "$OUTPUT_DIR/assessment_log.txt"
    
    # Run the assessment
    cd "$PROJECT_ROOT"
    
    log_info "Phase 1: Running full scan..."
    python agentic_runner.py \
        --mode full-scan \
        --scope_file "$SCOPE_FILE" \
        --profile "$PROFILE" \
        --output-dir "$OUTPUT_DIR" \
        2>&1 | tee -a "$OUTPUT_DIR/assessment_log.txt"
    
    # Check for findings
    FINDINGS_COUNT=$(find "$OUTPUT_DIR" -name "triage_*.json" -exec cat {} \; 2>/dev/null | python3 -c "import sys,json; data=[]; [data.extend(json.load(open(f)) if isinstance(json.load(open(f)),list) else []) for f in sys.argv[1:]]; print(len(data))" "$OUTPUT_DIR"/triage_*.json 2>/dev/null || echo "0")
    
    log_info "Phase 2: Assessment complete. Found $FINDINGS_COUNT triaged findings."
    
    # Record end time
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    echo "End time: $(date)" >> "$OUTPUT_DIR/assessment_log.txt"
    echo "Duration: $DURATION seconds" >> "$OUTPUT_DIR/assessment_log.txt"
    echo "Findings count: $FINDINGS_COUNT" >> "$OUTPUT_DIR/assessment_log.txt"
    
    log_success "Assessment complete in $DURATION seconds"
}

generate_reports() {
    log_info "Phase 3: Generating reports..."
    
    # Create reports directory
    mkdir -p "$CLIENT_REPORTS_DIR"
    
    # Find all triage files
    TRIAGE_FILES=$(find "$OUTPUT_DIR" -name "triage_*.json" 2>/dev/null | tr '\n' ' ')
    
    if [ -z "$TRIAGE_FILES" ]; then
        log_warning "No triage files found. Generating placeholder report."
        echo "# Assessment Complete - No High-Impact Findings" > "$CLIENT_REPORTS_DIR/report.md"
        echo "" >> "$CLIENT_REPORTS_DIR/report.md"
        echo "Assessment Date: $(date)" >> "$CLIENT_REPORTS_DIR/report.md"
        echo "Client: $CLIENT_NAME" >> "$CLIENT_REPORTS_DIR/report.md"
        echo "" >> "$CLIENT_REPORTS_DIR/report.md"
        echo "No high-impact vulnerabilities were identified during this assessment." >> "$CLIENT_REPORTS_DIR/report.md"
        return
    fi
    
    # Get target from scope file
    TARGET=$(python3 -c "import json; print(json.load(open('$SCOPE_FILE')).get('program_name', '$CLIENT_NAME'))")
    
    # Generate markdown report (always works)
    log_info "Generating markdown report..."
    python tools/report_generator.py \
        --findings $TRIAGE_FILES \
        --target "$TARGET" \
        --format markdown \
        --type full \
        --output "$CLIENT_REPORTS_DIR/${CLIENT_NAME}_report.md" \
        2>&1 | tee -a "$OUTPUT_DIR/assessment_log.txt"
    
    # Try PDF if available
    log_info "Attempting PDF generation..."
    python tools/report_generator.py \
        --findings $TRIAGE_FILES \
        --target "$TARGET" \
        --format pdf \
        --type executive \
        --output "$CLIENT_REPORTS_DIR/${CLIENT_NAME}_executive.pdf" \
        2>&1 | tee -a "$OUTPUT_DIR/assessment_log.txt" || log_warning "PDF generation failed (reportlab may not be installed)"
    
    # Copy raw findings
    log_info "Copying raw findings..."
    cat $TRIAGE_FILES > "$CLIENT_REPORTS_DIR/${CLIENT_NAME}_findings.json" 2>/dev/null || true
    
    log_success "Reports generated in: $CLIENT_REPORTS_DIR"
}

show_summary() {
    echo ""
    echo "=========================================="
    echo " ASSESSMENT SUMMARY"
    echo "=========================================="
    echo ""
    echo "Client: $CLIENT_NAME"
    echo "Date: $(date)"
    echo ""
    echo "Output Directory: $OUTPUT_DIR"
    echo "Reports Directory: $CLIENT_REPORTS_DIR"
    echo ""
    echo "Generated Files:"
    ls -la "$CLIENT_REPORTS_DIR/" 2>/dev/null || echo "(none)"
    echo ""
    echo "Next Steps:"
    echo "1. Review findings: python tools/validation_cli.py list"
    echo "2. Validate critical findings manually"
    echo "3. Review and polish reports in: $CLIENT_REPORTS_DIR/"
    echo "4. Schedule findings review call with client"
    echo ""
    log_success "Assessment workflow complete!"
}

# Main execution
main() {
    # Parse arguments
    if [ $# -lt 1 ]; then
        show_usage
        exit 1
    fi
    
    CLIENT_NAME="$1"
    PROFILE="${2:-$DEFAULT_PROFILE}"
    
    # Set up paths
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTPUT_DIR="${OUTPUT_BASE}/${CLIENT_NAME}_${TIMESTAMP}"
    CLIENT_REPORTS_DIR="${REPORTS_DIR}/${CLIENT_NAME}"
    
    # Run workflow
    check_prerequisites
    run_assessment
    generate_reports
    show_summary
}

# Run main
main "$@"

