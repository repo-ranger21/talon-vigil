#!/bin/bash
# OWASP ZAP Security Testing Script for TalonVigil
# This script performs automated security testing using OWASP ZAP

set -e

# Configuration
ZAP_PORT=${ZAP_PORT:-8080}
TARGET_URL=${TARGET_URL:-http://localhost:5000}
ZAP_API_KEY=${ZAP_API_KEY:-development-key-only}
REPORT_DIR="security_reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create reports directory
mkdir -p "$REPORT_DIR"

log_info "Starting OWASP ZAP security scan for TalonVigil"
log_info "Target URL: $TARGET_URL"

# Check if ZAP is running
if ! curl -s "http://localhost:$ZAP_PORT" > /dev/null; then
    log_error "OWASP ZAP is not running on port $ZAP_PORT"
    log_info "Starting ZAP daemon..."
    
    # Start ZAP in daemon mode
    if command -v zap.sh > /dev/null; then
        zap.sh -daemon -port "$ZAP_PORT" -config api.key="$ZAP_API_KEY" &
        ZAP_PID=$!
        sleep 30  # Wait for ZAP to start
    else
        log_error "OWASP ZAP not found. Please install ZAP or run it manually."
        exit 1
    fi
fi

# ZAP API base URL
ZAP_API="http://localhost:$ZAP_PORT"

# Function to call ZAP API
zap_api() {
    local endpoint="$1"
    local method="${2:-GET}"
    local data="${3:-}"
    
    if [ "$method" = "POST" ] && [ -n "$data" ]; then
        curl -s -X POST "$ZAP_API/JSON/$endpoint" \
            -H "Content-Type: application/json" \
            -d "$data"
    else
        curl -s "$ZAP_API/JSON/$endpoint"
    fi
}

# Configure ZAP for TalonVigil specific testing
log_info "Configuring ZAP for TalonVigil testing..."

# Set up authentication if needed
zap_api "authentication/action/setAuthenticationMethod/" "POST" \
    '{"contextId":"0","authMethodName":"httpAuthentication","authMethodConfigParams":"hostname=localhost&port=5000&realm="}'

# Configure session management
zap_api "sessionManagement/action/setSessionManagementMethod/" "POST" \
    '{"contextId":"0","methodName":"cookieBasedSessionManagement"}'

# Spider the application
log_info "Starting spider scan..."
SPIDER_ID=$(zap_api "spider/action/scan/" "POST" '{"url":"'$TARGET_URL'","maxChildren":"10","recurse":"true"}' | jq -r '.scan')

# Wait for spider to complete
while true; do
    SPIDER_STATUS=$(zap_api "spider/view/status/" | jq -r '.status')
    if [ "$SPIDER_STATUS" = "100" ]; then
        break
    fi
    log_info "Spider progress: $SPIDER_STATUS%"
    sleep 5
done

log_info "Spider scan completed"

# Active security scan
log_info "Starting active security scan..."
ASCAN_ID=$(zap_api "ascan/action/scan/" "POST" '{"url":"'$TARGET_URL'","recurse":"true","inScopeOnly":"false"}' | jq -r '.scan')

# Wait for active scan to complete
while true; do
    ASCAN_STATUS=$(zap_api "ascan/view/status/" | jq -r '.status')
    if [ "$ASCAN_STATUS" = "100" ]; then
        break
    fi
    log_info "Active scan progress: $ASCAN_STATUS%"
    sleep 10
done

log_info "Active security scan completed"

# Generate reports
log_info "Generating security reports..."

# HTML Report
zap_api "core/other/htmlreport/" > "$REPORT_DIR/zap_report_$TIMESTAMP.html"

# XML Report
zap_api "core/other/xmlreport/" > "$REPORT_DIR/zap_report_$TIMESTAMP.xml"

# JSON Report
zap_api "core/view/alerts/" > "$REPORT_DIR/zap_alerts_$TIMESTAMP.json"

# High-level summary
ALERTS=$(zap_api "core/view/numberOfAlerts/" | jq -r '.numberOfAlerts')
HIGH_ALERTS=$(zap_api "core/view/numberOfAlerts/High/" | jq -r '.numberOfAlerts')
MEDIUM_ALERTS=$(zap_api "core/view/numberOfAlerts/Medium/" | jq -r '.numberOfAlerts')
LOW_ALERTS=$(zap_api "core/view/numberOfAlerts/Low/" | jq -r '.numberOfAlerts')

log_info "Security Scan Summary:"
echo "  Total Alerts: $ALERTS"
echo "  High Risk: $HIGH_ALERTS"
echo "  Medium Risk: $MEDIUM_ALERTS"
echo "  Low Risk: $LOW_ALERTS"

# Generate custom TalonVigil security report
cat > "$REPORT_DIR/talon_vigil_security_summary_$TIMESTAMP.md" << EOF
# TalonVigil Security Scan Report

**Scan Date:** $(date)
**Target:** $TARGET_URL
**Scanner:** OWASP ZAP

## Summary

- **Total Alerts:** $ALERTS
- **High Risk:** $HIGH_ALERTS
- **Medium Risk:** $MEDIUM_ALERTS
- **Low Risk:** $LOW_ALERTS

## Risk Assessment

EOF

if [ "$HIGH_ALERTS" -gt 0 ]; then
    echo "🔴 **CRITICAL:** High-risk vulnerabilities detected. Immediate attention required." >> "$REPORT_DIR/talon_vigil_security_summary_$TIMESTAMP.md"
elif [ "$MEDIUM_ALERTS" -gt 5 ]; then
    echo "🟡 **WARNING:** Multiple medium-risk issues detected. Review recommended." >> "$REPORT_DIR/talon_vigil_security_summary_$TIMESTAMP.md"
else
    echo "🟢 **GOOD:** No critical security issues detected." >> "$REPORT_DIR/talon_vigil_security_summary_$TIMESTAMP.md"
fi

# Stop ZAP if we started it
if [ -n "${ZAP_PID:-}" ]; then
    log_info "Stopping ZAP daemon..."
    kill $ZAP_PID
fi

log_info "Security scan completed. Reports saved to $REPORT_DIR/"

# Set exit code based on findings
if [ "$HIGH_ALERTS" -gt 0 ]; then
    log_error "Security scan failed: High-risk vulnerabilities detected"
    exit 1
elif [ "$MEDIUM_ALERTS" -gt 10 ]; then
    log_warn "Security scan warning: Multiple medium-risk issues detected"
    exit 1
else
    log_info "Security scan passed"
    exit 0
fi
