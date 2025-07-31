#!/bin/bash
# Comprehensive Security Testing Suite for TalonVigil
# This script runs all security tests including unit tests, static analysis, and dependency checks

set -e

# Configuration
REPORT_DIR="security_reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PYTHON_ENV=${PYTHON_ENV:-venv}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Create reports directory
mkdir -p "$REPORT_DIR"

log_info "Starting comprehensive security testing for TalonVigil"

# Activate virtual environment if it exists
if [ -d "$PYTHON_ENV" ]; then
    log_info "Activating Python virtual environment: $PYTHON_ENV"
    source "$PYTHON_ENV/bin/activate"
fi

# Install testing dependencies if not present
log_step "1. Installing/updating security testing tools..."
pip install --quiet bandit safety semgrep pytest pytest-cov pytest-xdist black flake8 mypy || true

# Step 1: Static Code Analysis with Bandit
log_step "2. Running Bandit security static analysis..."
bandit -r . -f json -o "$REPORT_DIR/bandit_report_$TIMESTAMP.json" -ll || BANDIT_EXIT=$?
bandit -r . -f txt -o "$REPORT_DIR/bandit_report_$TIMESTAMP.txt" -ll || true

# Step 2: Dependency Security Check with Safety
log_step "3. Checking dependencies for known vulnerabilities..."
safety check --json --output "$REPORT_DIR/safety_report_$TIMESTAMP.json" || SAFETY_EXIT=$?
safety check --output "$REPORT_DIR/safety_report_$TIMESTAMP.txt" || true

# Step 3: Advanced static analysis with Semgrep
log_step "4. Running Semgrep advanced security analysis..."
if command -v semgrep > /dev/null; then
    semgrep --config=auto --json --output="$REPORT_DIR/semgrep_report_$TIMESTAMP.json" . || SEMGREP_EXIT=$?
    semgrep --config=auto --output="$REPORT_DIR/semgrep_report_$TIMESTAMP.txt" . || true
else
    log_warn "Semgrep not installed, skipping advanced static analysis"
fi

# Step 4: Code Quality Checks
log_step "5. Running code quality checks..."

# Black formatting check
black --check --diff . > "$REPORT_DIR/black_check_$TIMESTAMP.txt" 2>&1 || BLACK_EXIT=$?

# Flake8 style and complexity check
flake8 --output-file="$REPORT_DIR/flake8_report_$TIMESTAMP.txt" --max-line-length=88 --ignore=E203,W503 . || FLAKE8_EXIT=$?

# MyPy type checking
mypy --ignore-missing-imports --no-strict-optional . > "$REPORT_DIR/mypy_report_$TIMESTAMP.txt" 2>&1 || MYPY_EXIT=$?

# Step 5: Security Unit Tests
log_step "6. Running security-focused unit tests..."
if [ -f "test_security.py" ]; then
    pytest test_security.py -v --tb=short \
        --cov=. --cov-report=xml:"$REPORT_DIR/security_coverage_$TIMESTAMP.xml" \
        --cov-report=html:"$REPORT_DIR/security_coverage_html_$TIMESTAMP" \
        --junit-xml="$REPORT_DIR/security_tests_$TIMESTAMP.xml" \
        > "$REPORT_DIR/security_tests_$TIMESTAMP.txt" 2>&1 || PYTEST_EXIT=$?
else
    log_warn "No security test file found (test_security.py)"
fi

# Step 6: Custom TalonVigil Security Checks
log_step "7. Running TalonVigil-specific security checks..."

# Check for hardcoded secrets
log_info "Checking for hardcoded secrets..."
grep -r -i -E "(password|secret|key|token|api_key)" --include="*.py" . | \
    grep -v "# nosec" | grep -v "test_" | grep -v "__pycache__" > "$REPORT_DIR/potential_secrets_$TIMESTAMP.txt" || true

# Check for SQL injection patterns
log_info "Checking for potential SQL injection vulnerabilities..."
grep -r -E ".*\.execute\(.*%.*\)" --include="*.py" . > "$REPORT_DIR/sql_injection_check_$TIMESTAMP.txt" || true

# Check for XSS vulnerabilities
log_info "Checking for potential XSS vulnerabilities..."
grep -r -E "(render_template_string|Markup|safe)" --include="*.py" . > "$REPORT_DIR/xss_check_$TIMESTAMP.txt" || true

# Check for insecure configurations
log_info "Checking for insecure configurations..."
{
    echo "=== Checking for DEBUG=True in production ==="
    grep -r "DEBUG.*=.*True" --include="*.py" . || echo "No DEBUG=True found"
    
    echo -e "\n=== Checking for insecure random usage ==="
    grep -r "random\." --include="*.py" . | grep -v "secrets\." || echo "No insecure random usage found"
    
    echo -e "\n=== Checking for HTTP instead of HTTPS ==="
    grep -r "http://" --include="*.py" . || echo "No HTTP URLs found"
    
} > "$REPORT_DIR/config_security_check_$TIMESTAMP.txt"

# Step 7: Generate comprehensive report
log_step "8. Generating comprehensive security report..."

cat > "$REPORT_DIR/comprehensive_security_report_$TIMESTAMP.md" << EOF
# TalonVigil Comprehensive Security Report

**Report Generated:** $(date)
**Timestamp:** $TIMESTAMP

## Executive Summary

This report contains the results of comprehensive security testing for the TalonVigil cybersecurity platform.

## Test Results Summary

| Test Type | Status | Details |
|-----------|--------|---------|
| Bandit Static Analysis | $([ "${BANDIT_EXIT:-0}" -eq 0 ] && echo "✅ PASS" || echo "❌ FAIL") | See bandit_report_$TIMESTAMP.txt |
| Dependency Security | $([ "${SAFETY_EXIT:-0}" -eq 0 ] && echo "✅ PASS" || echo "❌ FAIL") | See safety_report_$TIMESTAMP.txt |
| Advanced Static Analysis | $([ "${SEMGREP_EXIT:-0}" -eq 0 ] && echo "✅ PASS" || echo "❌ FAIL") | See semgrep_report_$TIMESTAMP.txt |
| Code Formatting | $([ "${BLACK_EXIT:-0}" -eq 0 ] && echo "✅ PASS" || echo "❌ FAIL") | See black_check_$TIMESTAMP.txt |
| Style & Complexity | $([ "${FLAKE8_EXIT:-0}" -eq 0 ] && echo "✅ PASS" || echo "❌ FAIL") | See flake8_report_$TIMESTAMP.txt |
| Type Checking | $([ "${MYPY_EXIT:-0}" -eq 0 ] && echo "✅ PASS" || echo "❌ FAIL") | See mypy_report_$TIMESTAMP.txt |
| Security Unit Tests | $([ "${PYTEST_EXIT:-0}" -eq 0 ] && echo "✅ PASS" || echo "❌ FAIL") | See security_tests_$TIMESTAMP.txt |

## Security Findings

### High Priority Issues
$([ "${BANDIT_EXIT:-0}" -ne 0 ] && echo "- Bandit detected security issues" || echo "- No high priority issues detected")
$([ "${SAFETY_EXIT:-0}" -ne 0 ] && echo "- Vulnerable dependencies detected" || echo "")

### Medium Priority Issues
$([ "${SEMGREP_EXIT:-0}" -ne 0 ] && echo "- Semgrep detected potential security issues" || echo "- No medium priority issues detected")

### Code Quality Issues
$([ "${FLAKE8_EXIT:-0}" -ne 0 ] && echo "- Code style and complexity issues detected" || echo "- Code quality checks passed")
$([ "${BLACK_EXIT:-0}" -ne 0 ] && echo "- Code formatting issues detected" || echo "")
$([ "${MYPY_EXIT:-0}" -ne 0 ] && echo "- Type checking issues detected" || echo "")

## Recommendations

1. **Immediate Actions Required:**
   - Review and fix any high-severity security issues
   - Update vulnerable dependencies
   - Fix critical security unit test failures

2. **Medium-term Improvements:**
   - Address code quality and style issues
   - Improve type annotations
   - Enhance security test coverage

3. **Long-term Security Enhancements:**
   - Implement additional security controls
   - Regular security testing automation
   - Security training for development team

## Files Generated

- bandit_report_$TIMESTAMP.json/txt - Static security analysis
- safety_report_$TIMESTAMP.json/txt - Dependency vulnerability scan
- semgrep_report_$TIMESTAMP.json/txt - Advanced static analysis
- security_tests_$TIMESTAMP.xml/txt - Security unit test results
- security_coverage_$TIMESTAMP.xml - Test coverage report
- potential_secrets_$TIMESTAMP.txt - Hardcoded secrets check
- sql_injection_check_$TIMESTAMP.txt - SQL injection vulnerability check
- xss_check_$TIMESTAMP.txt - XSS vulnerability check
- config_security_check_$TIMESTAMP.txt - Configuration security issues

EOF

# Final summary
TOTAL_ISSUES=0
[ "${BANDIT_EXIT:-0}" -ne 0 ] && ((TOTAL_ISSUES++))
[ "${SAFETY_EXIT:-0}" -ne 0 ] && ((TOTAL_ISSUES++))
[ "${SEMGREP_EXIT:-0}" -ne 0 ] && ((TOTAL_ISSUES++))
[ "${PYTEST_EXIT:-0}" -ne 0 ] && ((TOTAL_ISSUES++))

log_info "Security testing completed. Reports saved to $REPORT_DIR/"
echo "Total security issues detected: $TOTAL_ISSUES"

if [ "$TOTAL_ISSUES" -gt 0 ]; then
    log_error "Security testing failed with $TOTAL_ISSUES issue(s)"
    echo "Review the generated reports for detailed information."
    exit 1
else
    log_info "All security tests passed!"
    exit 0
fi
