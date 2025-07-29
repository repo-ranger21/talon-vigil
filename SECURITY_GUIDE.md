# TalonVigil Security Implementation Guide

## Overview

This document outlines the comprehensive security measures implemented in TalonVigil, including Content Security Policy (CSP) headers, input sanitization, JWT/OAuth2 authentication, and automated dependency auditing.

## Security Features Implemented

### 1. Content Security Policy (CSP) Headers

**Purpose**: Prevent XSS attacks and unauthorized script execution.

**Implementation**: 
- Located in `security_headers.py`
- Uses Flask-Talisman for comprehensive CSP implementation
- Configured with strict policies for production

**Configuration**:
```python
# Development CSP (more permissive)
csp_config = {
    'default-src': "'self'",
    'script-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
    'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    # ... more directives
}

# Production CSP (stricter, uses nonces)
# Removes 'unsafe-inline' and uses cryptographic nonces
```

**Usage in Templates**:
```html
<!-- Use CSP nonce for inline scripts -->
<script nonce="{{ csp_nonce }}">
    // Your inline JavaScript here
</script>
```

### 2. Input Sanitization

**Purpose**: Prevent XSS, SQL injection, and other injection attacks.

**Implementation**:
- Located in `input_sanitization.py`
- Uses `bleach` library for HTML sanitization
- Marshmallow schemas for input validation
- **Never uses `dangerouslySetInnerHTML` equivalent**

**Key Features**:
```python
# HTML sanitization
sanitized_html = InputSanitizer.sanitize_html(user_input)

# Plain text sanitization
sanitized_text = InputSanitizer.sanitize_plain_text(user_input)

# URL validation
validated_url = InputSanitizer.validate_url(user_url)

# Email sanitization
sanitized_email = InputSanitizer.sanitize_email(user_email)
```

**Validation Decorators**:
```python
@validate_input(IOCValidationSchema)
def create_ioc():
    data = request.validated_data  # Pre-validated and sanitized
    # ... process data safely
```

### 3. JWT/OAuth2 Authentication

**Purpose**: Secure API access with modern authentication standards.

**Implementation**:
- JWT authentication in `jwt_auth.py`
- OAuth2 endpoints in `oauth_routes.py`
- Support for both JWT tokens and API keys

**Features**:
- Access and refresh tokens
- Scope-based authorization
- Token introspection
- OpenID Connect discovery
- Proper token expiration and rotation

**Usage**:
```python
# Require JWT with specific scopes
@jwt_required(['read', 'write'])
def secure_endpoint():
    user_id = g.current_user_id
    # ... endpoint logic

# Hybrid authentication (JWT or API key)
@hybrid_auth_required(['admin'])
def admin_endpoint():
    # ... admin logic
```

**OAuth2 Token Generation**:
```bash
# Request access token
curl -X POST /oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "password",
    "username": "user@example.com",
    "password": "secure_password",
    "scope": "read write"
  }'
```

### 4. Dependency Security Auditing

**Purpose**: Automatically detect and report security vulnerabilities in dependencies.

**Implementation**:
- Python script: `security_audit.py`
- GitHub Actions workflow: `.github/workflows/security-audit.yml`
- Multiple security tools integration

**Supported Tools**:
- **Safety**: Known vulnerability database
- **Pip-audit**: OSV and PyPI Advisory Database
- **Bandit**: Static code analysis for security issues
- **Semgrep**: Static analysis with security rules
- **License analysis**: Detect problematic licenses

**Manual Audit**:
```bash
# Run comprehensive security audit
python security_audit.py

# Run with custom requirements file
python security_audit.py --requirements custom-requirements.txt
```

**Automated Audit**:
- Runs daily via GitHub Actions
- Triggers on dependency changes
- Creates GitHub issues for vulnerabilities
- Fails CI/CD on security issues

## Security Configuration

### Environment Variables

```bash
# Production security settings
FLASK_ENV=production
FLASK_APP_SECRET_KEY=<your-secret-key>
JWT_SECRET_KEY=<your-jwt-secret>
DATABASE_URL=<your-database-url>

# CSP and CORS settings
ALLOWED_ORIGINS=https://yourdomain.com
FRONTEND_URL=https://yourdomain.com

# Optional: Skip security audit (not recommended)
SKIP_SECURITY_AUDIT=false
```

### Security Headers Applied

- **Content-Security-Policy**: Prevents XSS attacks
- **X-Frame-Options**: Prevents clickjacking
- **X-Content-Type-Options**: Prevents MIME sniffing
- **X-XSS-Protection**: Legacy XSS protection
- **Strict-Transport-Security**: Enforces HTTPS
- **Referrer-Policy**: Controls referrer information
- **Permissions-Policy**: Restricts browser features

## API Security

### Authentication Methods

1. **JWT Bearer Tokens** (Recommended)
```bash
Authorization: Bearer <jwt-token>
```

2. **API Keys** (Legacy support)
```bash
X-API-Key: <api-key>
```

### Rate Limiting

```python
# Per-endpoint rate limits
@limiter.limit("20/minute")  # IOC creation
@limiter.limit("100/minute") # Data retrieval
@limiter.limit("5/minute")   # Authentication
```

### Input Validation

All API endpoints use Marshmallow schemas for validation:

```python
class IOCCreateSchema(Schema):
    ioc_type = fields.Str(required=True, validate=validate.OneOf(['ip', 'domain', 'url', 'hash']))
    value = fields.Str(required=True, validate=validate.Length(min=1, max=500))
    description = fields.Str(validate=validate.Length(max=1000))
```

## Deployment Security

### Docker Security

```dockerfile
# Use non-root user
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

# Health checks
HEALTHCHECK --interval=30s --timeout=10s \
    CMD curl -f http://localhost:5000/health || exit 1
```

### Production Checklist

- [ ] Set strong `FLASK_APP_SECRET_KEY`
- [ ] Set secure `JWT_SECRET_KEY`
- [ ] Configure `ALLOWED_ORIGINS` for CORS
- [ ] Use HTTPS in production
- [ ] Set up proper database credentials
- [ ] Configure session security settings
- [ ] Enable rate limiting
- [ ] Set up security monitoring
- [ ] Run regular security audits

## Monitoring and Alerting

### Security Metrics Endpoint

```bash
GET /metrics/security
Authorization: Bearer <admin-token>
```

Returns:
```json
{
  "auth_failures_24h": 5,
  "rate_limit_violations_24h": 12,
  "csp_violations_24h": 0,
  "last_security_audit": "2025-01-28T10:30:00Z"
}
```

### Health Check

```bash
GET /health
```

Returns application health status and basic metrics.

## Incident Response

### Security Vulnerability Detection

1. **Automated Detection**: GitHub Actions runs daily security audits
2. **Issue Creation**: Automatically creates GitHub issues for vulnerabilities
3. **Notifications**: Optional Slack/Teams integration
4. **CI/CD Integration**: Fails builds on security issues

### Manual Response Steps

1. **Assess Impact**: Review security reports in `security_reports/` directory
2. **Update Dependencies**: Use `pip install --upgrade <package>`
3. **Test Updates**: Ensure application functionality
4. **Deploy**: Use secure deployment practices
5. **Verify**: Run security audit to confirm fixes

## Best Practices

### Development

1. **Never disable security features** in production
2. **Use validated data** from `request.validated_data`
3. **Sanitize all user inputs** before display
4. **Use parameterized queries** for database operations
5. **Implement proper error handling** without exposing sensitive information

### Template Security

```html
<!-- ✅ Safe: Use template helpers -->
{{ safe_text(user_content) }}
{{ safe_html(rich_content) }}

<!-- ❌ Dangerous: Never use raw content -->
{{ user_content|safe }}  <!-- DON'T DO THIS -->
```

### API Development

```python
# ✅ Good: Use authentication and validation
@api_key_or_jwt_required(['write'])
@validate_input(MySchema)
def my_endpoint():
    data = request.validated_data
    # ... safe processing

# ❌ Bad: Direct access to request data
def bad_endpoint():
    data = request.json  # Unvalidated!
    # ... dangerous processing
```

## Troubleshooting

### Common Issues

1. **CSP Violations**: Check browser console for blocked resources
2. **JWT Token Errors**: Verify token expiration and signature
3. **Rate Limiting**: Implement exponential backoff in clients
4. **Validation Errors**: Check Marshmallow schema definitions

### Debug Mode

```bash
# Enable debug logging
export FLASK_ENV=development
export FLASK_DEBUG=1
python run_secure.py
```

### Security Audit Failures

```bash
# Run manual audit with verbose output
python security_audit.py --verbose

# Check specific tool reports
cat security_reports/security_audit_*.json
```

## Contributing

When contributing to TalonVigil:

1. **Never bypass security measures**
2. **Add security tests** for new features
3. **Update documentation** for security-relevant changes
4. **Run security audit** before submitting PRs
5. **Follow secure coding practices**

## Security Contact

For security vulnerabilities, please:

1. **Do not** create public GitHub issues
2. **Email** security@yourcompany.com
3. **Include** detailed vulnerability information
4. **Allow** reasonable time for response

---

**Remember**: Security is an ongoing process, not a one-time setup. Regularly review and update security measures as threats evolve.
