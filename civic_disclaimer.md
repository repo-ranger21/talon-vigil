
---

### 📄 `cloudflare.md`

```markdown
# 🌐 TalonVigil DNS & SSL Setup (Cloudflare)

This guide helps contributors configure DNS routing and SSL protection for TalonVigil using Cloudflare.

---

## 🧱 Prerequisites

- Access to `talonvigil.com` zone in Cloudflare
- Least-privilege API token with DNS:Edit scope
- Backend deployment live on hosting platform

---

## 🛠️ Setup Steps

1. **Create API Token**
   - Go to Cloudflare → Profile → API Tokens → Create Token
   - Template: “Edit DNS”
   - Zone: `talonvigil.com`
   - Permissions: `Zone:DNS:Edit`
   - Save token as `CF_API_TOKEN`

2. **Add DNS Records**
   | Type | Name | Value | Proxy |
   |------|------|-------|-------|
   | CNAME | `api` | `render-backend-url` | Proxied |
   | CNAME | `www` | `frontend-deployment-url` | Proxied |

3. **Enable SSL**
   - SSL/TLS → Full (Strict)
   - Always Use HTTPS → On
   - Automatic HTTPS Rewrites → On

4. **Verify Routing**
   → Use `verify_dns.py` below

---

## 🫡 Civic Reminder

DNS is not just routing—it’s responsibility. Every record must be auditable, secure, and framed with dignity.

