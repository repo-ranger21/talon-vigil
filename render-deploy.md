# 🚀 TalonVigil Render Deployment Guide

This guide walks contributors through deploying TalonVigil’s backend on [Render](https://render.com), with civic-grade reproducibility and least-privilege security.

---

## 🧱 Prerequisites

- GitHub access to `talonvigil-backend`
- Python 3.11+ installed locally
- Render account with verified email

---

## 🛠️ Setup Steps

1. **Fork the repo**  
   → `https://github.com/talonvigil/talonvigil-backend`

2. **Create a new Web Service on Render**  
   → Select “Web Service” → Connect GitHub → Choose your fork

3. **Configure Environment**
   - Runtime: Python 3.11
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`
   - Environment Variables:
     - `FLASK_ENV=production`
     - `API_KEY=<your-least-privilege-key>`
     - `CIVIC_DISCLAIMER=true`

4. **Set Custom Domain**  
   → `api.talonvigil.com` (via Cloudflare CNAME)

5. **Enable Auto Deploy**  
   → Trigger builds on every push to `main`

---

## 🧪 Test Your Deployment

```bash
curl https://api.talonvigil.com/ping
# Expected: {"status": "alive", "civic": true}
