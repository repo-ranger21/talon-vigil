# Render Deployment Guide

## Civic Framing
This guide helps contributors deploy and verify the app on Render, ensuring transparency and parity for civic tech projects.

## Setup Steps
1. **Fork and Clone the Repo**
2. **Create a Render Web Service**
   - Connect to GitHub, select your repo.
   - Use `render.yaml` for config.
3. **Enable Auto-Deploy**
   - Go to service > Settings > Auto-Deploy (enable for main branch).
4. **Set Environment Variables**
   - Use `.env.template` for reference, add secrets via Render dashboard.
5. **Verify Health Check**
   - Visit `/health` endpoint; should return `{"status": "ok"}` with HTTP 200.
6. **Troubleshooting Parity**
   - Compare local vs Render logs for config mismatches.

## Useful Links
- [Render Docs](https://render.com/docs)