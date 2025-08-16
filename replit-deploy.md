# Replit Deployment Guide

## Civic Framing
This guide helps contributors deploy and verify the app on Replit, ensuring transparency and parity for civic tech projects.

## Setup Steps
1. **Fork and Clone the Repo**
2. **Create a Replit Project**
   - Visit [replit.com](https://replit.com) and create a new Repl
   - Choose "Import from GitHub" and select your forked repository
   - Replit will automatically detect the Python project and use `.replit` for config
3. **Configure Environment Variables**
   - Go to the "Secrets" tab in your Repl (lock icon in left sidebar)
   - Use `.env.template` for reference, add secrets via Replit's Secrets manager
   - Common variables: `SECRET_KEY`, `DATABASE_URL`, `DEBUG=False`
4. **Install Dependencies**
   - Replit will automatically install dependencies from `requirements.txt`
   - If manual installation is needed, use the Shell tab: `pip install -r requirements.txt`
5. **Run the Application**
   - Click the "Run" button or use the Shell: `python local_dev_server.py`
   - The app will be available at your Repl's URL (typically `https://your-repl-name.your-username.repl.co`)
6. **Enable Always-On (Optional)**
   - For production deployments, enable "Always On" in the Repl settings
   - This keeps your application running even when the editor is closed
7. **Verify Health Check**
   - Visit `/api/health` endpoint; should return `{"status": "healthy"}` with HTTP 200
   - Full URL: `https://your-repl-name.your-username.repl.co/api/health`
8. **Troubleshooting Parity**
   - Compare local vs Replit logs in the Console tab for config mismatches
   - Check the "Files" tab to ensure all necessary files are present

## Domain Configuration (Advanced)
For custom domains:
1. Upgrade to a paid Replit plan
2. Go to your Repl settings → "Custom Domains"  
3. Add your custom domain and follow DNS configuration instructions

## Useful Links
- [Replit Docs](https://docs.replit.com)
- [Replit Python Guide](https://docs.replit.com/programming-ide/using-replit-languages/python)
- [Replit Hosting Documentation](https://docs.replit.com/hosting/overview)