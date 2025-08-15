[![Render Status](https://render.com/api/v1/services/srv-d2f2vmur433s73epki50/status)](https://dashboard.render.com/web/srv-d2f2vmur433s73epki50)

# Talon Vigil

Welcome! This repository contains civic tech deployment resources, health check endpoints, and environment management files for transparent and reproducible app operations.

## Key Files

- `health-check.md` – Endpoint verification guide for Flask/FastAPI.
- `render-deploy.md` – Step-by-step Render deployment instructions.
- `.env.template` – Example environment variables.
- `.env.local` – Local environment overrides (excluded from version control).
- `.gitignore` – Ignores `.env.local` for safety.

## Deployment Status

The badge above shows the current Render deployment status for this project.

## Quick Start

1. Clone the repo and copy `.env.template` to `.env.local`, then set your own secrets.
2. Deploy to Render using the instructions in `render-deploy.md`.
3. Verify `/health` endpoint for parity.

## Contributing

We welcome civic-minded contributions! Please follow the guides and open issues for questions or suggestions.

---
For more details, see the full guides in this repo.