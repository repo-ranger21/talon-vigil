[![Replit](https://img.shields.io/badge/Deployed%20on-Replit-blue?logo=replit&logoColor=white)](https://replit.com)

# Talon Vigil

Welcome! This repository contains civic tech deployment resources, health check endpoints, and environment management files for transparent and reproducible app operations.

## Key Files

- `health-check.md` – Endpoint verification guide for Flask/FastAPI.
- `replit-deploy.md` – Step-by-step Replit deployment instructions.
- `.env.template` – Example environment variables.
- `.env.local` – Local environment overrides (excluded from version control).
- `.gitignore` – Ignores `.env.local` for safety.

## Deployment Status

The badge above shows this project can be deployed on Replit for easy access and testing.

## Quick Start

1. Clone the repo and copy `.env.template` to `.env.local`, then set your own secrets.
2. Deploy to Replit using the instructions in `replit-deploy.md`.
3. Verify `/health` endpoint for parity.

## Contributing

We welcome civic-minded contributions! Please follow the guides and open issues for questions or suggestions.

---
For more details, see the full guides in this repo.