# 🧼 Workspace Parity Guide

Ensure your local workspace matches what Git tracks—critical for reproducible deployments and contributor onboarding.

## 🔍 Step 1: Generate File Lists

```bash
git ls-files > tracked_files.txt
find . -type f | sed 's|^\./||' > workspace_files.txt
