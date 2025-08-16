# VS Code Workspace & GitHub Repository Parity Guide

This guide helps ensure your VS Code workspace is **exactly synchronized** with your GitHub repository.

---

## 1. Audit All Files

Compare the contents of these files and folders between your VS Code workspace and GitHub repo:

- `requirements.txt`
- `.replit`
- `replit.nix`
- `vercel.json`
- `.env.example`
- `.gitignore`
- `package.json`
- `app.py`
- Frontend folders: `src/`, `pages/`, `public/`
- Backend folders: `backend/`, `api/`, etc.

**Action:**  
If any file exists in one environment but not the other, copy it into the missing location.

---

## 2. Check VS Code Workspace Settings

Ensure `.vscode/settings.json` exists and includes:

```json
{
  "python.pythonPath": "venv/bin/python",
  "editor.formatOnSave": true,
  "files.exclude": {
    "**/__pycache__": true,
    "**/*.pyc": true
  }
}
```

---

## 3. File Manifest

See `FILE_MANIFEST.md` in this repo for a regularly updated list of all tracked files and folders.

---

## 4. Automation & Best Practices

- Use commit messages that describe synchronization (e.g. `chore: sync workspace with repo`).
- Regularly audit for drift and resolve discrepancies immediately.
- Use the VS Code GitHub integration to review changes before pushing.

---

_Last updated: 2025-08-15_