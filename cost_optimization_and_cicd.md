"""
Cost Optimization & Advanced CI/CD Security Integration

Cloud Cost Optimization:
- Right-size compute resources (web, Celery, DB) using cloud monitoring/metrics.
- Use auto-scaling for web/Celery nodes; set scaling policies based on queue depth, CPU, or requests.
- Purchase Reserved Instances/Savings Plans for steady-state workloads (DB, Redis).
- Prefer managed services for DB, Redis, object storage, leveraging auto-patching and backups.
- Use object storage lifecycle policies to expire old data/logs.
- Monitor egress costs (especially for API and reporting).

Advanced CI/CD Security:
- SAST: Add Bandit and SonarQube to pipeline for Python code static analysis.
- DAST: Integrate OWASP ZAP or similar to scan deployed web app endpoints during QA.
- Container Image Scanning: Use tools like Trivy, Snyk, or Docker Hub's built-in scan in CI to block vulnerable images.
- Example GitHub Actions snippet:
    - name: Run Trivy vulnerability scanner
      run: docker run --rm -v $(pwd):/project aquasec/trivy:latest --exit-code 1 --severity HIGH,CRITICAL /project

- Automate dependency updates and audits with Dependabot or RenovateBot.
"""