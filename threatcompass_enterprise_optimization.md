# ThreatCompass: Performance, Security & Enterprise Readiness Guide

## Part 1: Performance Optimization

---

### 1. Database Query Optimization

#### **A. Indexing**

- **Why:** Indexes speed up queries on frequently filtered or joined columns (especially in multi-tenant SaaS).
- **Key fields to index:**
  - `tenant_id` on all major multi-tenant models (`IOC`, `Playbook`, `UserEnvironment`, etc.)
  - `user_id`, `timestamp` (or `created_at`), foreign keys, and frequently filtered columns (e.g., `status` on `Playbook`)
- **How to add indexes in SQLAlchemy:**
    ```python
    class IOC(db.Model):
        __tablename__ = "iocs"
        id = db.Column(db.Integer, primary_key=True)
        tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, index=True)
        type = db.Column(db.String(50), nullable=False, index=True)
        value = db.Column(db.String(255), nullable=False)
        timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
        # ...other fields...
    ```
    Or add an explicit index:
    ```python
    __table_args__ = (
        db.Index('ix_ioc_tenant_type', 'tenant_id', 'type'),
    )
    ```

#### **B. Eager Loading / Lazy Loading**

- **Why:** Prevents N+1 queries when accessing related data (e.g., loading playbooks + steps for a dashboard).
- **How to use:**
    ```python
    from sqlalchemy.orm import joinedload, selectinload

    # Example: Eager load steps when querying playbooks
    playbooks = Playbook.query.options(selectinload(Playbook.steps)).filter_by(tenant_id=current_user.tenant_id).all()
    ```
- **Best Practice:** Use `selectinload` for collections, `joinedload` for one-to-one or many-to-one relationships.

#### **C. Pagination**

- **Why:** Avoids memory and response bloat for large datasets.
- **How to implement (Flask route example):**
    ```python
    @app.route('/iocs')
    @login_required
    def iocs_list():
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)
        pagination = IOC.query.filter_by(tenant_id=current_user.tenant_id).order_by(IOC.timestamp.desc()).paginate(page=page, per_page=per_page)
        return render_template('iocs_list.html', iocs=pagination.items, pagination=pagination)
    ```
    - For API endpoints, return `{"data": [...], "pagination": {"page":1, "per_page":50, "total":123}}`.

---

### 2. Caching Strategy

- **Use Case:** Frequently accessed, slow-changing data (e.g., MITRE ATT&CK mappings, environment configs).
- **Library:** [Flask-Caching](https://flask-caching.readthedocs.io/en/latest/)
- **Basic Setup:**
    ```python
    from flask_caching import Cache

    cache = Cache(config={'CACHE_TYPE': 'redis', 'CACHE_REDIS_URL': 'redis://redis:6379/0'})
    cache.init_app(app)
    ```
- **Example: Caching a route**
    ```python
    @app.route('/mitre_tactics')
    @cache.cached(timeout=3600)
    def get_mitre_tactics():
        tactics = MitreTactic.query.all()
        return jsonify([t.serialize() for t in tactics])
    ```
- **Cache DB query results:**
    ```python
    @cache.memoize(timeout=600)
    def get_top_enriched_iocs(tenant_id, limit=5):
        return IOC.query.filter_by(tenant_id=tenant_id).order_by(IOC.abuse_confidence.desc()).limit(limit).all()
    ```

---

### 3. Celery Task Optimization

- **Batching:** When enriching IOCs or scraping, process in batches to reduce API calls and DB overhead.
    ```python
    @celery.task
    def enrich_pending_iocs(batch_size=100):
        iocs = IOC.query.filter_by(...).limit(batch_size).all()
        for ioc in iocs:
            enrich_ioc_task.delay(ioc.id)
    ```
- **Efficient DB usage:** Use bulk updates where safe.
- **Retries:** Use Celery's retry logic for transient errors:
    ```python
    @celery.task(bind=True, max_retries=3)
    def enrich_ioc_task(self, ioc_id):
        try:
            # ...enrichment logic...
        except SomeTransientError as exc:
            self.retry(exc=exc, countdown=15)
    ```

---

## Part 2: Advanced Security Practices

---

### 1. Audit Logging / Activity Tracking

- **AuditLog Model:**
    ```python
    class AuditLog(db.Model):
        __tablename__ = "audit_logs"
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
        tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=True)
        action = db.Column(db.String(128), nullable=False)
        target_entity_type = db.Column(db.String(64), nullable=False)
        target_entity_id = db.Column(db.Integer, nullable=True)
        timestamp = db.Column(db.DateTime, default=datetime.utcnow)
        details_json = db.Column(db.JSON, nullable=True)
    ```
- **Integration Example:**
    ```python
    def log_audit_event(user_id, tenant_id, action, entity_type, entity_id, details):
        log = AuditLog(
            user_id=user_id,
            tenant_id=tenant_id,
            action=action,
            target_entity_type=entity_type,
            target_entity_id=entity_id,
            details_json=details
        )
        db.session.add(log)
        db.session.commit()
    # Usage in a Flask route:
    log_audit_event(current_user.id, current_user.tenant_id, "login", "User", current_user.id, {"ip": request.remote_addr})
    ```

---

### 2. Vulnerability Management & Dependencies

- **Automate Dependency Scanning:**
    - Use in CI/CD:
        - `pip-audit`:
            ```yaml
            - name: Run pip-audit
              run: pip install pip-audit && pip-audit
            ```
        - **Snyk:** Integrate Snyk scans for Python.
        - **Dependabot:** Enable for GitHub repos to auto-open PRs for vulnerable dependencies.
    - **Static Application Security Testing (SAST):**
        - Use [Bandit](https://bandit.readthedocs.io/) in CI:
            ```yaml
            - name: Run Bandit
              run: pip install bandit && bandit -r .
            ```

---

### 3. Secret Rotation Strategy

- **Best Practices:**
    - Store sensitive secrets in environment variables, ideally injected from a managed secret store (e.g., AWS Secrets Manager, Azure Key Vault, HashiCorp Vault).
    - Rotate DB/API/Flask secrets regularly.
        - Use short-lived credentials where possible.
        - Automate rotation using cloud provider features and reload application secrets without downtime.
    - For API keys & credentials stored in the database:
        - Store encrypted at rest (field-level encryption).
        - Implement an admin interface to rotate and revoke keys.
        - Log all key rotations in `AuditLog`.

---

## Part 3: Enterprise-Grade Scalability & Reliability

---

### 1. Horizontal Scaling Considerations

- **Stateless App:**  
  - Flask and Celery workers are stateless; session data in DB/Redis enables scaling.
- **How to scale:**
  - Run multiple web workers (e.g., Gunicorn/uwsgi with 4+ workers per instance).
  - Multiple Celery workers (with concurrency set per worker).
  - Use a managed PostgreSQL (RDS, CloudSQL) and Redis (ElastiCache, Azure Cache).
- **Load Balancer:**  
  - Place a cloud or container-native load balancer (e.g., AWS ALB, NGINX) in front of web nodes.

---

### 2. Disaster Recovery (Detailed Plan)

- **Recovery Point Objective (RPO):**  
  - Example: 1 hour (DB backups every hour, file/object storage versioning enabled).
- **Recovery Time Objective (RTO):**  
  - Example: 4 hours (infrastructure as code to rebuild, tested restore process).
- **Backups:**
  - Automated DB snapshots (hourly/daily, with 30-day retention).
  - Offsite/cloud provider backup storage.
- **Multi-AZ/Region Deployment:**
  - Use managed DB with Multi-AZ failover (e.g., AWS RDS Multi-AZ).
  - Web/Celery nodes in multiple availability zones.
  - Store all persistent files (if any) in object storage (S3/GCS) replicated across regions.
- **Disaster Recovery Runbook:**
    1. Detect incident, assess scope.
    2. Restore DB from latest snapshot.
    3. Redeploy web/Celery nodes from IaC (Terraform, CloudFormation).
    4. Validate restore, cut over DNS/load balancer.
    5. Communicate with stakeholders.

---

### 3. Graceful Shutdowns

- **Flask Web Workers:**  
  - Use Gunicorn with `--graceful-timeout` to finish in-flight requests before shutdown.
- **Celery Workers:**  
  - Use `--worker-shutdown-timeout` or send `SIGTERM` and wait for current tasks to finish.
    - Example: `celery -A app.celery worker --graceful-shutdown-timeout=30`
  - Handle `KeyboardInterrupt` or `SIGTERM` signals in custom task code if necessary.

---

## **Summary Table: Quick Wins**

| Area        | Technique                         | Example/Tool                        |
|-------------|-----------------------------------|-------------------------------------|
| DB Query    | Indexing, Eager Loading, Pagination| SQLAlchemy, Flask-SQLAlchemy        |
| Caching     | Flask-Caching w/ Redis            | `@cache.cached`, `@cache.memoize`   |
| Background  | Batching, Retries, Efficient DB   | Celery, Bulk DB ops                 |
| Security    | AuditLog, Dependency Scanning     | `AuditLog`, Bandit, pip-audit       |
| Secrets     | Cloud Secret Managers, Rotation   | AWS SM, Azure KV, Vault             |
| Scaling     | Multi-worker, Load Balancer, HA DB| Gunicorn, AWS ALB, RDS Multi-AZ     |
| Recovery    | DR Runbook, Backups, Multi-Region | Snapshots, Object storage           |
| Shutdown    | Graceful Timeout                  | Gunicorn, Celery flags              |

---

> **For each optimization:**
> - Profile and test before/after.
> - Automate where possible (CI/CD, cloud platform features).
> - Document procedures and runbooks for the team.
