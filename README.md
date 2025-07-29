# TalonVigil

A cloud-native, AI-powered cybersecurity threat intelligence platform with Zero Trust Architecture and advanced threat hunting capabilities.

## Overview

TalonVigil is an enterprise-grade, cloud-native cybersecurity platform that leverages AI/ML for threat intelligence, automated incident response, and proactive security operations. Built with Zero Trust principles, the platform provides federated threat intelligence, adaptive scoring, SOAR integration, and comprehensive compliance automation across multi-cloud environments.

## Features

### �️ Zero Trust Architecture
- Azure AD integration with conditional access policies
- Identity-based access controls with MFA enforcement
- Kubernetes network policies for microservice segmentation
- Managed identities for secure service-to-service communication
- Continuous verification and least-privilege access

### � Advanced Security & Authentication
- Flask-Security with JWT-Extended for robust authentication
- Azure Key Vault integration for secrets management
- Automatic secret rotation with audit logging
- RBAC with dynamic permission evaluation
- CSRF protection and secure session management

### 🤖 AI-Powered Threat Intelligence
- Federated learning across distributed threat data
- Adaptive threat scoring with ensemble ML models
- Real-time behavioral anomaly detection
- MITRE ATT&CK framework integration
- Automated threat hunting and correlation

### 🚀 DevSecOps Integration
- SonarQube static code analysis
- OWASP ZAP dynamic security testing
- Automated dependency scanning (pip-audit, npm audit)
- Security unit tests for APIs and components
- Policy-as-code with Azure Policy

### 🔄 SOAR & Automation
- Cortex XSOAR and Splunk Phantom connectors
- Automated incident response playbooks
- Phishing and malware containment workflows
- Rollback and recovery automation
- Purple team exercise orchestration

### 📊 Advanced Observability
- OpenTelemetry for unified telemetry
- Grafana and Azure Monitor visualizations
- ML-based anomaly detection on metrics
- Chaos engineering with Azure Chaos Studio
- Threat flow visualization

### 📋 Compliance & Governance
- Automated NIST, ISO 27001, SOC 2 mapping
- Azure Compliance Manager integration
- Continuous compliance monitoring
- Automated audit report generation
- Policy enforcement and remediation

### 🎯 Threat Simulation & Testing
- MITRE ATT&CK simulation with Caldera
- Atomic Red Team integration
- Scheduled purple team exercises
- Detection logic refinement
- Security control validation

## Technology Stack

- **Backend**: Python Flask
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Task Queue**: Celery with Redis broker
- **Authentication**: Flask-Login
- **Email**: Flask-Mail
- **Frontend**: HTML/CSS/JavaScript
- **Monitoring**: Sentry integration
- **Rate Limiting**: Flask-Limiter

## Prerequisites

- Python 3.8+
- PostgreSQL
- Redis
- Virtual environment (recommended)

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd talonvigil-v2
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   Create a `.env` file in the root directory:
   ```env
   FLASK_APP=app.py
   FLASK_ENV=development
   SECRET_KEY=your-secret-key
   DATABASE_URL=postgresql://username:password@localhost/talonvigil
   REDIS_URL=redis://localhost:6379/0
   MAIL_SERVER=your-mail-server
   MAIL_PORT=587
   MAIL_USERNAME=your-email
   MAIL_PASSWORD=your-password
   CELERY_BROKER_URL=redis://localhost:6379/0
   CELERY_RESULT_BACKEND=redis://localhost:6379/0
   ```

5. **Initialize the database**
   ```bash
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

## Running the Application

### Local Development Mode

1. **Start Redis server**
   ```bash
   redis-server
   ```

2. **Start Celery worker** (in a separate terminal)
   ```bash
   celery -A app.celery worker --loglevel=info
   ```

3. **Start Celery Beat scheduler** (in a separate terminal, if using scheduled tasks)
   ```bash
   celery -A app.celery beat --loglevel=info
   ```

4. **Run the Flask application**
   ```bash
   python app.py
   ```
   
   Or use the development script:
   ```bash
   ./run_dev.sh
   ```

The application will be available at `http://localhost:5000`.

### Cloud Deployment

TalonVigil includes complete infrastructure-as-code templates for deploying to Azure and AWS.

#### Quick Cloud Deployment

**Azure:**
```bash
cd terraform/azure
./deploy.sh dev
```

**AWS:**
```bash
cd terraform/aws
./deploy.sh dev
```

#### Manual Cloud Deployment

For detailed manual deployment instructions, see [terraform/README.md](terraform/README.md).

**Azure Resources Created:**
- App Service with Python runtime
- PostgreSQL Flexible Server
- Redis Cache
- Key Vault for secrets management
- Virtual Network with subnets
- Application Insights for monitoring
- Storage Account for static files

**AWS Resources Created:**
- ECS Fargate cluster and service
- RDS PostgreSQL instance
- ElastiCache Redis cluster
- Application Load Balancer
- ECR repository for container images
- VPC with public/private subnets
- CloudWatch for logging and monitoring
- Secrets Manager for sensitive data

#### Container Deployment

Build and run with Docker:
```bash
# Build image
docker build -t talonvigil .

# Run container
docker run -p 5000:5000 \
  -e DATABASE_URL="your-database-url" \
  -e REDIS_URL="your-redis-url" \
  talonvigil
```

### Production Mode

For production deployment, the infrastructure templates include:
- **High Availability**: Multi-AZ deployment with load balancing
- **Auto Scaling**: Automatic scaling based on CPU/memory usage
- **Security**: Network isolation, encryption at rest and in transit
- **Monitoring**: Comprehensive logging and alerting
- **Backup**: Automated database backups with point-in-time recovery

For production deployment, consider using:
- **WSGI Server**: Gunicorn (included in Docker image)
- **Reverse Proxy**: Azure Application Gateway or AWS ALB
- **Process Manager**: ECS Fargate or Azure Container Instances
- **Database**: Managed PostgreSQL with read replicas
- **Caching**: Redis with clustering
- **Monitoring**: Application Insights or CloudWatch with custom dashboards

## Project Structure

```
talonvigil-v2/
├── api/                    # API endpoints and modules
├── services/               # Business logic services
├── tasks/                  # Celery task definitions
├── templates/              # Jinja2 HTML templates
├── static/                 # CSS, JavaScript, and static assets
├── utils/                  # Utility functions and helpers
├── scripts/                # Deployment and utility scripts
├── logs/                   # Application logs
├── app.py                  # Main Flask application
├── auth.py                 # Authentication routes and logic
├── models.py               # SQLAlchemy database models
├── config.py               # Application configuration
├── requirements.txt        # Python dependencies
├── db_manager.py          # Database initialization
├── email_utils.py         # Email utilities
├── celery_utils.py        # Celery configuration utilities
├── rbac.py                # Role-based access control
├── routes.py              # Main application routes
└── onboarding_routes.py   # User onboarding workflows
```

## API Documentation

The application provides RESTful APIs for:
- User authentication and management
- Tenant operations
- Threat intelligence data
- System monitoring and health checks

API endpoints are documented and accessible at `/api/` when the application is running.

## Security Considerations

- All passwords are hashed using Werkzeug's secure hashing
- CSRF protection is enabled for all forms
- Rate limiting prevents abuse of authentication endpoints
- Input validation and sanitization on all user inputs
- Secure session management
- Environment-based configuration for sensitive data

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Testing

Run the test suite:
```bash
python -m pytest tests/
```

For coverage reports:
```bash
python -m pytest --cov=. tests/
```

## Monitoring and Logging

The application includes comprehensive logging and monitoring:
- Structured logging with configurable levels
- Sentry integration for error tracking
- Application performance monitoring
- Health check endpoints

## License

This project is licensed under the [MIT License](LICENSE).

## Support

For support and questions:
- Create an issue in the GitHub repository
- Check the documentation in the `/docs` directory
- Review the API documentation at `/api/docs`

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed list of changes and version history.

---

**TalonVigil** - Advanced Cybersecurity Threat Intelligence Platform
