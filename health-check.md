# Health Check Endpoint Verification

## Flask Example
@app.route('/health')
def health():
    return {'status': 'ok'}, 200

## FastAPI Example
from fastapi import FastAPI
app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}

## Civic Disclaimers
- Health checks do not expose sensitive data.
- Endpoints are for operational parity and uptime checks only.