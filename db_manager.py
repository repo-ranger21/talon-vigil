from datetime import datetime, date
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# --- Subscription Models ---

class SubscriptionPlan(db.Model):
    __tablename__ = "subscription_plans"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)  # 'Free', 'Standard', 'Enterprise', etc.
    price = db.Column(db.Numeric(10, 2), nullable=False)
    features_json = db.Column(db.JSON, nullable=True)  # e.g., {"max_users": 10, "api_calls": 10000, "pro_feature": True}
    is_active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"<SubscriptionPlan {self.name}>"

class TenantSubscription(db.Model):
    __tablename__ = "tenant_subscriptions"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('subscription_plans.id'), nullable=False)
    start_date = db.Column(db.Date, default=date.today)
    end_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(32), default="Active")  # 'Active', 'Trial', 'Cancelled'
    stripe_customer_id = db.Column(db.String(128), nullable=True)  # Or Paddle/Chargebee customer ID

    plan = db.relationship("SubscriptionPlan")
    tenant = db.relationship("Tenant", backref="subscriptions")

    def __repr__(self):
        return f"<TenantSubscription tenant={self.tenant_id} plan={self.plan_id} status={self.status}>"

# --- Usage Metrics Model ---

class UsageMetrics(db.Model):
    __tablename__ = "usage_metrics"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date = db.Column(db.Date, default=date.today)
    iocs_ingested = db.Column(db.Integer, default=0)
    playbooks_generated = db.Column(db.Integer, default=0)
    automated_actions = db.Column(db.Integer, default=0)
    api_calls = db.Column(db.Integer, default=0)
    # Extend as needed for other billable metrics

    def __repr__(self):
        return f"<UsageMetrics tenant={self.tenant_id} date={self.date}>"