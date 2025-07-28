# Example: Feature flag check for a tenant

def has_feature(tenant, feature_key: str) -> bool:
    active_sub = tenant.subscriptions.filter_by(status="Active").order_by(TenantSubscription.start_date.desc()).first()
    if not active_sub or not active_sub.plan or not active_sub.plan.features_json:
        return False
    return active_sub.plan.features_json.get(feature_key, False)

# Usage in Flask route or template
# if has_feature(current_tenant, "advanced_threat_intel"):
#     ... show or enable advanced features ...