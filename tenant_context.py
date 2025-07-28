from flask import g, request
from flask_login import current_user

def before_request():
    # Set the tenant_id for the current request based on the logged-in user
    if hasattr(current_user, "tenant_id"):
        g.tenant_id = current_user.tenant_id
    else:
        g.tenant_id = None

# Example: A query helper to always filter by tenant_id
def tenant_query(model):
    from flask import g
    return model.query.filter_by(tenant_id=g.tenant_id)