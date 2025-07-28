from functools import wraps
from flask import abort
from flask_login import current_user

def role_required(*roles):
    """Decorator to require one of the specified roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if not current_user.role or current_user.role.name not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Usage Example:
# @app.route("/admin/scrape_iocs")
# @login_required
# @role_required('admin')
# def scrape_iocs():
#     ...