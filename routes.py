from flask import Blueprint, render_template, request
from .db_manager import get_user_by_email

bp = Blueprint('main', __name__)

@bp.route('/profile')
def profile():
    email = request.args.get("email")
    user = get_user_by_email(email)
    if user:
        return render_template("profile.html", user=user)
    else:
        return "User not found", 404