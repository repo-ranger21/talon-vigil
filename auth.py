from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, Tenant
from db_manager import db
from email_utils import mail
from services.user_service import create_user, get_user_by_email
from datetime import datetime, timedelta
import secrets

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            flash('Please check your login details and try again.', 'error')
            return redirect(url_for('auth.login'))
            
        login_user(user, remember=remember)
        return redirect(url_for('main.profile'))
        
    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        name = request.form.get('name')
        company_name = request.form.get('company_name')
        # Basic validation
        if not all([email, password, confirm_password, name, company_name]):
            flash('All fields are required', 'error')
            return render_template('auth/register.html')
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('auth/register.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('auth/register.html')
        # Handle invitation flow
        tenant_id = None
        if 'invitation_token' in session:
            from models import InvitationToken
            token = InvitationToken.query.filter_by(
                token=session['invitation_token'],
                email=email,
                is_used=False
            ).first()
            
            if token:
                tenant_id = token.tenant_id
                token.is_used = True
                token.used_at = datetime.utcnow()
            else:
                session.pop('invitation_token', None)
                flash('Invalid or expired invitation', 'error')
                return render_template('auth/register.html')
        else:
            # Create new tenant for self-registration
            tenant = Tenant(
                name=company_name,
                domain=email.split('@')[1]
            )
            db.session.add(tenant)
            db.session.flush()  # Get tenant ID without committing
            tenant_id = tenant.id
        try:
            # Create user
            password_hash = generate_password_hash(password)
            user = create_user(email=email, name=name, tenant_id=tenant_id, password_hash=password_hash)
            
            # Log the user in
            login_user(user)
            
            # Clear invitation session data if any
            session.pop('invitation_token', None)
            session.pop('invitation_email', None)
            session.pop('invitation_tenant_id', None)
            session.pop('invitation_role', None)
            # Commit all changes
            db.session.commit()
            # Send welcome email
            try:
                from onboarding_routes import send_welcome_email
                send_welcome_email(user)
            except Exception as e:
                # Log error but don't fail registration
                current_app.logger.error(f"Failed to send welcome email: {e}")
            # Redirect to onboarding
            return redirect(url_for('onboarding.start_wizard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'error')
            return render_template('auth/register.html')
    return render_template('auth/register.html',
                          invitation_email=session.get('invitation_email'))

@auth_bp.route('/reset-password-request', methods=['GET', 'POST'])
def reset_request():
    """Handle password reset request."""
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))
    if request.method == 'POST':
        email = request.form.get('email')
        user = get_user_by_email(email)
        
        if user:
            # Generate token
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            
            # Send reset email
            reset_url = url_for('auth.reset_password', token=token, _external=True)
            msg = Message('Password Reset Request',
                          sender=current_app.config['MAIL_DEFAULT_SENDER'],
                          recipients=[user.email])
            msg.body = f'''To reset your password, visit the following link:{reset_url}If you did not make this request, simply ignore this email and no changes will be made.'''
            mail.send(msg)
            
            flash('An email has been sent with instructions to reset your password.', 'info')
            return redirect(url_for('auth.login'))
        else:
            flash('No account found with that email address.', 'error')
        return render_template('auth/reset_request.html')

@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Handle password reset."""
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))
        
    user = User.query.filter_by(reset_token=token).first()
    
    if user is None or user.reset_token_expires < datetime.utcnow():
        flash('Invalid or expired password reset token.', 'error')
        return redirect(url_for('auth.login'))
        
    if request.method == 'POST':
        password = request.form.get('password')
        user.password_hash = generate_password_hash(password)
        user.reset_token = None
        user.reset_token_expires = None
        db.session.commit()
        
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/reset_password.html')
