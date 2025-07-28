# onboarding.py - Customer Onboarding Flask Routes

from flask import Blueprint, render_template, request, session, redirect, url_for, flash, jsonify, current_app
from flask_login import login_required, current_user
from db_manager import (
    db, User, Tenant, UserEnvironment, IOC, Playbook, 
    TenantSubscription, SubscriptionPlan, InvitationToken,
    create_user, get_user_environments, get_user_playbooks
)
from playbook_engine import generate_playbooks_for_user
from scraper import scrape_cisa_alerts
from email_utils import send_email
from rbac import role_required
import secrets
import string
from datetime import datetime, timedelta
from urllib.parse import urljoin
import uuid

onboarding_bp = Blueprint('onboarding', __name__, url_prefix='/onboarding')
invite_bp = Blueprint('invite', __name__, url_prefix='/invite')

# ============================================================================
# ONBOARDING WIZARD ROUTES
# ============================================================================

@onboarding_bp.route('/start')
@login_required
def start_wizard():
    """Start or resume the onboarding wizard."""
    
    # Check if user has already completed onboarding
    if current_user.onboarding_completed:
        flash('You have already completed the onboarding process.', 'info')
        return redirect(url_for('index'))
    
    # Initialize wizard session if not exists
    if 'onboarding_step' not in session:
        session['onboarding_step'] = 1
        session['onboarding_data'] = {}
    
    # Redirect to current step
    step = session.get('onboarding_step', 1)
    return redirect(url_for(f'onboarding.step{step}'))


@onboarding_bp.route('/step1', methods=['GET', 'POST'])
@login_required
def step1():
    """Step 1: Welcome & Account Verification"""
    
    if request.method == 'POST':
        # Validate and save any additional user information
        full_name = request.form.get('full_name', '').strip()
        job_title = request.form.get('job_title', '').strip()
        company_size = request.form.get('company_size', '').strip()
        
        if full_name:
            current_user.full_name = full_name
        if job_title:
            current_user.job_title = job_title
            
        # Store onboarding preferences
        session['onboarding_data'].update({
            'company_size': company_size,
            'job_title': job_title
        })
        
        db.session.commit()
        
        # Move to next step
        session['onboarding_step'] = 2
        return redirect(url_for('onboarding.step2'))
    
    return render_template('onboarding/step1_welcome.html', 
                         user=current_user,
                         tenant=current_user.tenant)


@onboarding_bp.route('/step2', methods=['GET', 'POST'])
@login_required
def step2():
    """Step 2: Environment Profiling (Security Tools Setup)"""
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add_tool':
            # Add a new security tool
            tool_type = request.form.get('tool_type', '').strip()
            tool_name = request.form.get('tool_name', '').strip()
            tool_details = request.form.get('tool_details', '').strip()
            
            if tool_type and tool_name:
                try:
                    env_tool = UserEnvironment(
                        user_id=current_user.id,
                        tenant_id=current_user.tenant_id,
                        tool_type=tool_type,
                        tool_name=tool_name,
                        details=tool_details
                    )
                    db.session.add(env_tool)
                    db.session.commit()
                    
                    flash(f'Added {tool_type}: {tool_name}', 'success')
                    
                    # Store tool count in session for progress tracking
                    tools_added = session['onboarding_data'].get('tools_added', 0) + 1
                    session['onboarding_data']['tools_added'] = tools_added
                    
                except Exception as e:
                    flash(f'Error adding tool: {str(e)}', 'error')
                    db.session.rollback()
            else:
                flash('Please provide both tool type and name.', 'error')
        
        elif action == 'next_step':
            # Check if at least one tool has been added
            user_tools = get_user_environments(current_user.id)
            if not user_tools:
                flash('Please add at least one security tool before proceeding.', 'warning')
                return redirect(url_for('onboarding.step2'))
            
            session['onboarding_step'] = 3
            return redirect(url_for('onboarding.step3'))
        
        elif action == 'skip_step':
            session['onboarding_step'] = 3
            return redirect(url_for('onboarding.step3'))
    
    # Get current user's environment tools
    user_tools = get_user_environments(current_user.id)
    
    # Predefined tool suggestions
    suggested_tools = {
        'Firewall': ['Palo Alto Networks', 'Cisco ASA', 'Fortinet FortiGate', 'pfSense', 'SonicWall'],
        'EDR/Endpoint': ['CrowdStrike Falcon', 'Microsoft Defender', 'SentinelOne', 'Carbon Black', 'Cortex XDR'],
        'SIEM': ['Splunk', 'QRadar', 'ArcSight', 'LogRhythm', 'Elastic Security'],
        'Email Security': ['Proofpoint', 'Mimecast', 'Microsoft Defender for Office 365', 'Barracuda'],
        'Network Security': ['Snort', 'Suricata', 'Wireshark', 'Nessus', 'Nmap'],
        'Cloud Security': ['AWS Security Hub', 'Azure Security Center', 'Google Cloud Security', 'Prisma Cloud']
    }
    
    return render_template('onboarding/step2_environment.html',
                         user_tools=user_tools,
                         suggested_tools=suggested_tools)


@onboarding_bp.route('/step3', methods=['GET', 'POST'])
@login_required
def step3():
    """Step 3: Threat Intelligence Sources Setup"""
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'enable_cisa':
            try:
                # Trigger CISA alerts scraping task
                from scraper import scrape_cisa_alerts
                scrape_cisa_alerts.delay()
                
                flash('CISA threat intelligence feed has been enabled. IOCs will be imported shortly.', 'success')
                session['onboarding_data']['cisa_enabled'] = True
                
            except Exception as e:
                flash(f'Error enabling CISA feed: {str(e)}', 'error')
        
        elif action == 'next_step':
            session['onboarding_step'] = 4
            return redirect(url_for('onboarding.step4'))
        
        elif action == 'skip_step':
            session['onboarding_step'] = 4
            return redirect(url_for('onboarding.step4'))
    
    # Check if user has any existing IOCs
    existing_iocs_count = IOC.query.filter_by(tenant_id=current_user.tenant_id).count()
    
    return render_template('onboarding/step3_threat_intel.html',
                         existing_iocs_count=existing_iocs_count)


@onboarding_bp.route('/step4', methods=['GET', 'POST'])
@login_required
def step4():
    """Step 4: First Playbook Generation"""
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'generate_playbooks':
            try:
                # Get user's environment for context
                user_env = get_user_environments(current_user.id)
                
                if not user_env:
                    flash('Please set up your environment tools first.', 'warning')
                    return redirect(url_for('onboarding.step2'))
                
                # Get available IOCs for the tenant
                iocs = IOC.query.filter_by(tenant_id=current_user.tenant_id).limit(5).all()
                
                if not iocs:
                    # Create some sample IOCs for demonstration
                    sample_iocs = [
                        {'value': '8.8.8.8', 'type': 'IP_ADDRESS', 'source': 'Sample', 'description': 'Sample suspicious IP'},
                        {'value': 'malicious.example.com', 'type': 'DOMAIN', 'source': 'Sample', 'description': 'Sample malicious domain'},
                    ]
                    
                    for ioc_data in sample_iocs:
                        ioc = IOC(
                            tenant_id=current_user.tenant_id,
                            **ioc_data
                        )
                        db.session.add(ioc)
                    
                    db.session.commit()
                    iocs = IOC.query.filter_by(tenant_id=current_user.tenant_id).all()
                
                # Generate playbooks
                from playbook_engine import generate_playbooks_for_user
                generate_playbooks_for_user(current_user.id, iocs, user_env, 
                                          industry=session['onboarding_data'].get('company_size'))
                
                flash('Your first playbooks have been generated successfully!', 'success')
                session['onboarding_data']['playbooks_generated'] = True
                
            except Exception as e:
                flash(f'Error generating playbooks: {str(e)}', 'error')
                current_app.logger.error(f"Playbook generation error: {e}")
        
        elif action == 'next_step':
            session['onboarding_step'] = 5
            return redirect(url_for('onboarding.step5'))
        
        elif action == 'skip_step':
            session['onboarding_step'] = 5
            return redirect(url_for('onboarding.step5'))
    
    # Check existing playbooks
    existing_playbooks = get_user_playbooks(current_user.id)
    user_tools = get_user_environments(current_user.id)
    
    return render_template('onboarding/step4_playbooks.html',
                         existing_playbooks=existing_playbooks,
                         user_tools=user_tools,
                         tools_count=len(user_tools))


@onboarding_bp.route('/step5', methods=['GET', 'POST'])
@login_required
def step5():
    """Step 5: Completion & Dashboard Introduction"""
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'complete_onboarding':
            # Mark onboarding as completed
            current_user.onboarding_completed = True
            current_user.onboarding_completed_at = datetime.utcnow()
            db.session.commit()
            
            # Clear onboarding session data
            session.pop('onboarding_step', None)
            session.pop('onboarding_data', None)
            
            flash('Welcome to ThreatCompass! Your account setup is complete.', 'success')
            
            # Send welcome email
            try:
                send_welcome_email(current_user)
            except Exception as e:
                current_app.logger.error(f"Failed to send welcome email: {e}")
            
            return redirect(url_for('index'))
    
    # Gather completion summary
    user_tools = get_user_environments(current_user.id)
    user_playbooks = get_user_playbooks(current_user.id)
    iocs_count = IOC.query.filter_by(tenant_id=current_user.tenant_id).count()
    
    completion_summary = {
        'tools_added': len(user_tools),
        'playbooks_generated': len(user_playbooks),
        'iocs_available': iocs_count,
        'cisa_enabled': session.get('onboarding_data', {}).get('cisa_enabled', False)
    }
    
    return render_template('onboarding/step5_completion.html',
                         completion_summary=completion_summary,
                         user_tools=user_tools,
                         user_playbooks=user_playbooks)


@onboarding_bp.route('/skip')
@login_required
def skip_onboarding():
    """Allow users to skip the entire onboarding process."""
    current_user.onboarding_completed = True
    current_user.onboarding_completed_at = datetime.utcnow()
    db.session.commit()
    
    # Clear session data
    session.pop('onboarding_step', None)
    session.pop('onboarding_data', None)
    
    flash('Onboarding skipped. You can access setup options in your account settings.', 'info')
    return redirect(url_for('index'))


# ============================================================================
# TEAM INVITATION SYSTEM ROUTES
# ============================================================================

@invite_bp.route('/generate', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def generate_invitation():
    """Generate invitation tokens for new team members."""
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        role_name = request.form.get('role', 'user').strip()
        message = request.form.get('message', '').strip()
        
        if not email:
            flash('Email address is required.', 'error')
            return redirect(url_for('invite.generate_invitation'))
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('A user with this email already exists.', 'error')
            return redirect(url_for('invite.generate_invitation'))
        
        # Check for pending invitation
        pending_invite = InvitationToken.query.filter_by(
            email=email, 
            tenant_id=current_user.tenant_id,
            is_used=False
        ).filter(InvitationToken.expires_at > datetime.utcnow()).first()
        
        if pending_invite:
            flash('An invitation for this email is already pending.', 'warning')
            return redirect(url_for('invite.generate_invitation'))
        
        try:
            # Generate secure token
            token = secrets.token_urlsafe(32)
            
            # Create invitation record
            invitation = InvitationToken(
                token=token,
                email=email,
                tenant_id=current_user.tenant_id,
                invited_by_user_id=current_user.id,
                role_name=role_name,
                custom_message=message,
                expires_at=datetime.utcnow() + timedelta(days=7)  # 7-day expiry
            )
            
            db.session.add(invitation)
            db.session.commit()
            
            # Send invitation email
            invitation_url = urljoin(request.url_root, 
                                   url_for('invite.accept_invitation', token=token))
            
            send_invitation_email(invitation, invitation_url)
            
            flash(f'Invitation sent to {email} successfully!', 'success')
            
        except Exception as e:
            flash(f'Error sending invitation: {str(e)}', 'error')
            db.session.rollback()
            current_app.logger.error(f"Invitation error: {e}")
        
        return redirect(url_for('invite.manage_invitations'))
    
    # Get available roles for the form
    from db_manager import Role
    available_roles = Role.query.all()
    
    return render_template('invite/generate.html', available_roles=available_roles)


@invite_bp.route('/accept/<token>')
def accept_invitation(token):
    """Accept an invitation token and redirect to registration."""
    
    # Find and validate invitation
    invitation = InvitationToken.query.filter_by(token=token, is_used=False).first()
    
    if not invitation:
        flash('Invalid or expired invitation link.', 'error')
        return redirect(url_for('login'))
    
    if invitation.expires_at < datetime.utcnow():
        flash('This invitation has expired.', 'error')
        return redirect(url_for('login'))
    
    # Store invitation data in session for registration
    session['invitation_token'] = token
    session['invitation_email'] = invitation.email
    session['invitation_tenant_id'] = invitation.tenant_id
    session['invitation_role'] = invitation.role_name
    
    return redirect(url_for('register'))


@invite_bp.route('/manage')
@login_required
@role_required('admin')
def manage_invitations():
    """Manage pending and used invitations."""
    
    # Get all invitations for current tenant
    pending_invitations = InvitationToken.query.filter_by(
        tenant_id=current_user.tenant_id,
        is_used=False
    ).filter(InvitationToken.expires_at > datetime.utcnow()).all()
    
    used_invitations = InvitationToken.query.filter_by(
        tenant_id=current_user.tenant_id,
        is_used=True
    ).order_by(InvitationToken.used_at.desc()).limit(20).all()
    
    expired_invitations = InvitationToken.query.filter_by(
        tenant_id=current_user.tenant_id,
        is_used=False
    ).filter(InvitationToken.expires_at <= datetime.utcnow()).limit(10).all()
    
    return render_template('invite/manage.html',
                         pending_invitations=pending_invitations,
                         used_invitations=used_invitations,
                         expired_invitations=expired_invitations)


@invite_bp.route('/revoke/<int:invitation_id>', methods=['POST'])
@login_required
@role_required('admin')
def revoke_invitation(invitation_id):
    """Revoke a pending invitation."""
    
    invitation = InvitationToken.query.filter_by(
        id=invitation_id,
        tenant_id=current_user.tenant_id,
        is_used=False
    ).first_or_404()
    
    invitation.is_revoked = True
    invitation.revoked_at = datetime.utcnow()
    invitation.revoked_by_user_id = current_user.id
    
    db.session.commit()
    
    flash(f'Invitation for {invitation.email} has been revoked.', 'success')
    return redirect(url_for('invite.manage_invitations'))


@invite_bp.route('/resend/<int:invitation_id>', methods=['POST'])
@login_required
@role_required('admin')
def resend_invitation(invitation_id):
    """Resend a pending invitation."""
    
    invitation = InvitationToken.query.filter_by(
        id=invitation_id,
        tenant_id=current_user.tenant_id,
        is_used=False
    ).first_or_404()
    
    if invitation.expires_at <= datetime.utcnow():
        # Extend expiry for resend
        invitation.expires_at = datetime.utcnow() + timedelta(days=7)
    
    try:
        invitation_url = urljoin(request.url_root, 
                               url_for('invite.accept_invitation', token=invitation.token))
        
        send_invitation_email(invitation, invitation_url)
        
        db.session.commit()
        flash(f'Invitation resent to {invitation.email}', 'success')
        
    except Exception as e:
        flash(f'Error resending invitation: {str(e)}', 'error')
        current_app.logger.error(f"Resend invitation error: {e}")
    
    return redirect(url_for('invite.manage_invitations'))


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def send_invitation_email(invitation, invitation_url):
    """Send invitation email to the invited user."""
    
    tenant = Tenant.query.get(invitation.tenant_id)
    inviter = User.query.get(invitation.invited_by_user_id)
    
    subject = f"You're invited to join {tenant.name} on ThreatCompass"
    
    email_data = {
        'invitation': invitation,
        'tenant': tenant,
        'inviter': inviter,
        'invitation_url': invitation_url,
        'expires_in_days': (invitation.expires_at - datetime.utcnow()).days
    }
    
    send_email(
        recipient=invitation.email,
        subject=subject,
        template_name='emails/invitation.html',
        **email_data
    )


def send_welcome_email(user):
    """Send welcome email after onboarding completion."""
    
    subject = "Welcome to ThreatCompass!"
    
    send_email(
        recipient=user.email,
        subject=subject,
        template_name='emails/welcome.html',
        user=user,
        tenant=user.tenant,
        dashboard_url=urljoin(current_app.config.get('BASE_URL', ''), url_for('index'))
    )