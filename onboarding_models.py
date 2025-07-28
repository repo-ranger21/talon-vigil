# Add these models to your existing db_manager.py

from datetime import datetime
from sqlalchemy import Index

# Add these fields to the existing User model
class User(UserMixin, db.Model):
    # ... existing fields ...
    
    # Onboarding fields
    onboarding_completed = db.Column(db.Boolean, default=False, nullable=False)
    onboarding_completed_at = db.Column(db.DateTime, nullable=True)
    full_name = db.Column(db.String(255), nullable=True)
    job_title = db.Column(db.String(128), nullable=True)
    
    # ... rest of existing model ...


class InvitationToken(db.Model):
    """Model for managing team invitation tokens."""
    __tablename__ = 'invitation_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    
    # Multi-tenancy
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, index=True)
    
    # Invitation details
    invited_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    role_name = db.Column(db.String(64), nullable=False, default='user')
    custom_message = db.Column(db.Text, nullable=True)
    
    # Status tracking
    is_used = db.Column(db.Boolean, default=False, nullable=False)
    is_revoked = db.Column(db.Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    used_at = db.Column(db.DateTime, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    
    # Foreign key relationships
    revoked_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    accepted_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Relationships
    tenant = db.relationship('Tenant', backref='invitation_tokens')
    invited_by = db.relationship('User', foreign_keys=[invited_by_user_id], backref='sent_invitations')
    revoked_by = db.relationship('User', foreign_keys=[revoked_by_user_id], backref='revoked_invitations')
    accepted_by = db.relationship('User', foreign_keys=[accepted_by_user_id], backref='accepted_invitations')
    
    # Table constraints and indexes
    __table_args__ = (
        Index('ix_invitation_tenant_email', 'tenant_id', 'email'),
        Index('ix_invitation_status', 'is_used', 'is_revoked', 'expires_at'),
        db.UniqueConstraint('token', name='uq_invitation_token'),
    )
    
    def __repr__(self):
        return f'<InvitationToken {self.email} -> {self.tenant.name if self.tenant else "Unknown"}>'
    
    @property
    def is_expired(self):
        """Check if the invitation has expired."""
        return datetime.utcnow() > self.expires_at
    
    @property
    def is_valid(self):
        """Check if the invitation is valid (not used, not revoked, not expired)."""
        return not self.is_used and not self.is_revoked and not self.is_expired
    
    @property
    def status(self):
        """Get the current status of the invitation."""
        if self.is_used:
            return 'accepted'
        elif self.is_revoked:
            return 'revoked'
        elif self.is_expired:
            return 'expired'
        else:
            return 'pending'


class OnboardingProgress(db.Model):
    """Track detailed onboarding progress for analytics and support."""
    __tablename__ = 'onboarding_progress'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False, index=True)
    
    # Progress tracking
    current_step = db.Column(db.Integer, default=1, nullable=False)
    steps_completed = db.Column(db.JSON, nullable=True)  # Store completed step details
    total_time_spent = db.Column(db.Integer, default=0)  # Time in seconds
    
    # Step-specific metrics
    tools_added_count = db.Column(db.Integer, default=0)
    playbooks_generated_count = db.Column(db.Integer, default=0)
    intel_sources_enabled = db.Column(db.JSON, nullable=True)
    
    # Timestamps
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    last_activity_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    user = db.relationship('User', backref='onboarding_progress')
    tenant = db.relationship('Tenant', backref='onboarding_progress')
    
    def __repr__(self):
        return f'<OnboardingProgress {self.user.email} - Step {self.current_step}>'


# Helper functions for the onboarding system

def create_invitation_token(email, tenant_id, invited_by_user_id, role_name='user', custom_message=None, expires_in_days=7):
    """Create a new invitation token."""
    import secrets
    from datetime import timedelta
    
    token = secrets.token_urlsafe(32)
    
    invitation = InvitationToken(
        token=token,
        email=email.lower().strip(),
        tenant_id=tenant_id,
        invited_by_user_id=invited_by_user_id,
        role_name=role_name,
        custom_message=custom_message,
        expires_at=datetime.utcnow() + timedelta(days=expires_in_days)
    )
    
    return invitation


def process_invitation_acceptance(token, user_id):
    """Mark an invitation as accepted and associate with user."""
    invitation = InvitationToken.query.filter_by(token=token, is_used=False).first()
    
    if not invitation or not invitation.is_valid:
        return False
    
    invitation.is_used = True
    invitation.used_at = datetime.utcnow()
    invitation.accepted_by_user_id = user_id
    
    db.session.commit()
    return True


def get_user_onboarding_progress(user_id):
    """Get or create onboarding progress for a user."""
    progress = OnboardingProgress.query.filter_by(user_id=user_id).first()
    
    if not progress:
        user = User.query.get(user_id)
        progress = OnboardingProgress(
            user_id=user_id,
            tenant_id=user.tenant_id,
            current_step=1,
            steps_completed={}
        )
        db.session.add(progress)
        db.session.commit()
    
    return progress


def update_onboarding_progress(user_id, step, data=None):
    """Update onboarding progress for analytics."""
    progress = get_user_onboarding_progress(user_id)
    
    if step > progress.current_step:
        progress.current_step = step
    
    if data:
        steps_completed = progress.steps_completed or {}
        steps_completed[str(step)] = {
            'completed_at': datetime.utcnow().isoformat(),
            'data': data
        }
        progress.steps_completed = steps_completed
    
    progress.last_activity_at = datetime.utcnow()
    db.session.commit()
    
    return progress


def complete_onboarding(user_id):
    """Mark onboarding as completed."""
    user = User.query.get(user_id)
    user.onboarding_completed = True
    user.onboarding_completed_at = datetime.utcnow()
    
    progress = get_user_onboarding_progress(user_id)
    progress.completed_at = datetime.utcnow()
    
    db.session.commit()
    
    return user