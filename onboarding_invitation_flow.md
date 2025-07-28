## User Onboarding & Invitation Flow

**1. Tenant Creation & First Admin User**
- New tenant signs up (or is created by an admin).
- First user registers (becomes tenant admin).
- System creates initial Tenant, User, TenantSubscription (`status="Trial"`), triggers onboarding flow.

**2. Guided Onboarding Steps**
- After login, show a "Get Started" dashboard with:
    - Step 1: Add environment (security tools).
    - Step 2: Review initial dashboard/playbooks.
    - Step 3: Invite teammates (see below).
    - Step 4: Finalize subscription (if trial).

**3. User Invitation System**
- Tenant admin can invite new users:
    - Enters email, system generates unique token.
    - Sends invitation email with registration link/token.
    - User completes registration, is assigned to the tenant.
    - Optionally, admin can assign roles at invite or after joining.

**4. User Management**
- Tenant admin can view/manage users in their tenant:
    - Assign/revoke roles.
    - Deactivate/reactivate users.
    - Resend invitations.
    - Remove users (soft delete).

**5. Account & Data Deletion (GDPR/CCPA)**
- User/Tenant can request deactivation or deletion.
    - Mark as inactive (soft delete) immediately.
    - Hard delete after retention window or on admin approval.
    - Remove all PII, audit log activity, and data according to privacy policy.