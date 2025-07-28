"""
High-level Stripe Integration Outline

1. Store Stripe secret keys in secure configuration (env vars, secret manager).
2. On checkout:
    - Call Stripe API to create a Customer and Subscription for the tenant.
    - Store `stripe_customer_id` and plan info in TenantSubscription.
    - Redirect user to Stripe Checkout session (if using Stripe-hosted UI).
3. Webhooks:
    - Listen for Stripe events (e.g., `invoice.paid`, `customer.subscription.updated`, `customer.subscription.deleted`).
    - Update TenantSubscription status, start/end dates, and plan as needed.
4. Security & Compliance:
    - Validate webhook signatures.
    - Never log or store full card numbers or CVVs.
5. Example Flask endpoints:
"""

from flask import Blueprint, request, jsonify, current_app

billing_bp = Blueprint("billing_bp", __name__)

@billing_bp.route("/subscribe", methods=["POST"])
def subscribe():
    # 1. Collect required info from frontend (tenant_id, plan_id, user info)
    # 2. Call Stripe API to create customer/subscription (mock here)
    # 3. Store returned customer ID and create TenantSubscription
    return jsonify({"status": "success", "message": "Checkout initiated (mock)."})

@billing_bp.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    # 1. Validate event signature
    # 2. Parse event type (e.g., subscription created, cancelled)
    # 3. Update TenantSubscription accordingly
    return "", 200