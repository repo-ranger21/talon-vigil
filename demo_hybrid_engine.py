#!/usr/bin/env python3
"""
Demonstration script for the Hybrid Email Threat Detection Engine

This script shows how to use the hybrid detection engine to analyze different types of emails.
"""

from detection.hybrid_engine import analyze_email_threat

def demo_safe_email():
    """Demonstrate analysis of a safe email"""
    print("=== SAFE EMAIL ANALYSIS ===")
    email_data = {
        'headers': {
            'From': 'support@company.com',
            'Authentication-Results': 'spf=pass dkim=pass dmarc=pass',
            'Return-Path': '<support@company.com>'
        },
        'body': 'Thank you for your recent purchase. Your order has been shipped.',
        'attachments': [{'filename': 'receipt.pdf', 'content_type': 'application/pdf'}],
        'urls': ['https://company.com/track-order'],
        'sender': 'support@company.com',
        'subject': 'Order Shipped - Tracking Information'
    }
    
    result = analyze_email_threat(email_data)
    print_result(result)

def demo_suspicious_email():
    """Demonstrate analysis of a suspicious email"""
    print("\n=== SUSPICIOUS EMAIL ANALYSIS ===")
    email_data = {
        'headers': {
            'From': 'security@bank-alert.com',
            'Authentication-Results': 'spf=fail dkim=pass dmarc=pass',
            'Return-Path': '<noreply@different-domain.net>'
        },
        'body': 'URGENT ACTION REQUIRED: Your account will be suspended. Click here immediately to verify.',
        'attachments': [{'filename': 'account_verification.zip', 'content_type': 'application/zip'}],
        'urls': ['http://bit.ly/verify-account', 'https://secure-login.suspicious.net'],
        'sender': 'security@bank-alert.com',
        'subject': 'Account Suspension Warning - Immediate Action Required'
    }
    
    result = analyze_email_threat(email_data)
    print_result(result)

def demo_malicious_email():
    """Demonstrate analysis of a malicious email"""
    print("\n=== MALICIOUS EMAIL ANALYSIS ===")
    email_data = {
        'headers': {
            'From': 'ceo@malware.com',
            'Authentication-Results': 'spf=fail dkim=fail dmarc=fail',
            'Return-Path': '<attacker@evil-domain.com>'
        },
        'body': 'Confidential urgent CEO request. Wire transfer needed immediately. Bank details attached. Do not tell anyone.',
        'attachments': [
            {'filename': 'urgent_transfer.exe', 'content_type': 'application/octet-stream'},
            {'filename': 'bank_details.scr', 'content_type': 'application/octet-stream'}
        ],
        'urls': ['http://192.168.1.100/malware', 'https://paypal-verify.phish.org/login'],
        'sender': 'ceo@malware.com',
        'subject': 'CONFIDENTIAL: Urgent Wire Transfer Required'
    }
    
    result = analyze_email_threat(email_data)
    print_result(result)

def print_result(result):
    """Print analysis result in a formatted way"""
    print(f"Threat Level: {result.threat_level.value.upper()}")
    print(f"Risk Level: {result.risk_level.value.upper()}")
    print(f"Heuristic Score: {result.heuristic_score:.3f}")
    print(f"AI Score: {result.ai_score:.3f}")
    print(f"Final Score: {result.final_score:.3f}")
    print(f"Triggered Rules ({len(result.triggered_rules)}): {', '.join(result.triggered_rules)}")
    print("Reasoning:")
    for reason in result.reasoning:
        print(f"  • {reason}")

if __name__ == "__main__":
    print("Hybrid Email Threat Detection Engine - Demonstration")
    print("=" * 60)
    
    demo_safe_email()
    demo_suspicious_email()
    demo_malicious_email()
    
    print("\n" + "=" * 60)
    print("Demonstration complete!")