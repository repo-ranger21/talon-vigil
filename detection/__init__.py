"""
Detection package for email threat analysis
"""

from .hybrid_engine import HybridDetectionEngine, EmailContent, DetectionResult, analyze_email_threat

__all__ = ['HybridDetectionEngine', 'EmailContent', 'DetectionResult', 'analyze_email_threat']