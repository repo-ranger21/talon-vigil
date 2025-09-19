"""
Hybrid Email Threat Detection Engine

This module implements a hybrid approach combining heuristic rules and AI scoring
for email threat analysis. It processes email content, headers, attachments, and URLs
to provide comprehensive threat assessment.
"""

import re
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat level enumeration"""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class RiskLevel(Enum):
    """Risk level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class EmailContent:
    """Email content structure"""
    headers: Dict[str, str]
    body: str
    attachments: List[Dict[str, str]]
    urls: List[str]
    sender: str
    subject: str


@dataclass
class HeuristicRule:
    """Heuristic rule structure"""
    rule_id: str
    category: str
    pattern: str
    weight: float
    description: str


@dataclass
class DetectionResult:
    """Detection result structure"""
    threat_level: ThreatLevel
    risk_level: RiskLevel
    heuristic_score: float
    ai_score: float
    final_score: float
    triggered_rules: List[str]
    reasoning: List[str]


class HeuristicEngine:
    """Heuristic-based threat detection engine"""
    
    def __init__(self, heuristics_file: str = None):
        self.heuristics_file = heuristics_file or self._get_default_heuristics_path()
        self.rules: Dict[str, HeuristicRule] = {}
        self.load_heuristics()
    
    def _get_default_heuristics_path(self) -> str:
        """Get default heuristics file path"""
        current_dir = Path(__file__).parent
        return str(current_dir / "heuristics" / "heuristics.yml")
    
    def load_heuristics(self) -> None:
        """Load heuristic rules from YAML file"""
        try:
            with open(self.heuristics_file, 'r') as file:
                data = yaml.safe_load(file)
                
            for category, rules in data.items():
                for rule_id, rule_data in rules.items():
                    self.rules[rule_id] = HeuristicRule(
                        rule_id=rule_id,
                        category=rule_data['category'],
                        pattern=rule_data['pattern'],
                        weight=rule_data['weight'],
                        description=rule_data['description']
                    )
            
            logger.info(f"Loaded {len(self.rules)} heuristic rules")
            
        except FileNotFoundError:
            logger.error(f"Heuristics file not found: {self.heuristics_file}")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Error parsing heuristics file: {e}")
            raise
    
    def apply_header_rules(self, headers: Dict[str, str]) -> Tuple[float, List[str]]:
        """Apply header-based heuristic rules"""
        score = 0.0
        triggered = []
        
        header_rules = {k: v for k, v in self.rules.items() if v.category == 'header'}
        
        for rule_id, rule in header_rules.items():
            if self._check_header_rule(headers, rule):
                score += rule.weight
                triggered.append(rule_id)
                logger.debug(f"Header rule triggered: {rule_id} - {rule.description}")
        
        return score, triggered
    
    def apply_body_rules(self, body: str) -> Tuple[float, List[str]]:
        """Apply body content heuristic rules"""
        score = 0.0
        triggered = []
        
        body_rules = {k: v for k, v in self.rules.items() if v.category == 'body'}
        
        for rule_id, rule in body_rules.items():
            if re.search(rule.pattern, body, re.IGNORECASE):
                score += rule.weight
                triggered.append(rule_id)
                logger.debug(f"Body rule triggered: {rule_id} - {rule.description}")
        
        return score, triggered
    
    def apply_attachment_rules(self, attachments: List[Dict[str, str]]) -> Tuple[float, List[str]]:
        """Apply attachment-based heuristic rules"""
        score = 0.0
        triggered = []
        
        attachment_rules = {k: v for k, v in self.rules.items() if v.category == 'attachment'}
        
        for attachment in attachments:
            filename = attachment.get('filename', '').lower()
            for rule_id, rule in attachment_rules.items():
                if re.search(rule.pattern, filename, re.IGNORECASE):
                    score += rule.weight
                    triggered.append(rule_id)
                    logger.debug(f"Attachment rule triggered: {rule_id} - {rule.description}")
        
        return score, triggered
    
    def apply_url_rules(self, urls: List[str]) -> Tuple[float, List[str]]:
        """Apply URL-based heuristic rules"""
        score = 0.0
        triggered = []
        
        url_rules = {k: v for k, v in self.rules.items() if v.category == 'url'}
        
        for url in urls:
            for rule_id, rule in url_rules.items():
                if re.search(rule.pattern, url, re.IGNORECASE):
                    score += rule.weight
                    triggered.append(rule_id)
                    logger.debug(f"URL rule triggered: {rule_id} - {rule.description}")
        
        return score, triggered
    
    def _check_header_rule(self, headers: Dict[str, str], rule: HeuristicRule) -> bool:
        """Check if a header rule is triggered"""
        pattern = rule.pattern
        
        # Check specific authentication failures
        if pattern == "spf_fail":
            return headers.get('Authentication-Results', '').find('spf=fail') != -1
        elif pattern == "dkim_fail":
            return headers.get('Authentication-Results', '').find('dkim=fail') != -1
        elif pattern == "dmarc_fail":
            return headers.get('Authentication-Results', '').find('dmarc=fail') != -1
        elif pattern == "suspicious_sender":
            sender = headers.get('From', '').lower()
            # Simple reputation check - in production would use reputation services
            suspicious_domains = ['suspicious.com', 'malware.net', 'phish.org']
            return any(domain in sender for domain in suspicious_domains)
        elif pattern == "forged_headers":
            # Check for header inconsistencies
            return self._check_forged_headers(headers)
        
        return False
    
    def _check_forged_headers(self, headers: Dict[str, str]) -> bool:
        """Check for potentially forged headers"""
        # Simple check for mismatched sender information
        from_header = headers.get('From', '')
        return_path = headers.get('Return-Path', '')
        
        if from_header and return_path:
            from_domain = from_header.split('@')[-1].strip('>')
            return_domain = return_path.split('@')[-1].strip('>')
            return from_domain != return_domain
        
        return False


class AIEngine:
    """AI-based threat scoring engine (mock implementation)"""
    
    def __init__(self):
        self.model_weights = {
            'content_model': 0.4,
            'behavioral_model': 0.3,
            'reputation_model': 0.3
        }
    
    def score_email(self, email: EmailContent) -> float:
        """Generate AI-based threat score for email"""
        # Mock AI scoring implementation
        # In production, this would use trained ML models
        
        score = 0.0
        
        # Content-based scoring
        content_score = self._score_content(email.body + email.subject)
        score += content_score * self.model_weights['content_model']
        
        # Behavioral scoring
        behavioral_score = self._score_behavior(email)
        score += behavioral_score * self.model_weights['behavioral_model']
        
        # Reputation scoring
        reputation_score = self._score_reputation(email.sender)
        score += reputation_score * self.model_weights['reputation_model']
        
        return min(1.0, max(0.0, score))
    
    def _score_content(self, content: str) -> float:
        """Score content using NLP models (mock implementation)"""
        # Mock implementation - would use actual NLP models in production
        suspicious_patterns = [
            r'urgent.*action', r'click.*here', r'verify.*account',
            r'suspend.*account', r'unusual.*activity', r'security.*alert'
        ]
        
        score = 0.1  # Base score
        for pattern in suspicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                score += 0.15
        
        return min(1.0, score)
    
    def _score_behavior(self, email: EmailContent) -> float:
        """Score behavioral patterns (mock implementation)"""
        score = 0.1
        
        # Check for multiple suspicious indicators
        if len(email.attachments) > 3:
            score += 0.2
        
        if len(email.urls) > 5:
            score += 0.15
        
        # Time-based analysis (mock)
        # In production, would analyze sending patterns, timing, etc.
        
        return min(1.0, score)
    
    def _score_reputation(self, sender: str) -> float:
        """Score sender reputation (mock implementation)"""
        # Mock reputation scoring
        # In production, would query reputation databases
        
        known_bad_domains = ['malware.com', 'phish.net', 'scam.org']
        domain = sender.split('@')[-1].lower()
        
        if any(bad_domain in domain for bad_domain in known_bad_domains):
            return 0.9
        
        return 0.1  # Default low score


class HybridDetectionEngine:
    """Hybrid detection engine combining heuristics and AI"""
    
    def __init__(self, heuristics_file: str = None, heuristic_weight: float = 0.6, ai_weight: float = 0.4):
        self.heuristic_engine = HeuristicEngine(heuristics_file)
        self.ai_engine = AIEngine()
        self.heuristic_weight = heuristic_weight
        self.ai_weight = ai_weight
        
        # Ensure weights sum to 1.0
        total_weight = self.heuristic_weight + self.ai_weight
        self.heuristic_weight /= total_weight
        self.ai_weight /= total_weight
    
    def analyze_email(self, email: EmailContent) -> DetectionResult:
        """Analyze email using hybrid approach"""
        logger.info(f"Analyzing email from {email.sender}")
        
        # Apply heuristic rules
        header_score, header_rules = self.heuristic_engine.apply_header_rules(email.headers)
        body_score, body_rules = self.heuristic_engine.apply_body_rules(email.body)
        attachment_score, attachment_rules = self.heuristic_engine.apply_attachment_rules(email.attachments)
        url_score, url_rules = self.heuristic_engine.apply_url_rules(email.urls)
        
        # Combine heuristic scores
        heuristic_score = header_score + body_score + attachment_score + url_score
        triggered_rules = header_rules + body_rules + attachment_rules + url_rules
        
        # Normalize heuristic score
        heuristic_score = min(1.0, heuristic_score)
        
        # Get AI score
        ai_score = self.ai_engine.score_email(email)
        
        # Blend scores
        final_score = (heuristic_score * self.heuristic_weight) + (ai_score * self.ai_weight)
        
        # Determine threat and risk levels
        threat_level = self._determine_threat_level(final_score)
        risk_level = self._determine_risk_level(final_score, len(triggered_rules))
        
        # Generate reasoning
        reasoning = self._generate_reasoning(triggered_rules, heuristic_score, ai_score, final_score)
        
        result = DetectionResult(
            threat_level=threat_level,
            risk_level=risk_level,
            heuristic_score=heuristic_score,
            ai_score=ai_score,
            final_score=final_score,
            triggered_rules=triggered_rules,
            reasoning=reasoning
        )
        
        logger.info(f"Analysis complete: {threat_level.value} threat, score: {final_score:.3f}")
        return result
    
    def _determine_threat_level(self, score: float) -> ThreatLevel:
        """Determine threat level based on final score"""
        if score >= 0.7:
            return ThreatLevel.MALICIOUS
        elif score >= 0.4:
            return ThreatLevel.SUSPICIOUS
        else:
            return ThreatLevel.SAFE
    
    def _determine_risk_level(self, score: float, rule_count: int) -> RiskLevel:
        """Determine risk level based on score and rule count"""
        if score >= 0.8 or rule_count >= 5:
            return RiskLevel.CRITICAL
        elif score >= 0.6 or rule_count >= 3:
            return RiskLevel.HIGH
        elif score >= 0.3 or rule_count >= 1:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _generate_reasoning(self, triggered_rules: List[str], heuristic_score: float, 
                          ai_score: float, final_score: float) -> List[str]:
        """Generate human-readable reasoning for the detection result"""
        reasoning = []
        
        if triggered_rules:
            reasoning.append(f"Triggered {len(triggered_rules)} heuristic rules: {', '.join(triggered_rules)}")
        
        reasoning.append(f"Heuristic score: {heuristic_score:.3f}, AI score: {ai_score:.3f}")
        reasoning.append(f"Final blended score: {final_score:.3f}")
        
        if final_score >= 0.7:
            reasoning.append("High confidence malicious threat detected")
        elif final_score >= 0.4:
            reasoning.append("Suspicious patterns detected, manual review recommended")
        else:
            reasoning.append("No significant threats detected")
        
        return reasoning


# Convenience function for easy usage
def analyze_email_threat(email_data: Dict[str, Any], 
                        heuristics_file: str = None) -> DetectionResult:
    """
    Convenience function to analyze email threat
    
    Args:
        email_data: Dictionary containing email components
        heuristics_file: Optional path to heuristics file
    
    Returns:
        DetectionResult with threat analysis
    """
    email = EmailContent(
        headers=email_data.get('headers', {}),
        body=email_data.get('body', ''),
        attachments=email_data.get('attachments', []),
        urls=email_data.get('urls', []),
        sender=email_data.get('sender', ''),
        subject=email_data.get('subject', '')
    )
    
    engine = HybridDetectionEngine(heuristics_file)
    return engine.analyze_email(email)