"""
Compliance Framework for TalonVigil
Automated compliance mapping and reporting for various security standards
"""

import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    ISO_27001 = "iso_27001"
    SOC_2 = "soc_2"
    PCI_DSS = "pci_dss"
    NIST_CSF = "nist_csf"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    FISMA = "fisma"
    CIS_CONTROLS = "cis_controls"
    OWASP_TOP_10 = "owasp_top_10"
    NIST_800_53 = "nist_800_53"

class ControlStatus(Enum):
    """Control implementation status"""
    NOT_IMPLEMENTED = "not_implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    IMPLEMENTED = "implemented"
    NOT_APPLICABLE = "not_applicable"
    COMPENSATING_CONTROL = "compensating_control"

class EvidenceType(Enum):
    """Types of compliance evidence"""
    POLICY = "policy"
    PROCEDURE = "procedure"
    CONFIGURATION = "configuration"
    LOG = "log"
    SCAN_RESULT = "scan_result"
    AUDIT_REPORT = "audit_report"
    TRAINING_RECORD = "training_record"
    PENETRATION_TEST = "penetration_test"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    CODE_REVIEW = "code_review"

@dataclass
class ComplianceControl:
    """Individual compliance control"""
    id: str
    framework: ComplianceFramework
    category: str
    title: str
    description: str
    requirements: List[str]
    status: ControlStatus = ControlStatus.NOT_IMPLEMENTED
    implementation_notes: str = ""
    responsible_party: str = ""
    evidence: List['ComplianceEvidence'] = field(default_factory=list)
    last_assessed: Optional[datetime] = None
    next_assessment: Optional[datetime] = None
    risk_level: str = "medium"
    automated_checks: List[str] = field(default_factory=list)

@dataclass
class ComplianceEvidence:
    """Evidence supporting compliance control"""
    id: str
    control_id: str
    evidence_type: EvidenceType
    title: str
    description: str
    file_path: Optional[str] = None
    url: Optional[str] = None
    created_date: datetime = field(default_factory=datetime.utcnow)
    expiry_date: Optional[datetime] = None
    hash: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ComplianceAssessment:
    """Compliance assessment results"""
    id: str
    framework: ComplianceFramework
    assessment_date: datetime
    assessor: str
    scope: str
    controls_assessed: List[str]
    findings: List['ComplianceFinding'] = field(default_factory=list)
    overall_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    next_assessment_date: Optional[datetime] = None

@dataclass
class ComplianceFinding:
    """Individual compliance finding"""
    id: str
    control_id: str
    severity: str  # low, medium, high, critical
    title: str
    description: str
    recommendation: str
    status: str = "open"  # open, in_progress, closed
    due_date: Optional[datetime] = None
    assigned_to: Optional[str] = None

class ComplianceFrameworkDefinition(ABC):
    """Abstract base class for compliance framework definitions"""
    
    @abstractmethod
    def get_controls(self) -> List[ComplianceControl]:
        """Get all controls for this framework"""
        pass
    
    @abstractmethod
    def get_control_mappings(self) -> Dict[str, List[str]]:
        """Get mappings between controls and technical implementations"""
        pass

class ISO27001Framework(ComplianceFrameworkDefinition):
    """ISO 27001 compliance framework definition"""
    
    def get_controls(self) -> List[ComplianceControl]:
        """ISO 27001 Annex A controls"""
        controls = [
            ComplianceControl(
                id="A.5.1.1",
                framework=ComplianceFramework.ISO_27001,
                category="Information Security Policies",
                title="Information security policy",
                description="An information security policy shall be defined and approved by management",
                requirements=[
                    "Establish information security policy",
                    "Get management approval",
                    "Communicate to all personnel",
                    "Review regularly"
                ],
                risk_level="high"
            ),
            ComplianceControl(
                id="A.9.1.1",
                framework=ComplianceFramework.ISO_27001,
                category="Access Control",
                title="Access control policy",
                description="An access control policy shall be established and reviewed",
                requirements=[
                    "Define access control policy",
                    "Implement access controls",
                    "Regular review of access rights",
                    "Segregation of duties"
                ],
                risk_level="high",
                automated_checks=["rbac_check", "access_review", "privileged_access_monitoring"]
            ),
            ComplianceControl(
                id="A.9.2.1",
                framework=ComplianceFramework.ISO_27001,
                category="Access Control",
                title="User registration and de-registration",
                description="Formal user registration and de-registration process",
                requirements=[
                    "User provisioning process",
                    "Access approval workflow",
                    "Regular access reviews",
                    "Automated de-provisioning"
                ],
                risk_level="high",
                automated_checks=["user_lifecycle_check", "orphaned_accounts_check"]
            ),
            ComplianceControl(
                id="A.12.6.1",
                framework=ComplianceFramework.ISO_27001,
                category="Operations Security",
                title="Management of technical vulnerabilities",
                description="Technical vulnerabilities shall be managed effectively",
                requirements=[
                    "Vulnerability scanning",
                    "Patch management",
                    "Risk assessment of vulnerabilities",
                    "Timely remediation"
                ],
                risk_level="high",
                automated_checks=["vulnerability_scan", "patch_compliance", "cve_monitoring"]
            ),
            ComplianceControl(
                id="A.13.1.1",
                framework=ComplianceFramework.ISO_27001,
                category="Communications Security",
                title="Network security management",
                description="Networks shall be managed and controlled",
                requirements=[
                    "Network security controls",
                    "Network segregation",
                    "Network monitoring",
                    "Secure network architecture"
                ],
                risk_level="high",
                automated_checks=["network_segmentation_check", "firewall_rules_check"]
            ),
            ComplianceControl(
                id="A.14.2.1",
                framework=ComplianceFramework.ISO_27001,
                category="System Development",
                title="Secure development policy",
                description="Rules for secure development shall be established",
                requirements=[
                    "Secure coding standards",
                    "Security testing in SDLC",
                    "Code review processes",
                    "Security training for developers"
                ],
                risk_level="medium",
                automated_checks=["code_security_scan", "dependency_check", "sast_scan"]
            )
        ]
        return controls
    
    def get_control_mappings(self) -> Dict[str, List[str]]:
        """Map ISO controls to technical implementations"""
        return {
            "A.9.1.1": ["rbac.py", "zero_trust.py", "auth.py"],
            "A.9.2.1": ["user_management", "access_controls"],
            "A.12.6.1": ["vulnerability_scanner", "patch_management"],
            "A.13.1.1": ["network_security", "firewall_config"],
            "A.14.2.1": ["secure_coding", "sast_tools", "dependency_scanning"]
        }

class SOC2Framework(ComplianceFrameworkDefinition):
    """SOC 2 Type II compliance framework definition"""
    
    def get_controls(self) -> List[ComplianceControl]:
        """SOC 2 Trust Service Criteria"""
        controls = [
            ComplianceControl(
                id="CC1.1",
                framework=ComplianceFramework.SOC_2,
                category="Control Environment",
                title="Integrity and Ethical Values",
                description="The entity demonstrates a commitment to integrity and ethical values",
                requirements=[
                    "Code of conduct established",
                    "Ethical behavior training",
                    "Conflict of interest policies",
                    "Whistleblower mechanisms"
                ],
                risk_level="medium"
            ),
            ComplianceControl(
                id="CC6.1",
                framework=ComplianceFramework.SOC_2,
                category="Logical Access",
                title="Logical Access Controls",
                description="The entity implements logical access security software",
                requirements=[
                    "Authentication mechanisms",
                    "Authorization controls",
                    "Account management",
                    "Access monitoring"
                ],
                risk_level="high",
                automated_checks=["authentication_check", "authorization_check", "session_management"]
            ),
            ComplianceControl(
                id="CC7.1",
                framework=ComplianceFramework.SOC_2,
                category="System Operations",
                title="System Monitoring",
                description="The entity monitors system components",
                requirements=[
                    "System monitoring tools",
                    "Performance monitoring",
                    "Capacity management",
                    "Incident response procedures"
                ],
                risk_level="high",
                automated_checks=["system_monitoring", "performance_metrics", "log_analysis"]
            ),
            ComplianceControl(
                id="A1.1",
                framework=ComplianceFramework.SOC_2,
                category="Availability",
                title="Availability Commitments",
                description="The entity maintains commitments for system availability",
                requirements=[
                    "Availability SLAs defined",
                    "Redundancy and failover",
                    "Backup and recovery",
                    "Capacity planning"
                ],
                risk_level="high",
                automated_checks=["availability_monitoring", "backup_verification", "failover_testing"]
            )
        ]
        return controls
    
    def get_control_mappings(self) -> Dict[str, List[str]]:
        """Map SOC 2 controls to technical implementations"""
        return {
            "CC6.1": ["authentication", "authorization", "session_management"],
            "CC7.1": ["monitoring", "logging", "alerting"],
            "A1.1": ["high_availability", "backup_systems", "disaster_recovery"]
        }

class PCIDSSFramework(ComplianceFrameworkDefinition):
    """PCI DSS compliance framework definition"""
    
    def get_controls(self) -> List[ComplianceControl]:
        """PCI DSS Requirements"""
        controls = [
            ComplianceControl(
                id="1.1",
                framework=ComplianceFramework.PCI_DSS,
                category="Network Security",
                title="Firewall Configuration",
                description="Install and maintain firewall configuration",
                requirements=[
                    "Firewall standards documented",
                    "Network diagram maintained",
                    "Firewall rules reviewed",
                    "DMZ implementation"
                ],
                risk_level="critical",
                automated_checks=["firewall_config_check", "network_segmentation_check"]
            ),
            ComplianceControl(
                id="2.1",
                framework=ComplianceFramework.PCI_DSS,
                category="System Security",
                title="Default Passwords",
                description="Change vendor-supplied defaults",
                requirements=[
                    "Default passwords changed",
                    "Default SNMP strings changed",
                    "Unnecessary services removed",
                    "Security parameters configured"
                ],
                risk_level="critical",
                automated_checks=["default_credentials_check", "service_hardening_check"]
            ),
            ComplianceControl(
                id="3.1",
                framework=ComplianceFramework.PCI_DSS,
                category="Data Protection",
                title="Cardholder Data Protection",
                description="Protect stored cardholder data",
                requirements=[
                    "Data retention policy",
                    "Secure deletion procedures",
                    "Data encryption at rest",
                    "Access logging"
                ],
                risk_level="critical",
                automated_checks=["encryption_check", "data_classification_check"]
            ),
            ComplianceControl(
                id="8.1",
                framework=ComplianceFramework.PCI_DSS,
                category="Access Control",
                title="User Identification",
                description="Assign unique ID to each person with computer access",
                requirements=[
                    "Unique user IDs",
                    "User ID standards",
                    "Shared account restrictions",
                    "User account management"
                ],
                risk_level="high",
                automated_checks=["unique_id_check", "shared_account_check"]
            )
        ]
        return controls
    
    def get_control_mappings(self) -> Dict[str, List[str]]:
        """Map PCI DSS controls to technical implementations"""
        return {
            "1.1": ["firewall_management", "network_security"],
            "2.1": ["system_hardening", "configuration_management"],
            "3.1": ["data_encryption", "data_loss_prevention"],
            "8.1": ["identity_management", "user_provisioning"]
        }

class ComplianceManager:
    """
    Central compliance management system
    Manages controls, assessments, and evidence across multiple frameworks
    """
    
    def __init__(self, data_directory: str = "./compliance_data"):
        self.data_directory = Path(data_directory)
        self.data_directory.mkdir(exist_ok=True)
        
        self.frameworks: Dict[ComplianceFramework, ComplianceFrameworkDefinition] = {}
        self.controls: Dict[str, ComplianceControl] = {}
        self.evidence: Dict[str, ComplianceEvidence] = {}
        self.assessments: Dict[str, ComplianceAssessment] = {}
        self.automated_checks: Dict[str, callable] = {}
        
        # Initialize framework definitions
        self._initialize_frameworks()
        self._load_data()
    
    def _initialize_frameworks(self):
        """Initialize compliance framework definitions"""
        self.frameworks[ComplianceFramework.ISO_27001] = ISO27001Framework()
        self.frameworks[ComplianceFramework.SOC_2] = SOC2Framework()
        self.frameworks[ComplianceFramework.PCI_DSS] = PCIDSSFramework()
        
        # Load all controls
        for framework_def in self.frameworks.values():
            for control in framework_def.get_controls():
                self.controls[control.id] = control
        
        logger.info(f"Initialized {len(self.frameworks)} compliance frameworks with {len(self.controls)} controls")
    
    def register_automated_check(self, check_name: str, check_function: callable):
        """Register an automated compliance check"""
        self.automated_checks[check_name] = check_function
        logger.info(f"Registered automated check: {check_name}")
    
    def add_evidence(self, evidence: ComplianceEvidence) -> bool:
        """Add evidence for a compliance control"""
        try:
            # Validate control exists
            if evidence.control_id not in self.controls:
                logger.error(f"Control {evidence.control_id} not found")
                return False
            
            # Calculate hash if file provided
            if evidence.file_path and Path(evidence.file_path).exists():
                evidence.hash = self._calculate_file_hash(evidence.file_path)
            
            # Store evidence
            self.evidence[evidence.id] = evidence
            
            # Link to control
            control = self.controls[evidence.control_id]
            if evidence not in control.evidence:
                control.evidence.append(evidence)
            
            self._save_data()
            logger.info(f"Added evidence {evidence.id} for control {evidence.control_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding evidence: {e}")
            return False
    
    def update_control_status(self, control_id: str, status: ControlStatus, 
                             notes: str = "", responsible_party: str = "") -> bool:
        """Update control implementation status"""
        try:
            control = self.controls.get(control_id)
            if not control:
                logger.error(f"Control {control_id} not found")
                return False
            
            control.status = status
            control.implementation_notes = notes
            control.responsible_party = responsible_party
            control.last_assessed = datetime.utcnow()
            
            # Schedule next assessment (default: 1 year)
            control.next_assessment = datetime.utcnow() + timedelta(days=365)
            
            self._save_data()
            logger.info(f"Updated control {control_id} status to {status.value}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating control status: {e}")
            return False
    
    def run_automated_checks(self, framework: ComplianceFramework = None) -> Dict[str, Any]:
        """Run automated compliance checks"""
        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "framework": framework.value if framework else "all",
            "checks_run": 0,
            "checks_passed": 0,
            "checks_failed": 0,
            "details": []
        }
        
        try:
            # Get controls to check
            controls_to_check = []
            if framework:
                controls_to_check = [c for c in self.controls.values() if c.framework == framework]
            else:
                controls_to_check = list(self.controls.values())
            
            for control in controls_to_check:
                for check_name in control.automated_checks:
                    check_function = self.automated_checks.get(check_name)
                    if check_function:
                        try:
                            check_result = check_function(control)
                            results["checks_run"] += 1
                            
                            if check_result.get("passed", False):
                                results["checks_passed"] += 1
                            else:
                                results["checks_failed"] += 1
                            
                            results["details"].append({
                                "control_id": control.id,
                                "check_name": check_name,
                                "result": check_result
                            })
                            
                        except Exception as e:
                            logger.error(f"Error running check {check_name}: {e}")
                            results["checks_failed"] += 1
                            results["details"].append({
                                "control_id": control.id,
                                "check_name": check_name,
                                "result": {"passed": False, "error": str(e)}
                            })
            
            logger.info(f"Completed automated checks: {results['checks_passed']}/{results['checks_run']} passed")
            return results
            
        except Exception as e:
            logger.error(f"Error running automated checks: {e}")
            results["error"] = str(e)
            return results
    
    def create_assessment(self, framework: ComplianceFramework, assessor: str, 
                         scope: str, controls: List[str] = None) -> ComplianceAssessment:
        """Create a new compliance assessment"""
        assessment_id = str(uuid.uuid4())
        
        # Default to all controls for framework if none specified
        if not controls:
            controls = [c.id for c in self.controls.values() if c.framework == framework]
        
        assessment = ComplianceAssessment(
            id=assessment_id,
            framework=framework,
            assessment_date=datetime.utcnow(),
            assessor=assessor,
            scope=scope,
            controls_assessed=controls,
            next_assessment_date=datetime.utcnow() + timedelta(days=365)
        )
        
        # Run automated checks for assessment
        automated_results = self.run_automated_checks(framework)
        
        # Generate findings based on control status and automated checks
        assessment.findings = self._generate_findings(controls, automated_results)
        
        # Calculate overall score
        assessment.overall_score = self._calculate_compliance_score(controls)
        
        # Generate recommendations
        assessment.recommendations = self._generate_recommendations(assessment.findings)
        
        self.assessments[assessment_id] = assessment
        self._save_data()
        
        logger.info(f"Created assessment {assessment_id} for {framework.value}")
        return assessment
    
    def get_compliance_dashboard(self, framework: ComplianceFramework = None) -> Dict[str, Any]:
        """Generate compliance dashboard data"""
        dashboard = {
            "timestamp": datetime.utcnow().isoformat(),
            "framework": framework.value if framework else "all",
            "summary": {},
            "controls_by_status": {},
            "risk_summary": {},
            "upcoming_assessments": [],
            "recent_evidence": [],
            "automated_check_status": {}
        }
        
        # Filter controls
        controls = []
        if framework:
            controls = [c for c in self.controls.values() if c.framework == framework]
        else:
            controls = list(self.controls.values())
        
        # Control status summary
        status_counts = {}
        risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        
        for control in controls:
            # Status counts
            status = control.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
            
            # Risk counts
            risk_counts[control.risk_level] += 1
        
        dashboard["controls_by_status"] = status_counts
        dashboard["risk_summary"] = risk_counts
        
        # Summary metrics
        total_controls = len(controls)
        implemented = status_counts.get("implemented", 0)
        partially_implemented = status_counts.get("partially_implemented", 0)
        
        dashboard["summary"] = {
            "total_controls": total_controls,
            "implemented": implemented,
            "partially_implemented": partially_implemented,
            "compliance_percentage": ((implemented + partially_implemented * 0.5) / total_controls * 100) if total_controls > 0 else 0
        }
        
        # Upcoming assessments
        upcoming = []
        for control in controls:
            if control.next_assessment and control.next_assessment <= datetime.utcnow() + timedelta(days=30):
                upcoming.append({
                    "control_id": control.id,
                    "title": control.title,
                    "due_date": control.next_assessment.isoformat()
                })
        
        dashboard["upcoming_assessments"] = sorted(upcoming, key=lambda x: x["due_date"])
        
        # Recent evidence
        recent_evidence = []
        for evidence in self.evidence.values():
            if evidence.created_date >= datetime.utcnow() - timedelta(days=30):
                recent_evidence.append({
                    "id": evidence.id,
                    "control_id": evidence.control_id,
                    "title": evidence.title,
                    "type": evidence.evidence_type.value,
                    "created_date": evidence.created_date.isoformat()
                })
        
        dashboard["recent_evidence"] = sorted(recent_evidence, key=lambda x: x["created_date"], reverse=True)[:10]
        
        return dashboard
    
    def export_compliance_report(self, framework: ComplianceFramework, 
                                output_format: str = "json") -> str:
        """Export comprehensive compliance report"""
        report_data = {
            "framework": framework.value,
            "generated_date": datetime.utcnow().isoformat(),
            "controls": [],
            "evidence": [],
            "assessments": [],
            "summary": self.get_compliance_dashboard(framework)["summary"]
        }
        
        # Add controls for framework
        for control in self.controls.values():
            if control.framework == framework:
                control_data = {
                    "id": control.id,
                    "category": control.category,
                    "title": control.title,
                    "description": control.description,
                    "status": control.status.value,
                    "risk_level": control.risk_level,
                    "implementation_notes": control.implementation_notes,
                    "responsible_party": control.responsible_party,
                    "last_assessed": control.last_assessed.isoformat() if control.last_assessed else None,
                    "evidence_count": len(control.evidence)
                }
                report_data["controls"].append(control_data)
        
        # Add evidence
        for evidence in self.evidence.values():
            if any(c.framework == framework for c in self.controls.values() if c.id == evidence.control_id):
                evidence_data = {
                    "id": evidence.id,
                    "control_id": evidence.control_id,
                    "type": evidence.evidence_type.value,
                    "title": evidence.title,
                    "description": evidence.description,
                    "created_date": evidence.created_date.isoformat(),
                    "expiry_date": evidence.expiry_date.isoformat() if evidence.expiry_date else None
                }
                report_data["evidence"].append(evidence_data)
        
        # Add assessments
        for assessment in self.assessments.values():
            if assessment.framework == framework:
                assessment_data = {
                    "id": assessment.id,
                    "assessment_date": assessment.assessment_date.isoformat(),
                    "assessor": assessment.assessor,
                    "scope": assessment.scope,
                    "overall_score": assessment.overall_score,
                    "findings_count": len(assessment.findings)
                }
                report_data["assessments"].append(assessment_data)
        
        # Generate report file
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"compliance_report_{framework.value}_{timestamp}.{output_format}"
        filepath = self.data_directory / filename
        
        if output_format == "json":
            with open(filepath, 'w') as f:
                json.dump(report_data, f, indent=2)
        
        logger.info(f"Exported compliance report: {filepath}")
        return str(filepath)
    
    def _generate_findings(self, control_ids: List[str], 
                          automated_results: Dict[str, Any]) -> List[ComplianceFinding]:
        """Generate findings based on control assessment"""
        findings = []
        
        for control_id in control_ids:
            control = self.controls.get(control_id)
            if not control:
                continue
            
            # Check control status
            if control.status == ControlStatus.NOT_IMPLEMENTED:
                finding = ComplianceFinding(
                    id=str(uuid.uuid4()),
                    control_id=control_id,
                    severity="high" if control.risk_level in ["high", "critical"] else "medium",
                    title=f"Control {control_id} not implemented",
                    description=f"The control '{control.title}' has not been implemented",
                    recommendation="Implement the required control according to framework requirements",
                    due_date=datetime.utcnow() + timedelta(days=90)
                )
                findings.append(finding)
            
            # Check automated test results
            for detail in automated_results.get("details", []):
                if detail["control_id"] == control_id and not detail["result"].get("passed", False):
                    finding = ComplianceFinding(
                        id=str(uuid.uuid4()),
                        control_id=control_id,
                        severity="medium",
                        title=f"Automated check failed: {detail['check_name']}",
                        description=detail["result"].get("message", "Automated compliance check failed"),
                        recommendation="Review and remediate the failed automated check",
                        due_date=datetime.utcnow() + timedelta(days=30)
                    )
                    findings.append(finding)
        
        return findings
    
    def _calculate_compliance_score(self, control_ids: List[str]) -> float:
        """Calculate overall compliance score"""
        if not control_ids:
            return 0.0
        
        total_score = 0.0
        total_weight = 0.0
        
        for control_id in control_ids:
            control = self.controls.get(control_id)
            if not control:
                continue
            
            # Weight by risk level
            weight = {"low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0}.get(control.risk_level, 2.0)
            
            # Score by status
            score = {
                ControlStatus.IMPLEMENTED: 1.0,
                ControlStatus.PARTIALLY_IMPLEMENTED: 0.5,
                ControlStatus.COMPENSATING_CONTROL: 0.8,
                ControlStatus.NOT_APPLICABLE: 1.0,
                ControlStatus.NOT_IMPLEMENTED: 0.0
            }.get(control.status, 0.0)
            
            total_score += score * weight
            total_weight += weight
        
        return (total_score / total_weight * 100) if total_weight > 0 else 0.0
    
    def _generate_recommendations(self, findings: List[ComplianceFinding]) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []
        
        # High-level recommendations based on finding patterns
        high_severity_count = sum(1 for f in findings if f.severity in ["high", "critical"])
        if high_severity_count > 0:
            recommendations.append(f"Address {high_severity_count} high/critical severity findings as priority")
        
        # Framework-specific recommendations
        recommendations.extend([
            "Implement regular automated compliance monitoring",
            "Establish evidence collection procedures",
            "Schedule periodic compliance assessments",
            "Provide compliance training to responsible parties"
        ])
        
        return recommendations
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def _save_data(self):
        """Save compliance data to disk"""
        try:
            # Save controls
            controls_file = self.data_directory / "controls.json"
            with open(controls_file, 'w') as f:
                controls_data = {}
                for control_id, control in self.controls.items():
                    controls_data[control_id] = {
                        "id": control.id,
                        "framework": control.framework.value,
                        "category": control.category,
                        "title": control.title,
                        "description": control.description,
                        "requirements": control.requirements,
                        "status": control.status.value,
                        "implementation_notes": control.implementation_notes,
                        "responsible_party": control.responsible_party,
                        "last_assessed": control.last_assessed.isoformat() if control.last_assessed else None,
                        "next_assessment": control.next_assessment.isoformat() if control.next_assessment else None,
                        "risk_level": control.risk_level,
                        "automated_checks": control.automated_checks
                    }
                json.dump(controls_data, f, indent=2)
            
            # Save evidence
            evidence_file = self.data_directory / "evidence.json"
            with open(evidence_file, 'w') as f:
                evidence_data = {}
                for evidence_id, evidence in self.evidence.items():
                    evidence_data[evidence_id] = {
                        "id": evidence.id,
                        "control_id": evidence.control_id,
                        "evidence_type": evidence.evidence_type.value,
                        "title": evidence.title,
                        "description": evidence.description,
                        "file_path": evidence.file_path,
                        "url": evidence.url,
                        "created_date": evidence.created_date.isoformat(),
                        "expiry_date": evidence.expiry_date.isoformat() if evidence.expiry_date else None,
                        "hash": evidence.hash,
                        "metadata": evidence.metadata
                    }
                json.dump(evidence_data, f, indent=2)
            
            # Save assessments
            assessments_file = self.data_directory / "assessments.json"
            with open(assessments_file, 'w') as f:
                assessments_data = {}
                for assessment_id, assessment in self.assessments.items():
                    assessments_data[assessment_id] = {
                        "id": assessment.id,
                        "framework": assessment.framework.value,
                        "assessment_date": assessment.assessment_date.isoformat(),
                        "assessor": assessment.assessor,
                        "scope": assessment.scope,
                        "controls_assessed": assessment.controls_assessed,
                        "overall_score": assessment.overall_score,
                        "recommendations": assessment.recommendations,
                        "next_assessment_date": assessment.next_assessment_date.isoformat() if assessment.next_assessment_date else None,
                        "findings": [
                            {
                                "id": f.id,
                                "control_id": f.control_id,
                                "severity": f.severity,
                                "title": f.title,
                                "description": f.description,
                                "recommendation": f.recommendation,
                                "status": f.status,
                                "due_date": f.due_date.isoformat() if f.due_date else None,
                                "assigned_to": f.assigned_to
                            }
                            for f in assessment.findings
                        ]
                    }
                json.dump(assessments_data, f, indent=2)
            
        except Exception as e:
            logger.error(f"Error saving compliance data: {e}")
    
    def _load_data(self):
        """Load compliance data from disk"""
        try:
            # Load controls modifications
            controls_file = self.data_directory / "controls.json"
            if controls_file.exists():
                with open(controls_file, 'r') as f:
                    controls_data = json.load(f)
                    for control_id, data in controls_data.items():
                        if control_id in self.controls:
                            control = self.controls[control_id]
                            control.status = ControlStatus(data.get("status", "not_implemented"))
                            control.implementation_notes = data.get("implementation_notes", "")
                            control.responsible_party = data.get("responsible_party", "")
                            if data.get("last_assessed"):
                                control.last_assessed = datetime.fromisoformat(data["last_assessed"])
                            if data.get("next_assessment"):
                                control.next_assessment = datetime.fromisoformat(data["next_assessment"])
            
            # Load evidence
            evidence_file = self.data_directory / "evidence.json"
            if evidence_file.exists():
                with open(evidence_file, 'r') as f:
                    evidence_data = json.load(f)
                    for evidence_id, data in evidence_data.items():
                        evidence = ComplianceEvidence(
                            id=data["id"],
                            control_id=data["control_id"],
                            evidence_type=EvidenceType(data["evidence_type"]),
                            title=data["title"],
                            description=data["description"],
                            file_path=data.get("file_path"),
                            url=data.get("url"),
                            created_date=datetime.fromisoformat(data["created_date"]),
                            expiry_date=datetime.fromisoformat(data["expiry_date"]) if data.get("expiry_date") else None,
                            hash=data.get("hash"),
                            metadata=data.get("metadata", {})
                        )
                        self.evidence[evidence_id] = evidence
                        
                        # Link to control
                        if evidence.control_id in self.controls:
                            control = self.controls[evidence.control_id]
                            if evidence not in control.evidence:
                                control.evidence.append(evidence)
            
            # Load assessments
            assessments_file = self.data_directory / "assessments.json"
            if assessments_file.exists():
                with open(assessments_file, 'r') as f:
                    assessments_data = json.load(f)
                    for assessment_id, data in assessments_data.items():
                        assessment = ComplianceAssessment(
                            id=data["id"],
                            framework=ComplianceFramework(data["framework"]),
                            assessment_date=datetime.fromisoformat(data["assessment_date"]),
                            assessor=data["assessor"],
                            scope=data["scope"],
                            controls_assessed=data["controls_assessed"],
                            overall_score=data.get("overall_score", 0.0),
                            recommendations=data.get("recommendations", []),
                            next_assessment_date=datetime.fromisoformat(data["next_assessment_date"]) if data.get("next_assessment_date") else None
                        )
                        
                        # Load findings
                        for finding_data in data.get("findings", []):
                            finding = ComplianceFinding(
                                id=finding_data["id"],
                                control_id=finding_data["control_id"],
                                severity=finding_data["severity"],
                                title=finding_data["title"],
                                description=finding_data["description"],
                                recommendation=finding_data["recommendation"],
                                status=finding_data.get("status", "open"),
                                due_date=datetime.fromisoformat(finding_data["due_date"]) if finding_data.get("due_date") else None,
                                assigned_to=finding_data.get("assigned_to")
                            )
                            assessment.findings.append(finding)
                        
                        self.assessments[assessment_id] = assessment
            
            logger.info("Loaded compliance data from disk")
            
        except Exception as e:
            logger.error(f"Error loading compliance data: {e}")


# Example automated compliance checks
def rbac_check(control: ComplianceControl) -> Dict[str, Any]:
    """Example RBAC compliance check"""
    # This would integrate with actual RBAC system
    return {
        "passed": True,
        "message": "RBAC controls are properly configured",
        "details": {
            "roles_defined": True,
            "permissions_mapped": True,
            "access_reviews_current": True
        }
    }

def vulnerability_scan_check(control: ComplianceControl) -> Dict[str, Any]:
    """Example vulnerability scanning compliance check"""
    # This would integrate with actual vulnerability scanner
    return {
        "passed": False,
        "message": "Vulnerability scan is overdue",
        "details": {
            "last_scan_date": "2024-01-01",
            "critical_vulnerabilities": 2,
            "high_vulnerabilities": 5
        }
    }

def encryption_check(control: ComplianceControl) -> Dict[str, Any]:
    """Example encryption compliance check"""
    # This would check actual encryption implementations
    return {
        "passed": True,
        "message": "Encryption controls are properly implemented",
        "details": {
            "data_at_rest_encrypted": True,
            "data_in_transit_encrypted": True,
            "key_management_proper": True
        }
    }
