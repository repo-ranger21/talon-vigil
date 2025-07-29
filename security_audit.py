#!/usr/bin/env python3
"""
Dependency Security Audit Script
===============================

Automated security audit tool for Python dependencies.
Checks for known vulnerabilities using safety and other tools.
"""

import subprocess
import sys
import json
import os
import logging
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DependencyAuditor:
    """Python dependency security auditor"""
    
    def __init__(self, requirements_file='requirements.txt'):
        self.requirements_file = requirements_file
        self.report_dir = Path('security_reports')
        self.report_dir.mkdir(exist_ok=True)
        
    def run_safety_check(self):
        """Run safety check for known vulnerabilities"""
        logger.info("Running safety vulnerability scan...")
        
        try:
            # Install safety if not present
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'safety'], 
                          check=True, capture_output=True)
            
            # Run safety check
            result = subprocess.run([
                sys.executable, '-m', 'safety', 'check', 
                '--json', '--file', self.requirements_file
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("✅ No known vulnerabilities found by safety")
                return {'status': 'clean', 'vulnerabilities': []}
            else:
                try:
                    vulnerabilities = json.loads(result.stdout)
                    logger.warning(f"⚠️  {len(vulnerabilities)} vulnerabilities found by safety")
                    return {'status': 'vulnerable', 'vulnerabilities': vulnerabilities}
                except json.JSONDecodeError:
                    logger.error(f"Safety check failed: {result.stderr}")
                    return {'status': 'error', 'message': result.stderr}
                    
        except Exception as e:
            logger.error(f"Safety check failed: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def run_pip_audit(self):
        """Run pip-audit for additional vulnerability scanning"""
        logger.info("Running pip-audit vulnerability scan...")
        
        try:
            # Install pip-audit if not present
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'pip-audit'], 
                          check=True, capture_output=True)
            
            # Run pip-audit
            result = subprocess.run([
                sys.executable, '-m', 'pip_audit', 
                '--format', 'json',
                '--requirement', self.requirements_file
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                try:
                    audit_result = json.loads(result.stdout)
                    vulnerabilities = audit_result.get('vulnerabilities', [])
                    
                    if not vulnerabilities:
                        logger.info("✅ No vulnerabilities found by pip-audit")
                        return {'status': 'clean', 'vulnerabilities': []}
                    else:
                        logger.warning(f"⚠️  {len(vulnerabilities)} vulnerabilities found by pip-audit")
                        return {'status': 'vulnerable', 'vulnerabilities': vulnerabilities}
                        
                except json.JSONDecodeError:
                    logger.info("✅ No vulnerabilities found by pip-audit")
                    return {'status': 'clean', 'vulnerabilities': []}
            else:
                logger.error(f"pip-audit failed: {result.stderr}")
                return {'status': 'error', 'message': result.stderr}
                
        except Exception as e:
            logger.error(f"pip-audit failed: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def check_outdated_packages(self):
        """Check for outdated packages"""
        logger.info("Checking for outdated packages...")
        
        try:
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'list', '--outdated', '--format', 'json'
            ], capture_output=True, text=True, check=True)
            
            outdated = json.loads(result.stdout)
            
            if not outdated:
                logger.info("✅ All packages are up to date")
                return {'status': 'clean', 'outdated': []}
            else:
                logger.warning(f"⚠️  {len(outdated)} packages are outdated")
                return {'status': 'outdated', 'packages': outdated}
                
        except Exception as e:
            logger.error(f"Outdated package check failed: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def analyze_licenses(self):
        """Analyze package licenses for compliance"""
        logger.info("Analyzing package licenses...")
        
        try:
            # Install pip-licenses if not present
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'pip-licenses'], 
                          check=True, capture_output=True)
            
            # Get license information
            result = subprocess.run([
                sys.executable, '-m', 'pip_licenses', '--format', 'json'
            ], capture_output=True, text=True, check=True)
            
            licenses = json.loads(result.stdout)
            
            # Define problematic licenses
            problematic_licenses = [
                'GPL-3.0', 'GPL-2.0', 'AGPL-3.0', 'AGPL-1.0',
                'LGPL-3.0', 'LGPL-2.1', 'Copyleft'
            ]
            
            license_issues = []
            for package in licenses:
                license_name = package.get('License', 'Unknown')
                if any(prob in license_name for prob in problematic_licenses):
                    license_issues.append({
                        'name': package.get('Name'),
                        'version': package.get('Version'),
                        'license': license_name
                    })
            
            if license_issues:
                logger.warning(f"⚠️  {len(license_issues)} packages have potentially problematic licenses")
                return {'status': 'issues', 'license_issues': license_issues}
            else:
                logger.info("✅ No license issues found")
                return {'status': 'clean', 'license_issues': []}
                
        except Exception as e:
            logger.error(f"License analysis failed: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def generate_report(self, safety_result, pip_audit_result, outdated_result, license_result):
        """Generate comprehensive security report"""
        timestamp = datetime.now().isoformat()
        
        report = {
            'audit_timestamp': timestamp,
            'requirements_file': self.requirements_file,
            'safety_scan': safety_result,
            'pip_audit_scan': pip_audit_result,
            'outdated_packages': outdated_result,
            'license_analysis': license_result,
            'summary': {
                'total_vulnerabilities': 0,
                'critical_issues': [],
                'recommendations': []
            }
        }
        
        # Count total vulnerabilities
        if safety_result.get('vulnerabilities'):
            report['summary']['total_vulnerabilities'] += len(safety_result['vulnerabilities'])
        
        if pip_audit_result.get('vulnerabilities'):
            report['summary']['total_vulnerabilities'] += len(pip_audit_result['vulnerabilities'])
        
        # Generate recommendations
        recommendations = []
        
        if safety_result.get('status') == 'vulnerable':
            recommendations.append("Update packages to fix safety vulnerabilities")
        
        if pip_audit_result.get('status') == 'vulnerable':
            recommendations.append("Update packages to fix pip-audit vulnerabilities")
        
        if outdated_result.get('status') == 'outdated':
            recommendations.append("Update outdated packages to latest versions")
        
        if license_result.get('status') == 'issues':
            recommendations.append("Review packages with problematic licenses")
        
        if not recommendations:
            recommendations.append("No security issues found - continue regular monitoring")
        
        report['summary']['recommendations'] = recommendations
        
        # Save report
        report_file = self.report_dir / f"security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Security report saved to {report_file}")
        
        return report
    
    def run_full_audit(self):
        """Run complete security audit"""
        logger.info("Starting comprehensive dependency security audit...")
        
        if not os.path.exists(self.requirements_file):
            logger.error(f"Requirements file {self.requirements_file} not found")
            return None
        
        # Run all security checks
        safety_result = self.run_safety_check()
        pip_audit_result = self.run_pip_audit()
        outdated_result = self.check_outdated_packages()
        license_result = self.analyze_licenses()
        
        # Generate comprehensive report
        report = self.generate_report(safety_result, pip_audit_result, outdated_result, license_result)
        
        # Print summary
        self.print_summary(report)
        
        return report
    
    def print_summary(self, report):
        """Print audit summary to console"""
        print("\n" + "="*60)
        print("DEPENDENCY SECURITY AUDIT SUMMARY")
        print("="*60)
        
        total_vulns = report['summary']['total_vulnerabilities']
        if total_vulns > 0:
            print(f"🚨 VULNERABILITIES FOUND: {total_vulns}")
        else:
            print("✅ NO VULNERABILITIES FOUND")
        
        print(f"\nSafety Check: {report['safety_scan']['status']}")
        print(f"Pip-Audit Check: {report['pip_audit_scan']['status']}")
        print(f"Outdated Packages: {report['outdated_packages']['status']}")
        print(f"License Analysis: {report['license_analysis']['status']}")
        
        print("\nRECOMMENDATIONS:")
        for i, rec in enumerate(report['summary']['recommendations'], 1):
            print(f"{i}. {rec}")
        
        print("\n" + "="*60)
        
        # Exit with non-zero code if vulnerabilities found
        if total_vulns > 0:
            sys.exit(1)

def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Dependency Security Audit Tool')
    parser.add_argument('--requirements', '-r', default='requirements.txt',
                       help='Path to requirements.txt file')
    parser.add_argument('--output-dir', '-o', default='security_reports',
                       help='Directory to save reports')
    
    args = parser.parse_args()
    
    auditor = DependencyAuditor(args.requirements)
    auditor.report_dir = Path(args.output_dir)
    auditor.report_dir.mkdir(exist_ok=True)
    
    report = auditor.run_full_audit()
    
    if report and report['summary']['total_vulnerabilities'] > 0:
        print(f"\n⚠️  Security issues found! Check {auditor.report_dir} for detailed report.")
        sys.exit(1)
    else:
        print(f"\n✅ Security audit passed! Report saved to {auditor.report_dir}")

if __name__ == '__main__':
    main()
