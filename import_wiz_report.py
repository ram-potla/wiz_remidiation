# import_wiz_report.py
import csv
import json
import yaml
from pathlib import Path
from datetime import datetime

class WizReportProcessor:
    def __init__(self, report_path: str, services_config: str):
        self.report_path = report_path
        self.services = self.load_services(services_config)
        self.kb_path = Path("knowledge-base")
    
    def load_services(self, config_path: str) -> dict:
        """Load service repository mappings"""
        with open(config_path) as f:
            config = yaml.safe_load(f)
        return config['services']
    
    def process_csv_report(self):
        """Process Wiz CSV report"""
        vulnerabilities = []
        
        with open(self.report_path) as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                vuln = self.parse_vulnerability(row)
                vulnerabilities.append(vuln)
                self.save_vulnerability(vuln)
        
        print(f"✅ Processed {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def parse_vulnerability(self, row: dict) -> dict:
        """Parse a row from Wiz report"""
        
        # Extract service name from resource
        service_name = self.extract_service_name(row.get('Service', ''))
        
        # Map vulnerability type
        vuln_type = self.map_vulnerability_type(row.get('Type', ''))
        
        # Structure the data
        vuln = {
            "id": row.get('IssueID', '').strip(),
            "wiz_id": row.get('IssueID', '').strip(),
            "severity": row.get('Severity', 'MEDIUM').upper().strip(),
            "type": vuln_type,
            "service": service_name,
            
            # File information
            "file_path": row.get('FilePath', '').strip(),
            "line_number": self.parse_line_number(row.get('LineNumber', '')),
            
            # Description
            "title": row.get('Type', '').strip(),
            "description": row.get('Description', '').strip(),
            "recommendation": row.get('Recommendation', '').strip(),
            
            # Repository info (from mapping)
            "repo_url": self.services.get(service_name, {}).get('repo_url', ''),
            "default_branch": self.services.get(service_name, {}).get('default_branch', 'main'),
            
            # Metadata
            "imported_at": datetime.now().isoformat(),
            "status": "OPEN",
        }
        
        # Add dependency-specific info if applicable
        if vuln_type == 'dependency':
            vuln['package_name'] = self.extract_package_name(row.get('Description', ''))
            vuln['current_version'] = self.extract_current_version(row.get('Description', ''))
            vuln['fixed_version'] = self.extract_fixed_version(row.get('Recommendation', ''))
        
        return vuln
    
    def extract_service_name(self, resource: str) -> str:
        """Extract service name from resource identifier"""
        # Examples:
        # "auth-service-deployment-abc123" → "auth-service"
        # "payment-service" → "payment-service"
        # "k8s-user-service-pod" → "user-service"
        
        resource_lower = resource.lower()
        
        # Check known services
        for service_name in self.services.keys():
            if service_name in resource_lower:
                return service_name
        
        # Fallback: extract first part
        parts = resource.split('-')
        if len(parts) >= 2:
            return f"{parts[0]}-{parts[1]}"
        
        return resource
    
    def map_vulnerability_type(self, wiz_type: str) -> str:
        """Map Wiz vulnerability type to our fix pattern types"""
        
        type_lower = wiz_type.lower()
        
        # SQL Injection
        if 'sql injection' in type_lower or 'sqli' in type_lower:
            return 'sql-injection'
        
        # XSS
        if 'xss' in type_lower or 'cross-site scripting' in type_lower:
            return 'xss'
        
        # Dependencies
        if 'cve' in type_lower or 'vulnerable package' in type_lower or 'outdated dependency' in type_lower:
            return 'dependency'
        
        # Secrets
        if 'hardcoded' in type_lower or 'secret' in type_lower or 'credential' in type_lower:
            return 'hardcoded-secret'
        
        # Configuration
        if 'misconfiguration' in type_lower:
            return 'configuration'
        
        return 'generic'
    
    def parse_line_number(self, line_str: str) -> int:
        """Parse line number from string"""
        try:
            return int(line_str) if line_str and line_str != 'N/A' else None
        except ValueError:
            return None
    
    def extract_package_name(self, description: str) -> str:
        """Extract package name from description"""
        # Example: "log4j version 2.14.0 has CVE-2021-44228"
        # Should extract: "log4j"
        
        import re
        # Look for common patterns
        match = re.search(r'(\w+(?:-\w+)*)\s+version', description, re.IGNORECASE)
        if match:
            return match.group(1)
        
        return ""
    
    def extract_current_version(self, description: str) -> str:
        """Extract current version from description"""
        import re
        match = re.search(r'version\s+([\d.]+)', description, re.IGNORECASE)
        if match:
            return match.group(1)
        return ""
    
    def extract_fixed_version(self, recommendation: str) -> str:
        """Extract fixed version from recommendation"""
        import re
        match = re.search(r'update\s+to\s+([\d.]+)', recommendation, re.IGNORECASE)
        if match:
            return match.group(1)
        return ""
    
    def save_vulnerability(self, vuln: dict):
        """Save vulnerability to Knowledge Base"""
        
        service_name = vuln['service']
        vuln_id = vuln['id']
        
        # Create directory structure
        service_dir = self.kb_path / "vulnerabilities" / service_name
        service_dir.mkdir(parents=True, exist_ok=True)
        
        # Save vulnerability
        vuln_file = service_dir / f"{vuln_id}.json"
        with open(vuln_file, 'w') as f:
            json.dump(vuln, f, indent=2)
    
    def generate_summary(self, vulnerabilities: list):
        """Generate summary report"""
        
        summary = {
            "import_date": datetime.now().isoformat(),
            "total_vulnerabilities": len(vulnerabilities),
            "by_severity": {},
            "by_type": {},
            "by_service": {}
        }
        
        for vuln in vulnerabilities:
            # By severity
            severity = vuln['severity']
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # By type
            vuln_type = vuln['type']
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
            
            # By service
            service = vuln['service']
            summary['by_service'][service] = summary['by_service'].get(service, 0) + 1
        
        # Save summary
        summary_file = self.kb_path / "import_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print("\n📊 Summary:")
        print(f"Total: {summary['total_vulnerabilities']}")
        print(f"By Severity: {summary['by_severity']}")
        print(f"By Type: {summary['by_type']}")
        print(f"By Service: {summary['by_service']}")
        
        return summary


# Usage
if __name__ == "__main__":
    processor = WizReportProcessor(
        report_path="wiz_report.csv",
        services_config="service-repos.yml"
    )
    
    vulnerabilities = processor.process_csv_report()
    processor.generate_summary(vulnerabilities)