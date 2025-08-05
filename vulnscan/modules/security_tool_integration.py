import requests
import json
import time
from datetime import datetime


class SecurityToolIntegration:
    def __init__(self, config_file=None):
        self.config = self.load_config(config_file)

    def load_config(self, config_file):
        """Load configuration from file"""
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return json.load(f)
        return {}

    def export_to_defectdojo(self, findings, target):
        """Export findings to DefectDojo"""
        if 'defectdojo' not in self.config:
            return False

        dd_config = self.config['defectdojo']
        url = f"{dd_config['url']}/api/v2/import-scan/"
        headers = {
            'Authorization': f"Token {dd_config['api_key']}",
            'Content-Type': 'application/json'
        }

        # Prepare findings for DefectDojo
        dd_findings = []

        # Flatten findings
        all_findings = self._flatten_findings(findings)

        for finding in all_findings:
            if isinstance(finding, dict):
                dd_findings.append({
                    'title': finding.get('type', 'Unknown'),
                    'description': finding.get('description', ''),
                    'severity': self._map_severity(finding.get('severity', 'Low')),
                    'url': finding.get('url', ''),
                    'tags': ['VulnScan']
                })

        data = {
            'scan_type': 'VulnScan Advanced',
            'test_title': f'Advanced Security Scan for {target}',
            'target_start': datetime.now().isoformat(),
            'target_end': datetime.now().isoformat(),
            'engagement_name': f'Continuous Security Monitoring',
            'product_name': target,
            'findings': dd_findings
        }

        try:
            response = requests.post(url, json=data, headers=headers)
            if response.status_code == 201:
                return True
            else:
                print(f"Error exporting to DefectDojo: {response.text}")
                return False
        except Exception as e:
            print(f"Error exporting to DefectDojo: {e}")
            return False

    def export_to_jira(self, findings, target):
        """Export findings to Jira"""
        if 'jira' not in self.config:
            return False

        jira_config = self.config['jira']
        url = f"{jira_config['url']}/rest/api/2/issue/"
        headers = {
            'Authorization': f"Basic {jira_config['auth']}",
            'Content-Type': 'application/json'
        }

        issues_created = 0

        # Flatten findings
        all_findings = self._flatten_findings(findings)

        # Create Jira issues for critical and high findings
        for finding in all_findings:
            if isinstance(finding, dict) and finding.get('severity') in ['Critical', 'High']:
                data = {
                    'fields': {
                        'project': {'key': jira_config['project']},
                        'summary': f"[Security] {finding.get('type', 'Unknown')} vulnerability in {target}",
                        'description': self._format_jira_description(finding, target),
                        'issuetype': {'name': 'Bug'},
                        'priority': {'name': 'Highest' if finding.get('severity') == 'Critical' else 'High'},
                        'labels': ['security', 'vulnscan']
                    }
                }

                try:
                    response = requests.post(url, json=data, headers=headers)
                    if response.status_code == 201:
                        issues_created += 1
                        print(
                            f"Created Jira issue: {response.json().get('key')}")
                    else:
                        print(f"Error creating Jira issue: {response.text}")
                except Exception as e:
                    print(f"Error creating Jira issue: {e}")

        return issues_created > 0

    def export_to_slack(self, findings, target):
        """Send summary to Slack"""
        if 'slack' not in self.config:
            return False

        slack_config = self.config['slack']
        url = slack_config['webhook_url']

        # Calculate summary statistics
        total_findings = 0
        critical_count = 0
        high_count = 0

        all_findings = self._flatten_findings(findings)

        for finding in all_findings:
            if isinstance(finding, dict):
                total_findings += 1
                if finding.get('severity') == 'Critical':
                    critical_count += 1
                elif finding.get('severity') == 'High':
                    high_count += 1

        # Prepare Slack message
        message = {
            'text': f"Security Scan Results for {target}",
            'attachments': [
                {
                    'color': 'danger' if critical_count > 0 else 'warning' if high_count > 0 else 'good',
                    'fields': [
                        {'title': 'Total Findings', 'value': str(
                            total_findings), 'short': True},
                        {'title': 'Critical', 'value': str(
                            critical_count), 'short': True},
                        {'title': 'High', 'value': str(
                            high_count), 'short': True},
                        {'title': 'Scan Date', 'value': datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"), 'short': True}
                    ]
                }
            ]
        }

        try:
            response = requests.post(url, json=message)
            return response.status_code == 200
        except Exception as e:
            print(f"Error sending Slack notification: {e}")
            return False

    def export_to_webhook(self, findings, target):
        """Export findings to custom webhook"""
        if 'webhook' not in self.config:
            return False

        webhook_config = self.config['webhook']
        url = webhook_config['url']
        headers = webhook_config.get(
            'headers', {'Content-Type': 'application/json'})

        # Prepare webhook payload
        payload = {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'findings': findings
        }

        try:
            response = requests.post(url, json=payload, headers=headers)
            return response.status_code == 200
        except Exception as e:
            print(f"Error sending webhook: {e}")
            return False

    def export_to_siem(self, findings, target):
        """Export findings to SIEM system"""
        if 'siem' not in self.config:
            return False

        siem_config = self.config['siem']

        # Format findings for SIEM (common format for Splunk, ELK, etc.)
        siem_events = []

        all_findings = self._flatten_findings(findings)

        for finding in all_findings:
            if isinstance(finding, dict):
                event = {
                    'timestamp': datetime.now().isoformat(),
                    'source': 'VulnScan',
                    'target': target,
                    'event_type': 'vulnerability',
                    'vulnerability': {
                        'type': finding.get('type', 'Unknown'),
                        'severity': finding.get('severity', 'Low'),
                        'description': finding.get('description', ''),
                        'url': finding.get('url', '')
                    }
                }
                siem_events.append(event)

        # Send to SIEM (example for Splunk HTTP Event Collector)
        if siem_config.get('type') == 'splunk':
            url = siem_config['url']
            headers = {
                'Authorization': f"Splunk {siem_config['token']}",
                'Content-Type': 'application/json'
            }

            try:
                for event in siem_events:
                    response = requests.post(url, json=event, headers=headers)
                    if response.status_code != 200:
                        print(f"Error sending to SIEM: {response.text}")
                        return False
                return True
            except Exception as e:
                print(f"Error sending to SIEM: {e}")
                return False

        return False

    def export_all(self, findings, target):
        """Export findings to all configured tools"""
        results = {
            'defectdojo': self.export_to_defectdojo(findings, target),
            'jira': self.export_to_jira(findings, target),
            'slack': self.export_to_slack(findings, target),
            'webhook': self.export_to_webhook(findings, target),
            'siem': self.export_to_siem(findings, target)
        }

        return results

    def _flatten_findings(self, findings):
        """Flatten nested findings structure"""
        all_findings = []

        if isinstance(findings, dict):
            for category, category_findings in findings.items():
                if category == 'target' or category == 'timestamp':
                    continue

                if isinstance(category_findings, dict):
                    # Handle nested structures
                    for subcategory, subfindings in category_findings.items():
                        if isinstance(subfindings, list):
                            all_findings.extend(subfindings)
                        elif isinstance(subfindings, dict):
                            all_findings.append(subfindings)
                elif isinstance(category_findings, list):
                    all_findings.extend(category_findings)
                elif category_findings:
                    all_findings.append({
                        'type': category.replace('_', ' ').title(),
                        'severity': 'Info',
                        'description': str(category_findings)
                    })

        return all_findings

    def _map_severity(self, severity):
        """Map VulnScan severity to DefectDojo severity"""
        severity_mapping = {
            'Critical': 'Critical',
            'High': 'High',
            'Medium': 'Medium',
            'Low': 'Low',
            'Info': 'Info'
        }
        return severity_mapping.get(severity, 'Low')

    def _format_jira_description(self, finding, target):
        """Format finding description for Jira"""
        return f"""
        *Vulnerability Type:* {finding.get('type', 'Unknown')}
        *Severity:* {finding.get('severity', 'Low')}
        *Description:* {finding.get('description', 'No description')}
        *Target:* {target}
        *URL:* {finding.get('url', 'N/A')}
        *Discovered by:* VulnScan
        *Discovery Date:* {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        """
