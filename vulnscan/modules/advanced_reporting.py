import matplotlib.pyplot as plt
import seaborn as sns
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from datetime import datetime
import json
import os
import base64
from io import BytesIO


class AdvancedSecurityReporter:
    def __init__(self, target, scan_results):
        self.target = target
        self.scan_results = scan_results
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.report_dir = f"reports/{self.target.replace('https://', '').replace('http://', '').replace('/', '_')}"
        os.makedirs(self.report_dir, exist_ok=True)

    def calculate_risk_score(self):
        """Calculate overall risk score based on findings"""
        severity_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 1
        }

        total_score = 0
        max_score = 0

        # Flatten all findings
        all_findings = self._flatten_findings()

        for finding in all_findings:
            if isinstance(finding, dict):
                severity = finding.get('severity', 'Low')
                total_score += severity_weights.get(severity, 0)
                max_score += severity_weights.get('Critical', 10)

        # Normalize to 0-100 scale
        if max_score > 0:
            risk_score = min(100, int((total_score / max_score) * 100))
        else:
            risk_score = 0

        return risk_score

    def _flatten_findings(self):
        """Flatten nested findings structure"""
        all_findings = []

        for category, findings in self.scan_results.get('findings', {}).items():
            if isinstance(findings, list):
                # Convert simple string results to dict format
                for finding in findings:
                    if isinstance(finding, str):
                        all_findings.append({
                            'type': category.replace('_', ' ').title(),
                            'severity': 'Info',
                            'description': finding
                        })
                    elif isinstance(finding, dict):
                        all_findings.append(finding)
            elif isinstance(findings, dict):
                # Handle nested structures like api_vulnerabilities
                for subcategory, subfindings in findings.items():
                    if isinstance(subfindings, list):
                        all_findings.extend(subfindings)
                    elif isinstance(subfindings, dict):
                        all_findings.append(subfindings)
            elif findings:
                # Handle single results
                all_findings.append({
                    'type': category.replace('_', ' ').title(),
                    'severity': 'Info',
                    'description': str(findings)
                })

        return all_findings

    def get_risk_color(self, risk_score):
        """Get color based on risk score"""
        if risk_score >= 90:
            return colors.red
        elif risk_score >= 70:
            return colors.orange
        elif risk_score >= 40:
            return colors.yellow
        else:
            return colors.green

    def generate_visualizations(self):
        """Generate visualizations for the report"""
        try:
            # Count vulnerabilities by severity
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

            all_findings = self._flatten_findings()

            for finding in all_findings:
                if isinstance(finding, dict):
                    severity = finding.get('severity', 'Low')
                    if severity in severity_counts:
                        severity_counts[severity] += 1

            # Create bar chart
            plt.figure(figsize=(10, 6))
            sns.barplot(x=list(severity_counts.keys()),
                        y=list(severity_counts.values()))
            plt.title('Vulnerability Severity Distribution')
            plt.xlabel('Severity')
            plt.ylabel('Count')
            plt.tight_layout()
            plt.savefig(f"{self.report_dir}/severity_distribution.png")
            plt.close()

            # Create pie chart
            plt.figure(figsize=(8, 8))
            plt.pie(list(severity_counts.values()), labels=list(
                severity_counts.keys()), autopct='%1.1f%%')
            plt.title('Vulnerability Severity Distribution')
            plt.tight_layout()
            plt.savefig(f"{self.report_dir}/severity_pie.png")
            plt.close()

            # Create risk gauge
            risk_score = self.calculate_risk_score()
            fig, ax = plt.subplots(figsize=(8, 6))

            # Create gauge
            gauge_colors = ['green', 'yellow', 'orange', 'red']
            gauge_limits = [0, 25, 50, 75, 100]

            # Draw gauge
            for i in range(len(gauge_limits)-1):
                ax.barh(0, gauge_limits[i+1]-gauge_limits[i], left=gauge_limits[i],
                        color=gauge_colors[i], height=0.5)

            # Draw needle
            ax.barh(0, risk_score, color='black', height=0.1)

            # Set labels
            ax.set_xlim(0, 100)
            ax.set_ylim(-0.5, 0.5)
            ax.set_yticks([])
            ax.set_xticks([0, 25, 50, 75, 100])
            ax.set_title(f'Risk Score: {risk_score}/100')

            plt.tight_layout()
            plt.savefig(f"{self.report_dir}/risk_gauge.png")
            plt.close()

        except Exception as e:
            print(f"Error generating visualizations: {e}")
            # Create placeholder images if visualization fails
            for img_name in ['severity_distribution.png', 'severity_pie.png', 'risk_gauge.png']:
                try:
                    fig, ax = plt.subplots(figsize=(6, 4))
                    ax.text(0.5, 0.5, 'Visualization Error',
                            ha='center', va='center')
                    ax.axis('off')
                    plt.savefig(f"{self.report_dir}/{img_name}")
                    plt.close()
                except:
                    pass

    def generate_pdf_report(self):
        """Generate comprehensive PDF report"""
        doc = SimpleDocTemplate(
            f"{self.report_dir}/security_report.pdf", pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue
        )
        story.append(
            Paragraph("Advanced Security Vulnerability Report", title_style))
        story.append(Spacer(1, 12))

        # Target and timestamp
        story.append(
            Paragraph(f"<b>Target:</b> {self.target}", styles['Normal']))
        story.append(
            Paragraph(f"<b>Scan Date:</b> {self.timestamp}", styles['Normal']))
        story.append(Spacer(1, 12))

        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        risk_score = self.calculate_risk_score()
        risk_color = self.get_risk_color(risk_score)

        # Fixed color formatting - use hex color without any modification
        story.append(Paragraph(
            f"<b>Risk Score:</b> <font color='{risk_color.hexval()}'>{risk_score}/100</font>", styles['Normal']))
        story.append(Spacer(1, 12))

        # Add visualizations
        self.generate_visualizations()

        # Add risk gauge
        if os.path.exists(f"{self.report_dir}/risk_gauge.png"):
            story.append(
                Image(f"{self.report_dir}/risk_gauge.png", width=4*inch, height=3*inch))
            story.append(Spacer(1, 12))

        # Add severity distribution
        if os.path.exists(f"{self.report_dir}/severity_distribution.png"):
            story.append(Image(
                f"{self.report_dir}/severity_distribution.png", width=6*inch, height=4*inch))
            story.append(Spacer(1, 12))

        # Detailed Findings
        story.append(Paragraph("Detailed Findings", styles['Heading2']))

        # Process all findings
        all_findings = self._flatten_findings()

        if all_findings:
            # Create table for findings
            data = [["Finding Type", "Severity", "Description"]]
            for finding in all_findings:
                if isinstance(finding, dict):
                    finding_type = finding.get(
                        'type', finding.get('vulnerability', 'Unknown'))
                    severity = finding.get('severity', 'Low')
                    description = finding.get('description', 'No description')

                    # Truncate long descriptions
                    if len(description) > 100:
                        description = description[:97] + "..."

                    data.append([finding_type, severity, description])

            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            story.append(table)
            story.append(Spacer(1, 12))
        else:
            story.append(
                Paragraph("No vulnerabilities found.", styles['Normal']))
            story.append(Spacer(1, 12))

        # Module-specific findings
        story.append(Paragraph("Module-Specific Findings", styles['Heading2']))

        for category, findings in self.scan_results.items():
            if category in ['target', 'timestamp']:
                continue

            if isinstance(findings, dict) and findings:
                story.append(Paragraph(category.replace(
                    '_', ' ').title(), styles['Heading3']))

                # Handle nested structures
                for subcategory, subfindings in findings.items():
                    if isinstance(subfindings, list) and subfindings:
                        story.append(Paragraph(subcategory.replace(
                            '_', ' ').title(), styles['Heading4']))

                        for finding in subfindings:
                            if isinstance(finding, dict):
                                story.append(Paragraph(
                                    f"<b>Type:</b> {finding.get('type', 'Unknown')}<br/>"
                                    f"<b>Severity:</b> {finding.get('severity', 'Low')}<br/>"
                                    f"<b>Description:</b> {finding.get('description', 'No description')}",
                                    styles['Normal']))
                                story.append(Spacer(1, 6))

            elif isinstance(findings, list) and findings:
                story.append(Paragraph(category.replace(
                    '_', ' ').title(), styles['Heading3']))

                for finding in findings:
                    if isinstance(finding, dict):
                        story.append(Paragraph(
                            f"<b>Type:</b> {finding.get('type', 'Unknown')}<br/>"
                            f"<b>Severity:</b> {finding.get('severity', 'Low')}<br/>"
                            f"<b>Description:</b> {finding.get('description', 'No description')}",
                            styles['Normal']))
                        story.append(Spacer(1, 6))

        # Recommendations
        story.append(Paragraph("Recommendations", styles['Heading2']))
        recommendations = self.generate_recommendations()
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", styles['Normal']))

        # Build PDF
        doc.build(story)
        return f"{self.report_dir}/security_report.pdf"

    def generate_html_report(self):
        """Generate interactive HTML report"""
        all_findings = self._flatten_findings()
        risk_score = self.calculate_risk_score()

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Report - {self.target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .section {{ margin-top: 20px; }}
                .finding {{ background-color: #fff; border: 1px solid #ddd; padding: 15px; margin-bottom: 10px; border-radius: 5px; }}
                .critical {{ border-left: 5px solid #d9534f; }}
                .high {{ border-left: 5px solid #f0ad4e; }}
                .medium {{ border-left: 5px solid #5bc0de; }}
                .low {{ border-left: 5px solid #5cb85c; }}
                .risk-score {{ font-size: 48px; font-weight: bold; text-align: center; }}
                .risk-low {{ color: #5cb85c; }}
                .risk-medium {{ color: #f0ad4e; }}
                .risk-high {{ color: #d9534f; }}
                .risk-critical {{ color: #8b0000; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .module-section {{ margin-top: 30px; border-top: 1px solid #ddd; padding-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Vulnerability Report</h1>
                <p><b>Target:</b> {self.target}</p>
                <p><b>Scan Date:</b> {self.timestamp}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="risk-score risk-{self.get_risk_class(risk_score)}">{risk_score}/100</div>
            </div>
            
            <div class="section">
                <h2>Findings Summary</h2>
                <table>
                    <tr>
                        <th>Category</th>
                        <th>Critical</th>
                        <th>High</th>
                        <th>Medium</th>
                        <th>Low</th>
                    </tr>
        """

        # Add summary table
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for finding in all_findings:
            if isinstance(finding, dict):
                severity = finding.get('severity', 'Low')
                if severity in severity_counts:
                    severity_counts[severity] += 1

        html_content += f"""
                    <tr>
                        <td>All Findings</td>
                        <td>{severity_counts['Critical']}</td>
                        <td>{severity_counts['High']}</td>
                        <td>{severity_counts['Medium']}</td>
                        <td>{severity_counts['Low']}</td>
                    </tr>
                </table>
            </div>
            
            <div class="section">
                <h2>Detailed Findings</h2>
        """

        # Add detailed findings
        for finding in all_findings:
            if isinstance(finding, dict):
                severity = finding.get('severity', 'Low').lower()
                finding_type = finding.get(
                    'type', finding.get('vulnerability', 'Unknown'))
                description = finding.get('description', 'No description')

                html_content += f"""
                <div class="finding {severity}">
                    <h4>{finding_type}</h4>
                    <p><b>Severity:</b> {finding.get('severity', 'Low')}</p>
                    <p><b>Description:</b> {description}</p>
                </div>
                """

        # Add module-specific findings
        html_content += """
            <div class="section">
                <h2>Module-Specific Findings</h2>
        """

        for category, findings in self.scan_results.items():
            if category in ['target', 'timestamp']:
                continue

            if isinstance(findings, dict) and findings:
                html_content += f"""
                <div class="module-section">
                    <h3>{category.replace('_', ' ').title()}</h3>
                """

                for subcategory, subfindings in findings.items():
                    if isinstance(subfindings, list) and subfindings:
                        html_content += f"""
                        <h4>{subcategory.replace('_', ' ').title()}</h4>
                        """

                        for finding in subfindings:
                            if isinstance(finding, dict):
                                severity = finding.get(
                                    'severity', 'Low').lower()
                                finding_type = finding.get('type', 'Unknown')
                                description = finding.get(
                                    'description', 'No description')

                                html_content += f"""
                                <div class="finding {severity}">
                                    <h5>{finding_type}</h5>
                                    <p><b>Severity:</b> {finding.get('severity', 'Low')}</p>
                                    <p><b>Description:</b> {description}</p>
                                </div>
                                """

                html_content += "</div>"

        # Add recommendations
        html_content += """
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
                <ul>
        """

        for rec in self.generate_recommendations():
            html_content += f"<li>{rec}</li>"

        html_content += """
                </ul>
            </div>
        </body>
        </html>
        """

        with open(f"{self.report_dir}/security_report.html", 'w') as f:
            f.write(html_content)

        return f"{self.report_dir}/security_report.html"

    def get_risk_class(self, risk_score):
        """Get CSS class for risk score"""
        if risk_score >= 90:
            return 'critical'
        elif risk_score >= 70:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        else:
            return 'low'

    def generate_json_report(self):
        """Generate JSON report for integration with other tools"""
        report = {
            "target": self.target,
            "scan_date": self.timestamp,
            "risk_score": self.calculate_risk_score(),
            "findings": self.scan_results,
            "recommendations": self.generate_recommendations()
        }

        with open(f"{self.report_dir}/security_report.json", 'w') as f:
            json.dump(report, f, indent=4)

        return f"{self.report_dir}/security_report.json"

    def generate_recommendations(self):
        """Generate recommendations based on findings"""
        recommendations = []
        all_findings = self._flatten_findings()

        # Check for critical vulnerabilities
        for finding in all_findings:
            if isinstance(finding, dict) and finding.get('severity') == 'Critical':
                vuln_type = finding.get('type', 'Unknown')
                if 'SQL Injection' in vuln_type:
                    recommendations.append(
                        "Implement parameterized queries or prepared statements to prevent SQL injection attacks.")
                elif 'XSS' in vuln_type:
                    recommendations.append(
                        "Implement Content Security Policy (CSP) and sanitize user input to prevent XSS attacks.")
                elif 'Subdomain Takeover' in vuln_type:
                    recommendations.append(
                        "Remove unused DNS records or verify ownership of all subdomains.")
                elif 'JWT' in vuln_type:
                    recommendations.append(
                        "Use strong secrets for JWT tokens and avoid using the 'none' algorithm.")

        # General recommendations
        recommendations.append(
            "Implement a Web Application Firewall (WAF) to protect against common attacks.")
        recommendations.append(
            "Regularly update and patch all software and dependencies.")
        recommendations.append(
            "Conduct regular security assessments and penetration testing.")
        recommendations.append(
            "Implement proper logging and monitoring for security events.")
        recommendations.append(
            "Follow the principle of least privilege for all user accounts and services.")

        return recommendations

    def generate_all_reports(self):
        """Generate all report formats"""
        pdf_report = self.generate_pdf_report()
        json_report = self.generate_json_report()
        html_report = self.generate_html_report()

        return {
            'pdf': pdf_report,
            'json': json_report,
            'html': html_report
        }
