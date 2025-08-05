import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
import requests


class ModernSecurityPlatform:
    def __init__(self, target_url, config=None):
        self.target_url = target_url
        self.config = config or {}
        self.results = {
            'target': target_url,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'findings': {}
        }

    def run_comprehensive_scan(self):
        """Run a comprehensive security scan using all available modules"""
        print(
            f"\n[*] Starting comprehensive security scan for {self.target_url}")
        start_time = time.time()

        # Initialize all modules
        modules = {
            'domain_enumeration': self._run_domain_enumeration,
            'cloud_vulnerabilities': self._run_cloud_scan,
            'web_app_vulnerabilities': self._run_web_app_scan,
            'api_vulnerabilities': self._run_api_scan,
            'ai_findings': self._run_ai_scan
        }

        # Run modules in parallel
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                module_name: executor.submit(func)
                for module_name, func in modules.items()
            }

            for module_name, future in futures.items():
                try:
                    result = future.result()
                    self.results['findings'][module_name] = result
                    print(
                        f"[+] {module_name.replace('_', ' ').title()} completed")
                except Exception as e:
                    print(f"[-] Error in {module_name}: {str(e)}")
                    self.results['findings'][module_name] = {'error': str(e)}

        # Calculate scan statistics
        elapsed_time = time.time() - start_time
        self.results['scan_statistics'] = {
            'elapsed_time': elapsed_time,
            'modules_completed': len(modules),
            'total_findings': self._count_findings()
        }

        print(
            f"\n[+] Comprehensive scan completed in {elapsed_time:.2f} seconds")
        print(f"[+] Total findings: {self._count_findings()}")

        return self.results

    def _run_domain_enumeration(self):
        """Run advanced domain enumeration"""
        try:
            from .domain_passive_active_check import AdvancedSubdomainEnumerator
            enumerator = AdvancedSubdomainEnumerator(self.target_url)
            return enumerator.run_enumeration()
        except ImportError:
            print("[-] AdvancedSubdomainEnumerator module not found")
            return {'error': 'Module not available'}

    def _run_cloud_scan(self):
        """Run cloud vulnerability scanning"""
        try:
            from .cloud_vulnerability_checking import CloudSecurityScanner
            scanner = CloudSecurityScanner(self.target_url)
            return scanner.run_scan()
        except ImportError:
            print("[-] CloudSecurityScanner module not found")
            return {'error': 'Module not available'}

    def _run_web_app_scan(self):
        """Run advanced web application scanning"""
        try:
            from .web_app_checking import AdvancedWebAppTester
            scanner = AdvancedWebAppTester(self.target_url)
            return scanner.run_tests()
        except ImportError:
            print("[-] AdvancedWebAppTester module not found")
            return {'error': 'Module not available'}

    def _run_api_scan(self):
        """Run API security testing"""
        try:
            from .advanced_api_checking import GraphQLSecurityTester, APISecurityTester

            # Test GraphQL endpoints
            graphql_tester = GraphQLSecurityTester(self.target_url)
            graphql_results = graphql_tester.run_tests()

            # Test general API security
            api_tester = APISecurityTester(self.target_url)
            api_results = api_tester.run_tests()

            return {
                'graphql': graphql_results,
                'general': api_results
            }
        except ImportError:
            print("[-] API security modules not found")
            return {'error': 'Module not available'}

    def _run_ai_scan(self):
        """Run AI-powered vulnerability detection"""
        try:
            from .ai_powered_checking import AIVulnerabilityDetector
            detector = AIVulnerabilityDetector()

            # Get web content for AI analysis
            try:
                response = requests.get(f"https://{self.target_url}",
                                        headers={'User-Agent': 'Mozilla/5.0'},
                                        timeout=10)
                return detector.analyze_response(response.text)
            except Exception as e:
                return {'error': f'Failed to fetch content: {str(e)}'}
        except ImportError:
            print("[-] AIVulnerabilityDetector module not found")
            return {'error': 'Module not available'}

    def _count_findings(self):
        """Count total number of findings across all modules"""
        count = 0
        for module_name, findings in self.results['findings'].items():
            if isinstance(findings, dict):
                if 'error' in findings:
                    continue
                # Handle nested structures
                for key, value in findings.items():
                    if isinstance(value, list):
                        count += len(value)
                    elif isinstance(value, dict) and 'error' not in value:
                        count += 1
            elif isinstance(findings, list):
                count += len(findings)
        return count

    def generate_report(self, report_format='json'):
        """Generate a security report"""
        try:
            from .advanced_reporting import AdvancedSecurityReporter
            reporter = AdvancedSecurityReporter(self.target_url, self.results)

            if report_format == 'json':
                return reporter.generate_json_report()
            elif report_format == 'html':
                return reporter.generate_html_report()
            elif report_format == 'pdf':
                return reporter.generate_pdf_report()
            else:
                return reporter.generate_all_reports()
        except ImportError:
            print("[-] AdvancedSecurityReporter module not found")
            return None

    def export_to_security_tools(self):
        """Export findings to security tools"""
        try:
            from .advanced_reporting import SecurityToolIntegration
            tool_integration = SecurityToolIntegration()
            return tool_integration.export_all(self.results, self.target_url)
        except ImportError:
            print("[-] SecurityToolIntegration module not found")
            return None
