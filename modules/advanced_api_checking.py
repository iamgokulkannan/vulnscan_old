import requests
from urllib.parse import urljoin
import json
import re
from bs4 import BeautifulSoup
import time


class GraphQLSecurityTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.headers = {'Content-Type': 'application/json'}
        self.results = []

    def test_graphql_introspection(self):
        """Test for GraphQL introspection exposure"""
        introspection_query = {
            "query": """
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                    types {
                        ...FullType
                    }
                    directives {
                        name
                        description
                        locations
                        args {
                            ...InputValue
                        }
                    }
                }
            }
            fragment FullType on __Type {
                kind
                name
                description
                fields(includeDeprecated: true) {
                    name
                    description
                    args {
                        ...InputValue
                    }
                    type {
                        ...TypeRef
                    }
                    isDeprecated
                    deprecationReason
                }
                inputFields {
                    ...InputValue
                }
                interfaces {
                    ...TypeRef
                }
                enumValues(includeDeprecated: true) {
                    name
                    description
                    isDeprecated
                    deprecationReason
                }
                possibleTypes {
                    ...TypeRef
                }
            }
            fragment InputValue on __InputValue {
                name
                description
                type { ...TypeRef }
                defaultValue
            }
            fragment TypeRef on __Type {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                    ofType {
                                        kind
                                        name
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
        }

        try:
            response = requests.post(
                urljoin(self.target_url, '/graphql'),
                json=introspection_query,
                headers=self.headers
            )

            if response.status_code == 200 and '__schema' in response.text:
                self.results.append({
                    'type': 'GraphQL Introspection',
                    'severity': 'High',
                    'description': 'GraphQL introspection is enabled, exposing schema details',
                    'endpoint': urljoin(self.target_url, '/graphql')
                })

        except Exception as e:
            print(f"Error testing GraphQL introspection: {e}")

    def test_graphql_dos(self):
        """Test for GraphQL DoS vulnerabilities"""
        dos_query = {
            "query": """
            query {
                posts {
                    id
                    title
                    author {
                        id
                        name
                        posts {
                            id
                            title
                            author {
                                id
                                name
                                posts {
                                    id
                                    title
                                    author {
                                        id
                                        name
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
        }

        try:
            start_time = time.time()
            response = requests.post(
                urljoin(self.target_url, '/graphql'),
                json=dos_query,
                headers=self.headers,
                timeout=10
            )
            response_time = time.time() - start_time

            if response_time > 5:
                self.results.append({
                    'type': 'GraphQL DoS Vulnerability',
                    'severity': 'High',
                    'description': f"GraphQL endpoint is vulnerable to DoS attacks (response time: {response_time:.2f}s)",
                    'endpoint': urljoin(self.target_url, '/graphql')
                })

        except Exception as e:
            print(f"Error testing GraphQL DoS: {e}")

    def run_tests(self):
        """Run all GraphQL security tests"""
        self.test_graphql_introspection()
        self.test_graphql_dos()
        return self.results


class APISecurityTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.results = []

    def discover_api_endpoints(self):
        """Discover API endpoints in the target"""
        # Common API paths
        api_paths = [
            '/api', '/rest', '/graphql', '/v1', '/v2', '/v3',
            '/swagger', '/openapi.json', '/api-docs', '/docs'
        ]

        discovered_endpoints = []

        for path in api_paths:
            url = urljoin(self.target_url, path)
            try:
                response = requests.get(url, headers=self.headers, timeout=5)
                if response.status_code == 200:
                    discovered_endpoints.append({
                        'url': url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('Content-Type', '')
                    })

                    # Check for specific API indicators
                    if 'swagger' in response.text.lower() or 'openapi' in response.text.lower():
                        self.results.append({
                            'type': 'Exposed API Documentation',
                            'severity': 'Medium',
                            'description': f"API documentation is exposed at {url}",
                            'endpoint': url
                        })

                    if 'graphql' in response.text.lower():
                        self.results.append({
                            'type': 'GraphQL Endpoint',
                            'severity': 'Medium',
                            'description': f"GraphQL endpoint discovered at {url}",
                            'endpoint': url
                        })
            except:
                pass

        return discovered_endpoints

    def test_rest_api_security(self, endpoint):
        """Test REST API endpoints for common vulnerabilities"""
        # Test for common REST API vulnerabilities
        test_cases = [
            # Test for IDOR
            {'method': 'GET', 'params': {'id': 1}},
            # Test for SQL injection
            {'method': 'GET', 'params': {'id': "1' OR '1'='1"}},
            # Test for XSS
            {'method': 'GET', 'params': {
                'search': "<script>alert('XSS')</script>"}},
        ]

        for test in test_cases:
            try:
                if test['method'] == 'GET':
                    response = requests.get(
                        endpoint['url'],
                        params=test['params'],
                        headers=self.headers,
                        timeout=5
                    )

                # Check for vulnerability indicators
                if 'SQL syntax' in response.text.lower():
                    self.results.append({
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'description': f"Potential SQL injection in API endpoint: {endpoint['url']}",
                        'endpoint': endpoint['url']
                    })

                if '<script>' in response.text and 'XSS' in response.text:
                    self.results.append({
                        'type': 'XSS',
                        'severity': 'High',
                        'description': f"Potential XSS in API endpoint: {endpoint['url']}",
                        'endpoint': endpoint['url']
                    })

            except:
                pass

    def test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        # Common authentication endpoints
        auth_paths = ['/login', '/auth', '/signin', '/api/login', '/api/auth']

        for path in auth_paths:
            url = urljoin(self.target_url, path)
            try:
                # Test without authentication
                response = requests.get(url, headers=self.headers, timeout=5)

                # Test with common bypass techniques
                bypass_headers = self.headers.copy()
                bypass_headers['X-Original-URL'] = '/admin'
                bypass_headers['X-Rewrite-URL'] = '/admin'

                bypass_response = requests.get(
                    url, headers=bypass_headers, timeout=5)

                # Check if bypass was successful
                if bypass_response.status_code == 200 and 'admin' in bypass_response.text.lower():
                    self.results.append({
                        'type': 'Authentication Bypass',
                        'severity': 'Critical',
                        'description': f"Authentication bypass possible at {url}",
                        'endpoint': url
                    })

            except:
                pass

    def test_rate_limiting(self):
        """Test for rate limiting vulnerabilities"""
        # Test with rapid requests
        test_endpoint = urljoin(self.target_url, '/api')

        try:
            for i in range(10):
                response = requests.get(
                    test_endpoint, headers=self.headers, timeout=5)
                if response.status_code == 429:
                    # Rate limiting is in place
                    return

            # If we get here, rate limiting might not be in place
            self.results.append({
                'type': 'Missing Rate Limiting',
                'severity': 'Medium',
                'description': f"No rate limiting detected at {test_endpoint}",
                'endpoint': test_endpoint
            })

        except:
            pass

    def run_tests(self):
        """Run all API security tests"""
        print(f"[*] Running API security tests for {self.target_url}")

        # Discover API endpoints
        endpoints = self.discover_api_endpoints()

        # Test discovered endpoints
        for endpoint in endpoints:
            self.test_rest_api_security(endpoint)

        # Test for authentication bypass
        self.test_authentication_bypass()

        # Test rate limiting
        self.test_rate_limiting()

        return self.results
