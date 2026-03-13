import re
import urllib.parse
import socket

class PhishingDetector:
    def __init__(self):
        # Common keywords used in phishing attacks to impersonate legitimate services
        self.suspicious_keywords = [
            'login', 'secure', 'account', 'update', 'banking', 'verify',
            'webscr', 'password', 'credential', 'support', 'service',
            'billing', 'invoice', 'confirm'
        ]
        
        # Popular URL shortening services that might obscure malicious links
        self.shortening_services = [
            'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'v.gd'
        ]

    def check_ip_in_url(self, domain):
        """Check if the domain is an IP address instead of a hostname."""
        # Strip out any port numbers first
        domain = domain.split(':')[0]
        try:
            socket.inet_aton(domain)
            return True
        except socket.error:
            return False

    def check_url_length(self, url, max_length=75):
        """Cybercriminals often use overly long URLs to hide the actual domain."""
        return len(url) > max_length

    def check_at_symbol(self, url):
        """The @ symbol leads the browser to ignore everything preceding it."""
        return '@' in url

    def check_redirects(self, path):
        """Check for multiple redirects (//) in the path."""
        # We only check the path, to avoid flagging http:// or https://
        return '//' in path

    def check_dash_in_domain(self, domain):
        """Some phishing domains use dashes to mimic legitimate site names (e.g. www.paypal-update.com)"""
        return '-' in domain

    def check_subdomains(self, domain):
        """Phishers often use many subdomains to look legitimate."""
        # Removing 'www.' if it exists to not count it
        if domain.startswith('www.'):
            domain = domain[4:]
        parts = domain.split('.')
        # E.g., login.update.paypal.xyz has 4 parts. Normal sites usually have 2 or 3 (e.g. example.co.uk)
        return len(parts) > 3

    def check_shortening_service(self, domain):
        """Check if the URL uses a known URL shortening service."""
        return any(service in domain.lower() for service in self.shortening_services)

    def check_suspicious_keywords(self, url):
        """Check for common phishing keywords in the URL."""
        url_lower = url.lower()
        return [keyword for keyword in self.suspicious_keywords if keyword in url_lower]

    def analyze_url(self, url):
        """Analyze a URL and return a risk score and identified risks."""
        original_url = url
        # Ensure URL has a scheme for proper parsing, defaulting to http
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url

        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
        except Exception as e:
            return {"status": "error", "message": f"Invalid URL format: {str(e)}"}

        risks = []
        score = 0

        if self.check_ip_in_url(domain):
            risks.append("Uses IP address instead of domain name")
            score += 3
            
        if self.check_url_length(url):
            risks.append("Unusually long URL length")
            score += 1

        if self.check_at_symbol(url):
            risks.append("Contains '@' symbol (obscures actual destination)")
            score += 3

        if self.check_redirects(path):
            risks.append("Contains suspicious redirect sequence (//) within the path")
            score += 2

        if self.check_dash_in_domain(domain):
            risks.append("Contains dash(es) in domain name")
            score += 1

        if self.check_subdomains(domain):
            risks.append("Contains unusually high number of subdomains")
            score += 2

        if self.check_shortening_service(domain):
            risks.append("Uses a known URL shortening service")
            score += 2

        found_keywords = self.check_suspicious_keywords(url)
        if found_keywords:
            risks.append(f"Contains suspicious generic keywords: {', '.join(found_keywords)}")
            score += 2

        # Calculate severity based on score
        severity = "Safe/Low Risk"
        if score >= 5:
            severity = "High Risk (Likely Phishing)"
        elif score >= 3:
            severity = "Medium Risk (Suspicious)"

        return {
            "url": original_url,
            "risk_score": score,
            "severity": severity,
            "identified_risks": risks,
            "is_likely_phishing": score >= 5
        }

if __name__ == "__main__":
    detector = PhishingDetector()
    
    # A mix of legitimate and suspicious URLs
    test_urls = [
        "https://www.google.com",
        "https://github.com/login", # Legitimate but contains 'login', could raise mild suspicion
        "http://192.168.1.1/login.php",
        "https://secure-update.paypal.com.verification-process.xyz",
        "http://bit.ly/123qwe",
        "https://www.mybank.com@phishing-site.com/login"
    ]
    
    print("="*60)
    print("   🔍 PHISHING DETECTION TOOL TEST RUN 🔍   ")
    print("="*60)
    
    for url in test_urls:
        result = detector.analyze_url(url)
        print(f"\nTarget URL: {url}")
        if result.get("status") == "error":
            print(f"Error: {result['message']}")
            continue
            
        print(f"Severity  : {result['severity']} (Score: {result['risk_score']})")
        
        if result['identified_risks']:
            print("Risks Identified:")
            for risk in result['identified_risks']:
                print(f"  [!] {risk}")
        else:
            print("  [✓] No obvious risks identified based on simple heuristics.")
            
    print("\n" + "="*60)
