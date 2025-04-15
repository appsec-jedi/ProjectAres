import requests
from bs4 import BeautifulSoup
import concurrent.futures

class WebDiscovery:
    def __init__(self, target):
        self.target = target
        self.base_url = f"http://{target}"

    def detect_http_services(self):
        ports = [80, 443, 8080, 8443]
        active_services = []
        for port in ports:
            for scheme in ["http", "https"]:
                url = f"{scheme}://{self.target}:{port}"
                try:
                    response = requests.get(url, timeout=3)
                    # Consider any status < 400 as a sign of an active service
                    if response.status_code < 400:
                        active_services.append(url)
                except requests.RequestException:
                    continue
        return active_services

    def analyze_headers(self, target):
        try:
            response = requests.get(target, timeout=3)
            headers = response.headers
            security_headers = [
                "X-Frame-Options", 
                "Strict-Transport-Security", 
                "Content-Security-Policy", 
                "X-Content-Type-Options"
            ]
            missing = [header for header in security_headers if header not in headers]
            return {"url": target, "headers": headers, "missing_security_headers": missing}
        except requests.RequestException as e:
            return {"url": target, "error": str(e)}

    def crawl_website(self, start_url, max_depth=2):
        visited = set()
        to_visit = [(start_url, 0)]
        
        while to_visit:
            url, depth = to_visit.pop(0)
            if depth > max_depth or url in visited:
                continue
            visited.add(url)
            try:
                response = requests.get(url, timeout=5)
                soup = BeautifulSoup(response.text, "html.parser")
                for link in soup.find_all("a", href=True):
                    absolute_link = requests.compat.urljoin(url, link["href"])
                    # Only follow links within the same target domain
                    if start_url in absolute_link and absolute_link not in visited:
                        to_visit.append((absolute_link, depth + 1))
            except requests.RequestException:
                continue
        return list(visited)

    def enumerate_directories(self, base_url):
        wordlist = ["admin", "login", "dashboard", "config", "backup"]
        discovered = []
        def probe_directory(word):
            test_url = f"{base_url}/{word}"
            try:
                response = requests.get(test_url, timeout=2)
                if response.status_code in [200, 301, 302, 403]:
                    return test_url
            except requests.RequestException:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(probe_directory, wordlist)
        for result in results:
            if result:
                discovered.append(result)
        return discovered

    def check_default_pages(self, url):
        default_paths = ["admin", "login", "dashboard", "wp-admin"]
        found = []
        for path in default_paths:
            test_url = f"{url}/{path}"
            try:
                response = requests.get(test_url, timeout=3)
                if response.status_code in [200, 301, 302]:
                    found.append(test_url)
            except requests.RequestException:
                continue
        return found

    def run_all(self):
        print(f"Running all on {self.base_url}")
        services = self.detect_http_services()
        for service in services:
            print(f"Analyzing: {service}")
            header_info = self.analyze_headers(service)
            print(header_info)
            crawled = self.crawl_website(service)
            print("Crawled URLs:", crawled)
            directories = self.enumerate_directories(service)
            print(f"Directories found: {directories}")
            pages = self.check_default_pages(service)
            print(f"Default pages found: {pages}")