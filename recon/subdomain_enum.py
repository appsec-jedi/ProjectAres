import requests

def fetch_subdomains_crtsh(domain):
    print(f"Fetching {domain}")
    crtsh_url = f"https://crt.sh/?q=%.{domain}&output=json"
    response = requests.get(crtsh_url)
    if response.ok:
        subdomains = set()
        for entry in response.json():
            name_value = entry['common_name']
            if name_value not in subdomains:
                subdomains.update(name_value.split('\n'))
                print(name_value)
    else:
        print(f"No subdomains found for: {domain}")
