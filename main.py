import re
import ipaddress

from recon.subdomain_enum import fetch_subdomains_crtsh
from recon.port_scanner import scan_ports
from recon.web_discovery import WebDiscovery

ascii_art = r"""


   _ (`-.  _  .-')                           ('-.             .-') _    
  ( (OO  )( \( -O )                        _(  OO)           (  OO) )   
 _.`     \ ,------.  .-'),-----.      ,--.(,------.   .-----./     '._  
(__...--'' |   /`. '( OO'  .-.  ' .-')| ,| |  .---'  '  .--./|'--...__) 
 |  /  | | |  /  | |/   |  | |  |( OO |(_| |  |      |  |('-.'--.  .--' 
 |  |_.' | |  |_.' |\_) |  |\|  || `-'|  |(|  '--.  /_) |OO  )  |  |    
 |  .___.' |  .  '.'  \ |  | |  |,--. |  | |  .--'  ||  |`-'|   |  |    
 |  |      |  |\  \    `'  '-'  '|  '-'  / |  `---.(_'  '--'\   |  |    
 `--'      `--' '--'     `-----'  `-----'  `------'   `-----'   `--'    
                ('-.     _  .-')     ('-.    .-')                                    
                ( OO ).-.( \( -O )  _(  OO)  ( OO ).                                  
                / . --. / ,------. (,------.(_)---\_)                                 
                | \-.  \  |   /`. ' |  .---'/    _ |                                  
                .-'-'  |  | |  /  | | |  |    \  :` `.                                  
                \| |_.'  | |  |_.' |(|  '--.  '..`''.)                                 
                |  .-.  | |  .  '.' |  .--' .-._)   \                                 
                |  | |  | |  |\  \  |  `---.\       /                                 
                `--' `--' `--' '--' `------' `-----'                                  


"""

def sanitize_domain(domain):
    domain = domain.strip().lower()
    if re.fullmatch(r"(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}", domain):
        return domain
    else:
        raise ValueError(f"Invalid domain provided: {domain}")

def sanitize_ipv4(ip_input):
    try:
        ipv4 = ipaddress.IPv4Address(ip_input.strip())
        return str(ipv4)
    except ipaddress.AddressValueError:
        raise ValueError(f"Invalid IPv4 address provided: {ip_input}")
    
def sanitize_selection(domain):
    domain = domain.strip().lower()
    if re.fullmatch(r"(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}", domain):
        return domain
    else:
        raise ValueError(f"Invalid domain provided: {domain}")
    



def main():
    print(ascii_art)
    print("\n")
    print("\n")
    print("Select an option from the menu below:")
    print("1. Recon")
    print("1. Vuln scanner")

    pattern = re.compile(r'[^\w.]')
    sanitized_input = pattern.sub('', input())
    if sanitized_input == "1":
        print("Which recon tool do you want to run?:")
        print("1. Domain enumeration")
        print("2. Port scanner")
        print("3. Web discovery")

        sanitized_input = pattern.sub('', input())
        if sanitized_input == "1":
            print("What is the domain you want to enumerate?:")
            sanitized_domain = sanitize_domain(input())
            fetch_subdomains_crtsh(sanitized_domain)
        elif sanitized_input == "2":
            print("What is the ip you want to scan?:")
            sanitized_domain = sanitize_domain(input())
            print(scan_ports(sanitized_domain))
        elif sanitized_input == "3":
            selected_domain = input("What is the domain you want to check?: ")
            WebDiscovery(sanitize_domain(selected_domain)).run_all()



if __name__ == '__main__':
    main()
