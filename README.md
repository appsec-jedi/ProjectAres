# ProjectAres

ProjectAres is an automated offensive security toolkit built with Python. It is designed for reconnaissance and preliminary vulnerability scanning, providing modular capabilities to perform tasks such as subdomain enumeration, port scanning, web discovery, and network discovery.

## Overview

ProjectAres enables security professionals to efficiently perform recon on both local and external networks. The project integrates multiple Python modules that:

- Enumerate subdomains via certificate transparency logs.
- Scan target hosts for open ports using nmap.
- Analyze web services and perform directory enumeration on web applications.
- Discover active hosts on a network by sending parallel ping requests.
- (Planned) Integrate vulnerability scanning functionalities.

The project leverages industry-standard tools like nmap, along with Python libraries such as `ipaddress`, `netifaces`, `socket`, and `concurrent.futures` for a comprehensive recon process.

## Features

- **Domain Enumeration:**  
  Extract subdomains using public services like crt.sh.
  
- **Port Scanning:**  
  Use nmap to probe and identify open ports and running services.
  
- **Web Discovery:**  
  Analyze HTTP headers, crawl web pages, and perform directory enumeration.
  
- **Network Discovery:**  
  Identify active hosts on a local network using ping sweeps with concurrent execution.
  
- **Input Sanitization:**  
  Validate and sanitize user-supplied domain names and IP addresses.

## Getting Started

### Prerequisites

- **Python 3.8+**  
- **nmap:** Ensure that the nmap tool is installed on your system.  
  - **macOS:** `brew install nmap`  
  - **Ubuntu/Debian:** `sudo apt-get install nmap`  
  - **Windows:** Download and install from the [nmap website](https://nmap.org/)
  
- **Python Libraries:**  
  Install the required Python packages. For example, create and activate a virtual environment, then run: pip install -r requirements.txt

### Installation

- **Clone the repository:** `git clone <https://github.com/yourusername/ProjectAres.git>`
- **Navigate to the project directory:** `cd ProjectAres`
- **Create a virtual environment and activate it:** `python3 -m venv myenv / source myenv/bin/activate`
- **Install dependencies:** `pip install -r requirements.txt`

### Usage

- Run the main program using the following command: `python main.py`
- Upon running the script, you will see the ProjectAres ASCII art followed by a menu:
- Recon: Select from options for domain enumeration, port scanning, web discovery, or network discovery.
- Vuln Scanner: A placeholder for future integration of vulnerability scanning capabilities.

- For example, selecting “1” for Recon will then prompt you to choose one of the recon tools:

    1. Subdomain Enumeration: Enter a domain name to enumerate subdomains.
    2. Port Scanner: Enter an IP address to scan open ports.
    3. Web Discovery: Enter a domain name to perform web recon.
    4. Network Discovery: Launch a network discovery routine to identify active hosts on your local network.

The scripts incorporate input sanitization and error handling to ensure reliable operations.

### Contributing

Contributions are welcome! If you’d like to improve ProjectAres, please fork the repository and submit a pull request. For major changes, please open an issue first to discuss what you’d like to change.

### License

This project is licensed under the MIT License

### Disclaimer

ProjectAres is intended for educational purposes only. Unauthorized scanning of networks and hosts is illegal and unethical. Always ensure you have explicit permission before scanning networks you do not own.
