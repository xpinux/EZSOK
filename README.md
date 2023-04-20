# EZSOK - Easy Security Overview Kit

Easily scan your files, Hashes, IP addresses, domains, and emails using various security APIs.

## Table of Contents

- [Overview](#overview)
- [Features](#Features)
- [Installation](#installation)
- [Dependencies](#Dependencies)
- [Usage](#usage)
    - [Option 1: Enter Hash, IP, Domain, or Email](#option-1-enter-hash-ip-domain-or-email)
    - [Option 2: Provide File Path to Calculate Hash](#option-2-provide-file-path-to-calculate-hash)
    - [Option 3: Provide CSV File Path with Hashes, IPs, Domains, or Emails](#option-3-provide-csv-file-path-with-hashes-ips-domains-or-emails)
- [Tools and APIs used in this project](#Tools and APIs used in this project)
- [License](#License)
- [Disclaimer](#Disclaimer)
- [Credits](#credits)

## Overview

EZSOK is a Python script that helps you to scan your files, IP addresses, Hashes, domains, and emails using various security APIs. It uses the following APIs:

- VirusTotal
- AbuseIPDB
- UrlScan
- Shodan

## Features

- Scan files, hashes, IP addresses, domains, and emails using multiple security APIs
- Calculate file hashes (SHA-256) for scanning
- Process input data from CSV files

## Installation

1. Clone the repository:
`git clone https://github.com/yourusername/ezsok.git`
2. `pip install -r requirements.txt`
3. Replace the API keys in the script with your own:
`VIRUSTOTAL_API_KEY = 'your_api_key'
ABUSEIPDB_API_KEY = 'your_api_key'
URLSCAN_API_KEY = 'your_api_key'
SHODAN_API_KEY = 'your_api_key'
`
## Dependencies

- Python 3.6 or higher
- `requests`
- `tabulate`
- `ipaddress`

##Usage
Run the script using Python:
`python ezsok.py`

Choose one of the available options:

# Option 1: Enter Hash, IP, Domain, or Email
Enter a hash, IP, domain, or email, and the script will scan the input data using the available APIs.

Example: `Enter your choice (1, 2, or 3): 1
Enter hash, IP, domain, or email: example.com`

# Option 2: Provide File Path to Calculate Hash
Provide a file path, and the script will calculate the file's SHA-256 hash and scan the hash using the available APIs.

Example:`Enter your choice (1, 2, or 3): 2
Enter file path: /path/to/your/file.txt`

# Option 3: Provide CSV File Path with Hashes, IPs, Domains, or Emails
Provide a CSV file path containing hashes, IPs, domains, or emails. The script will read the CSV file and scan each input data using the available APIs.

Example:`Enter your choice (1, 2, or 3): 3
Enter CSV file path: /path/to/your/input.csv`

# Tools and APIs used in this project
    - [VirusTotal](https://www.virustotal.com/)
    - [AbuseIPDB](https://www.abuseipdb.com/)
    - [UrlScan](https://urlscan.io/)
    - [Shodan](https://www.shodan.io/)
    - [MalwareShare](https://www.malshare.com/)

# License

This project is licensed under the MIT License.

# Disclaimer

This tool is for educational purposes only. The authors and contributors are not responsible for any misuse or damage caused by this program. Always use with permission and follow the rules and regulations applicable in your region.

# Credits
Developed by Xpinux
