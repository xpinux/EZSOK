import hashlib
import requests
import requests.exceptions
import csv
import ipaddress
from tabulate import tabulate

# Replace with your API keys
VIRUSTOTAL_API_KEY = ''
ABUSEIPDB_API_KEY = ''
URLSCAN_API_KEY = ''
SHODAN_API_KEY = ''
MALWARESHARE_API_KEY = ''

def read_csv(file_path):
    with open(file_path, 'r') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        input_data_list = []
        for row in reader:
            for item in row:
                input_data_list.append(item.strip())
    return input_data_list

        
def get_file_hash(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
        file_hash = hashlib.sha256(data).hexdigest()
    return file_hash


def virustotal_scan(input_data):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    url = f'https://www.virustotal.com/api/v3/search?query={input_data}'
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error while calling VirusTotal API: {e}")
        return {}
    return response.json()

def abuseipdb_scan(ip):
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}'
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error while calling AbuseIPDB API: {e}")
        return {}
    return response.json()

def urlscan_scan(domain):
    headers = {
        'API-Key': URLSCAN_API_KEY
    }
    url = f'https://urlscan.io/api/v1/search/?q=domain:{domain}'
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error while calling UrlScan API: {e}")
        return {}
    return response.json()

def shodan_scan(ip):
    url = f'https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}'
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error while calling Shodan API: {e}")
        return {}
    return response.json()

def extract_virustotal_data(data):
    if not data:
        return []

    results = []
    for result in data['data']:
        last_analysis_stats = result['attributes']['last_analysis_stats']
        malicious = last_analysis_stats.get('malicious', 0)
        suspicious = last_analysis_stats.get('suspicious', 0)
        harmless = last_analysis_stats.get('harmless', 0)
        undetected = last_analysis_stats.get('undetected', 0)
        total = malicious + suspicious + harmless + undetected
        results.append({
            'ID': result['id'],
            'Type': result['type'],
            'Detections': f"{malicious} / {total}"
        })
    return results




def extract_abuseipdb_data(data):
    if 'data' in data:
        return [
            {'Attribute': 'IP', 'Value': data['data']['ipAddress']},
            {'Attribute': 'Domain', 'Value': data['data'].get('domain', 'N/A')},
            {'Attribute': 'Usage Type', 'Value': data['data'].get('usageType', 'N/A')},
            {'Attribute': 'ISP', 'Value': data['data'].get('isp', 'N/A')},
            {'Attribute': 'Country', 'Value': data['data'].get('countryName', 'N/A')},
            {'Attribute': 'Total Reports', 'Value': data['data']['totalReports']},
            {'Attribute': 'Last Report', 'Value': data['data']['lastReportedAt']}
        ]
    return []



def extract_urlscan_data(data):
    if 'results' in data:
        results = []
        for result in data['results']:
            try:
                url = result['page']['url']
                status = result['page']['status']
                results.append({'URL': url, 'Status': status})
            except KeyError:
                print("Warning: Unexpected API response format.")
        return results
    return []



def extract_shodan_data(data):
    if data:
        return [
            {'Attribute': 'IP', 'Value': data['ip_str']},
            {'Attribute': 'Hostname', 'Value': ', '.join(data.get('hostnames', []))},
            {'Attribute': 'City', 'Value': data.get('city', 'N/A')},
            {'Attribute': 'Country', 'Value': data.get('country_name', 'N/A')},
            {'Attribute': 'ISP', 'Value': data.get('isp', 'N/A')},
            {'Attribute': 'Organisation', 'Value': data.get('org', 'N/A')},
            {'Attribute': 'Operating System', 'Value': data.get('os', 'N/A')},
            {'Attribute': 'Ports', 'Value': ', '.join(map(str, data.get('ports', [])))},
        ]
    return []


def display_results(scan_name, data, headers):
    print(f"\n{scan_name} Scan:")
    if data:
        formatted_data = [headers]
        for item in data:
            if isinstance(item, dict):
                formatted_data.append([item[header] for header in headers])
            elif isinstance(item, list):
                formatted_data.append(item)
        print(tabulate(formatted_data, headers="firstrow", tablefmt="grid"))
    else:
        print("No results found")



def main():
    try:
        print("Select option:")
        print("1. Enter hash, IP, domain, or email")
        print("2. Provide file path to calculate hash")
        print("3. Provide CSV file path with hashes, IPs, domains, or emails")
        choice = int(input("Enter your choice (1, 2, or 3): "))
    except ValueError:
        print("Invalid input. Please enter a valid number.")
        return

    if choice == 1:
        input_data = input("Enter hash, IP, domain, or email: ")
        input_data_list = [input_data]
    elif choice == 2:
        file_path = input("Enter file path: ")
        try:
            file_hash = get_file_hash(file_path)
            input_data_list = [file_hash]
            print(f"File hash: {file_hash}")
        except FileNotFoundError:
            print("Error: File not found.")
            return
        except IOError as e:
            print(f"Error while reading the file: {e}")
            return
    elif choice == 3:
        csv_file_path = input("Enter CSV file path: ")
        try:
            input_data_list = read_csv(csv_file_path)
            print(f"Input data list: {input_data_list}")
        except FileNotFoundError:
            print("Error: CSV file not found.")
            return
        except Exception as e:
            print(f"Error while reading the CSV file: {e}")
            return
    else:
        print("Invalid choice.")
        return

    for i, input_data in enumerate(input_data_list):
        print(f"\nScan {i+1}: {input_data}")
        display_results("VirusTotal", extract_virustotal_data(virustotal_scan(input_data)), ['ID', 'Type', 'Detections'])

        if "." in input_data:  # Assuming it's an IP address or domain
            display_results("AbuseIPDB", extract_abuseipdb_data(abuseipdb_scan(input_data)), ['Attribute', 'Value'])
            display_results("UrlScan", extract_urlscan_data(urlscan_scan(input_data)), ['URL', 'Status'])
        try:  # Check if input data is a valid IP address for Shodan scan
            ipaddress.ip_address(input_data)
            display_results("Shodan", extract_shodan_data(shodan_scan(input_data)), ['Attribute', 'Value'])
        except ValueError:
            pass

if __name__ == "__main__":
    main()

