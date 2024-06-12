import requests
import sys
import json
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.exceptions import RequestException, ConnectionError, Timeout
from tqdm import tqdm
from colorama import Fore, Style
import time
import subprocess

# List of patterns to identify parameters potentially vulnerable to SQLi
patterns = [
    "id=", "select=", "report=", "role=", "update=", "query=", "user=",
    "name=", "sort=", "where=", "search=", "params=", "process=", "row=",
    "view=", "table=", "from=", "sel=", "results=", "sleep=", "fetch=",
    "order=", "keyword=", "column=", "field=", "delete=", "string=",
    "number=", "filter="
]

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def waybackfinder(host):
    """
    Fetches URLs from the Wayback Machine for a given host, including subdomains.

    Args:
        host (str): The domain to search for in the Wayback Machine.

    Returns:
        list: A list of URLs from the Wayback Machine.
    """
    url = f'http://web.archive.org/cdx/search/cdx?url=*.{host}/*&output=json&fl=original&collapse=urlkey'
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        results = r.json()
        return results[1:]
    except ConnectionError as e:
        logging.error(f"Connection error fetching URLs for {host}: {e}")
    except Timeout as e:
        logging.error(f"Timeout error fetching URLs for {host}: {e}")
    except RequestException as e:
        logging.error(f"Error fetching URLs for {host}: {e}")
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON response for {host}: {e}")
    return []

def check_sqli(endpoint):
    """
    Checks if an endpoint contains any patterns indicating potential SQLi vulnerability.

    Args:
        endpoint (str): The URL to check for SQLi patterns.

    Returns:
        bool: True if any pattern is found, False otherwise.
    """
    return any(pattern in endpoint for pattern in patterns)

def fetch_urls_for_domain(domain, rate_limit):
    """
    Fetches URLs for a given domain.

    Args:
        domain (str): The domain to fetch URLs for.
        rate_limit (float): The rate limit in seconds between requests.

    Returns:
        list: A list of URLs for the domain.
    """
    logging.info(f"Fetching URLs for domain: {domain}")
    urls = waybackfinder(domain)
    time.sleep(rate_limit)
    return urls

def check_proxychains():
    """
    Checks if proxychains is working by attempting to connect to google.com.

    Returns:
        bool: True if proxychains is working, False otherwise.
    """
    try:
        result = subprocess.run(['proxychains', 'curl', '-I', 'https://www.google.com'], capture_output=True, text=True, timeout=20)
        if "HTTP/2 200" in result.stdout:
            return True
    except Exception as e:
        logging.error(f"Proxychains test failed: {e}")
    return False

def main():
    print(Fore.YELLOW + "Tool Made with love by Albert C" + Style.RESET_ALL)
    print(Fore.YELLOW + "Version: 1.0.0" + Style.RESET_ALL)

    parser = argparse.ArgumentParser(
        description='''SQLi Hunter - A tool to find potential SQL injection vulnerabilities
        by fetching URLs from the Wayback Machine and checking for common SQLi patterns.
        
        Disclaimer: Increasing the rate limit may cause Wayback Machine to close the connection.
        A recommended rate limit is between 1 and 2 seconds.

        Usage examples:
        subfinder -d testphp.vulnweb.com -all -silent | python3 sqlihunter.py -o sqliurls.txt -r 1
        python3 sqlihunter.py -f domains.txt -o sqliurls.txt -r 2
        subfinder -d testphp.vulnweb.com -all -silent | python3 sqlihunter.py -o sqliurls.txt; sqlmap -m sqliurls.txt --batch --dbs --risk 2 --level 5 --random-agent | tee -a sqli.txt
        proxychains subfinder -d testphp.vulnweb.com -all -silent | proxychains python3 sqlihunter.py -o sqliurls.txt -r 1
        ''')
    parser.add_argument('-f', '--file', type=str, help='Input file with domains')
    parser.add_argument('-o', '--output', type=str, required=True, help='Output file to save potential SQLi endpoints')
    parser.add_argument('-r', '--rate', type=float, default=0, help='Rate limit in seconds between requests (default: 0). Recommended between 1 and 2 seconds.')
    parser.add_argument('--use-proxychains', action='store_true', help='Use proxychains for network requests')
    args = parser.parse_args()

    input_file = args.file
    output_file = args.output
    rate_limit = args.rate
    use_proxychains = args.use_proxychains

    if use_proxychains:
        print(Fore.YELLOW + "Checking if proxychains is working..." + Style.RESET_ALL)
        if not check_proxychains():
            print(Fore.RED + "Proxychains is not working. Please check your configuration." + Style.RESET_ALL)
            sys.exit(1)
        else:
            print(Fore.GREEN + "Proxychains is working." + Style.RESET_ALL)

    if input_file:
        with open(input_file, 'r') as f:
            domains = f.read().splitlines()
    else:
        print(Fore.YELLOW + "Reading domains from stdin..." + Style.RESET_ALL)
        domains = sys.stdin.read().splitlines()

    all_urls = set()

    print("Processing domains...\n")

    # Use a ThreadPoolExecutor to parallelize the requests
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_urls_for_domain, domain, rate_limit): domain for domain in domains}
        
        width = 50  # Set the width of the progress bar
        for future in tqdm(as_completed(futures), total=len(futures), desc="Fetching URLs", unit="domain", ncols=width):
            domain = futures[future]
            try:
                urls = future.result()
                for url in urls:
                    all_urls.add(url[0])
                print(f"Processed domain: {domain}")
            except Exception as e:
                logging.error(f"Error processing domain {domain}: {e}")

    print("\nChecking for potential SQLi vulnerabilities...\n")
    
    potential_sqli_endpoints = [url for url in tqdm(all_urls, desc="Checking URLs", unit="url", ncols=width) if check_sqli(url)]

    with open(output_file, 'w') as f:
        for endpoint in potential_sqli_endpoints:
            f.write(endpoint + "\n")

    logging.info(f"Potential SQLi endpoints saved to {output_file}")

if __name__ == "__main__":
    main()
