#!/usr/bin/env python3
import os
import sys
import time
import logging
import subprocess
import signal
from datetime import datetime
from argparse import ArgumentParser
from urllib.parse import urlparse, urlunparse
from colorama import init, Fore, Style

# Initialize colorama for colors
init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global flag for graceful interruption
interrupted = False

def signal_handler(sig, frame):
    global interrupted
    interrupted = True
    print(Fore.RED + "\nScan interrupted by user (Ctrl+C). Exiting gracefully..." + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def show_credits():
    """Display a cool ASCII banner with credits and version information."""
    banner = f"""
{Fore.CYAN}============================================
         SQLiHunter Tool
   made with {Fore.MAGENTA}❤{Fore.CYAN} by Albert C @yz9yt
             Version 1.0
============================================{Style.RESET_ALL}
"""
    print(banner)

def create_output_directory(name):
    """Creates the output directory with format: name_<timestamp>."""
    timestamp = int(time.time() * 1000)
    output_dir = f"{name}_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def ensure_patterns_file(file_path="sqli.patterns"):
    """
    Ensures the SQLi patterns file exists. If not, it creates it automatically.
    """
    default_patterns = [
        "id=", "select=", "report=", "role=", "update=", "query=", "user=",
        "name=", "sort=", "where=", "search=", "params=", "process=", "row=",
        "view=", "table=", "from=", "sel=", "results=", "sleep=", "fetch=",
        "order=", "keyword=", "column=", "field=", "delete=", "string=",
        "number=", "filter="
    ]
    
    if not os.path.exists(file_path):
        logging.warning(f"The `{file_path}` file was not found. Creating it automatically...")
        try:
            with open(file_path, "w") as f:
                for pat in default_patterns:
                    f.write(pat + "\n")
            logging.info(f"Generated `{file_path}` with default patterns.")
        except Exception as e:
            logging.error(f"Failed to create `{file_path}`: {e}")
            sys.exit(1)
    
    # Load patterns from file
    with open(file_path, "r") as f:
        patterns = [line.strip() for line in f if line.strip()]
    
    return patterns

def fetch_urls_from_wayback(domain, rate_limit=1):
    """Fetches URLs from the Wayback Machine."""
    logging.info(f"Fetching URLs for {domain} from Wayback Machine...")
    cmd = f"curl 'https://web.archive.org/cdx/search/cdx?url={domain}//*&output=txt&fl=original'"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
        urls = result.stdout.splitlines()
        if not urls:
            logging.warning(f"No URLs found for {domain} in Wayback Machine. Skipping domain.")
        else:
            logging.info(f"Fetched {len(urls)} URLs for {domain}.")
        time.sleep(rate_limit)
        return urls
    except subprocess.CalledProcessError as e:
        logging.error(f"Error fetching URLs for {domain}: {e}")
        return []

def normalize_url(url):
    """Normalizes a URL by removing query parameters and fragments."""
    try:
        parsed = urlparse(url)
        normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        return normalized
    except Exception:
        return url

def clean_urls(urls, patterns):
    """Filters URLs that contain SQLi patterns and deduplicates them."""
    suspicious = []
    for url in urls:
        for pat in patterns:
            if pat in url:
                suspicious.append(url)
                break
    deduped = {}
    for url in suspicious:
        norm = normalize_url(url)
        if norm not in deduped:
            deduped[norm] = url
    return list(deduped.values())

def write_urls_to_file(urls, filepath):
    """Writes a list of URLs to a file."""
    with open(filepath, "w") as f:
        for url in urls:
            f.write(url + "\n")
    logging.info(f"Wrote {len(urls)} URLs to {filepath}.")

def main():
    show_credits()
    parser = ArgumentParser(description="SQLiHunter: Find SQL injection vulnerabilities from Wayback Machine URLs")
    parser.add_argument("-d", "--domain", help="Target domain to scan for SQLi vulnerabilities")
    parser.add_argument("-l", "--list", help="File containing list of domains to scan")
    parser.add_argument("-o", "--output", help="Output file name for suspicious URLs", default="sqliurls.txt")
    parser.add_argument("-r", "--rate", type=int, help="Rate limit for requests (seconds)", default=2)
    parser.add_argument("-p", "--patterns", help="File for SQLi patterns (default: sqli.patterns)", default="sqli.patterns")
    args = parser.parse_args()

    if not args.domain and not args.list:
        logging.error("You must specify either a domain (-d) or a list file (-l). Exiting.")
        sys.exit(1)

    patterns = ensure_patterns_file(args.patterns)

    # Modo lista: procesamos todos los dominios juntos
    if args.list:
        if not os.path.exists(args.list):
            logging.error(f"The list file `{args.list}` does not exist. Exiting.")
            sys.exit(1)
        with open(args.list, "r") as f:
            domain_list = [line.strip() for line in f if line.strip()]
        output_dir = create_output_directory("output_list")
        aggregate_raw = []
        aggregate_clean = []
        for domain in domain_list:
            logging.info(f"Scanning domain: {domain}")
            urls = fetch_urls_from_wayback(domain, args.rate)
            if not urls:
                continue
            aggregate_raw.extend(urls)
            aggregate_clean.extend(clean_urls(urls, patterns))
        if not aggregate_raw:
            logging.warning("No URLs found for any domain in the list. Exiting.")
            sys.exit(0)
        raw_file = os.path.join(output_dir, "raw_urls.txt")
        cleaned_file = os.path.join(output_dir, "cleaned_urls.txt")
        write_urls_to_file(aggregate_raw, raw_file)
        write_urls_to_file(aggregate_clean, cleaned_file)
        logging.info(f"\nScanning completed for list. Total domains scanned: {len(domain_list)}")
        print(f"\nTotal URLs fetched: {len(aggregate_raw)}")
        print(f"Suspicious URLs found: {len(aggregate_clean)}")
        print(f"Results stored in: {output_dir}")
        sqlmap_command = f"sqlmap -m {cleaned_file} --batch --level 5 --risk 3 --dbs"
        print(f"\nSQLMap command suggestion:\n{sqlmap_command}\n")
    else:
        # Modo dominio único
        domain = args.domain
        output_dir = create_output_directory(domain)
        raw_file = os.path.join(output_dir, "raw_urls.txt")
        cleaned_file = os.path.join(output_dir, "cleaned_urls.txt")
        logging.info(f"Scanning domain: {domain}")
        urls = fetch_urls_from_wayback(domain, args.rate)
        if not urls:
            logging.warning(f"No URLs found for {domain}. Exiting.")
            sys.exit(0)
        write_urls_to_file(urls, raw_file)
        suspicious_urls = clean_urls(urls, patterns)
        write_urls_to_file(suspicious_urls, cleaned_file)
        logging.info(f"\nScanning for {domain} completed!")
        print(f"\nTotal URLs fetched: {len(urls)}")
        print(f"Suspicious URLs found: {len(suspicious_urls)}")
        print(f"Results stored in: {output_dir}")
        sqlmap_command = f"sqlmap -m {cleaned_file} --batch --level 5 --risk 3 --dbs"
        print(f"\nSQLMap command suggestion:\n{sqlmap_command}\n")

if __name__ == "__main__":
    main()
