#!/usr/bin/env python3
import os
import sys
import time
import logging
import subprocess
from datetime import datetime
from argparse import ArgumentParser
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def show_credits():
    """Display credits and version information."""
    header = f"""
{Fore.BLUE}============================================
         SQLiHunter Tool
   made with {Fore.MAGENTA}❤{Fore.CYAN} by Albert C @yz9yt
             Version 1.0
============================================
"""
    print(header)

def create_output_directory(domain):
    """Creates the output directory with format: output_<domain>_<timestamp>."""
    timestamp = int(time.time() * 1000)
    output_dir = f"output_{domain}_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def fetch_urls_from_wayback(domain):
    """Fetches URLs from Wayback Machine using the cURL command."""
    try:
        result = subprocess.run(
            ['curl', '-s', f'https://web.archive.org/cdx/search/cdx?url={domain}//*&output=txt&fl=original'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        output = result.stdout.decode('utf-8')
        if result.returncode != 0:
            logging.error(f"Error fetching URLs: {result.stderr.decode('utf-8')}")
            sys.exit(1)
        return output.splitlines()
    except Exception as e:
        logging.error(f"An error occurred while fetching URLs: {str(e)}")
        sys.exit(1)

def clean_urls(urls):
    """Cleans the URLs by filtering out duplicates and suspicious ones."""
    clean_urls = set(urls)  # Remove duplicates
    return [url for url in clean_urls if "?" in url]  # Filter for query strings

def write_urls_to_file(urls, output_dir, file_name):
    """Writes the list of URLs to the specified file."""
    # Ensure the directory exists before writing to the file
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, file_name), 'w') as file:
        for url in urls:
            file.write(url + '\n')

def process_domains_from_list(domains_list, output_dir):
    """Process a list of domains and extract URLs."""
    all_raw_urls = []
    for domain in domains_list:
        logging.info(f"Fetching URLs for {domain} from Wayback Machine...")
        urls = fetch_urls_from_wayback(domain)
        if not urls:
            logging.warning(f"No URLs found for {domain} in Wayback Machine. Skipping domain.")
            continue

        logging.info(f"Fetched {len(urls)} URLs for {domain}.")

        # Add all raw URLs for this domain to the list
        all_raw_urls.extend(urls)

        # Create a subdirectory for the domain
        domain_output_dir = os.path.join(output_dir, domain)
        os.makedirs(domain_output_dir, exist_ok=True)

        # Write raw URLs to file
        write_urls_to_file(urls, domain_output_dir, f'{domain}_raw_urls.txt')

        # Clean the URLs and write them to file
        cleaned_urls = clean_urls(urls)
        write_urls_to_file(cleaned_urls, domain_output_dir, f'{domain}_cleaned_urls.txt')

        logging.info(f"Wrote {len(urls)} raw URLs to {domain}_raw_urls.txt.")
        logging.info(f"Wrote {len(cleaned_urls)} cleaned URLs to {domain}_cleaned_urls.txt.")

    # Clean all URLs from all domains and write them to a single file
    cleaned_all_urls = clean_urls(all_raw_urls)
    write_urls_to_file(cleaned_all_urls, output_dir, 'all_cleaned_urls.txt')
    logging.info(f"Total cleaned URLs from all domains written to all_cleaned_urls.txt.")

    # Generate SQLmap command for all domains
    sqlmap_command = f"sqlmap -m {os.path.join(output_dir, 'all_cleaned_urls.txt')} --batch --level 5 --risk 3 --dbs"
    logging.info(f"SQLMap Command for all domains:\n{sqlmap_command}")
    return sqlmap_command

def main():
    parser = ArgumentParser(description="SQLiHunter: Find SQL injection vulnerabilities from Wayback Machine URLs")
    parser.add_argument('-d', '--domain', help='Target domain to scan for SQLi vulnerabilities')
    parser.add_argument('-l', '--list', help='File containing list of domains to scan')
    parser.add_argument('-o', '--output', help='Output directory for suspicious URLs', default='./output')
    
    args = parser.parse_args()

    show_credits()

    if args.domain:
        domains = [args.domain]
    elif args.list:
        with open(args.list, 'r') as file:
            domains = [line.strip() for line in file.readlines()]
    else:
        logging.error("No domain or list of domains provided. Exiting.")
        sys.exit(1)

    try:
        output_dir = create_output_directory("all_domains")
        sqlmap_command = process_domains_from_list(domains, output_dir)

        # Ask user if they want to run sqlmap
        user_input = input(f"\nSQLMap command suggestion for all domains:\n{sqlmap_command}\n\nDo you want to run sqlmap with the above command? (Y/N) [Y]: ").strip().lower()
        if user_input == '' or user_input == 'y':
            os.system(sqlmap_command)
        else:
            logging.info("SQLMap command not executed. You can copy and paste it manually.")
    except KeyboardInterrupt:
        logging.info("\nScan interrupted by user (Ctrl+C). Exiting gracefully...")
        sys.exit(0)

if __name__ == '__main__':
    main()
