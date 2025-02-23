# Eliminamos la opción -r (rate) del código Python y del archivo README

# Código Python actualizado sin la opción "rate"
updated_python_code = """
#!/usr/bin/env python3
import os
import sys
import time
import logging
import subprocess
from datetime import datetime
from argparse import ArgumentParser

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def show_credits():
    """Display credits and version information."""
    header = f\"\"\"
============================================
         SQLiHunter Tool
   made with ❤ by Albert C @yz9yt
             Version 1.0
============================================
\"\"\"
    print(header)

def create_output_directory(domain):
    """Creates the output directory with format: output_<domain>_<timestamp>."""
    timestamp = int(time.time() * 1000)
    output_dir = f"output_{domain}_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def fetch_urls_from_wayback(domain):
    """Fetch URLs from the Wayback Machine using curl."""
    url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&fl=original"
    result = subprocess.run(
        ['curl', '-s', url],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return result.stdout.decode().splitlines()

def clean_urls(raw_urls, patterns):
    """Cleans URLs based on suspicious patterns."""
    cleaned_urls = []
    for url in raw_urls:
        for pattern in patterns:
            if pattern in url:
                cleaned_urls.append(url)
                break
    return cleaned_urls

def write_to_file(file_path, urls):
    """Write the URLs to a file."""
    with open(file_path, 'w') as f:
        for url in urls:
            f.write(url + '\\n')

def main():
    parser = ArgumentParser(description="SQLiHunter: Find SQL injection vulnerabilities from Wayback Machine URLs.")
    parser.add_argument('-d', '--domain', help="Target domain to scan for SQLi vulnerabilities")
    parser.add_argument('-l', '--list', help="File containing list of domains to scan")
    parser.add_argument('-o', '--output', help="Output file for suspicious URLs")
    parser.add_argument('--use-proxychains', action='store_true', help="Use proxychains for network requests")
    args = parser.parse_args()

    # Display credits
    show_credits()

    if args.domain:
        domains = [args.domain]
    elif args.list:
        with open(args.list, 'r') as f:
            domains = [line.strip() for line in f.readlines()]
    else:
        logging.error("No domain or list provided. Exiting.")
        sys.exit(1)

    # Load SQL injection patterns
    if not os.path.exists('sqli.patterns'):
        logging.warning("The `sqli.patterns` file was not found. Generating default patterns.")
        patterns = ["' OR 1=1 --", '" OR 1=1 --', "' OR 'x'='x", '" OR "x"="x']
        with open('sqli.patterns', 'w') as f:
            for pattern in patterns:
                f.write(pattern + '\\n')
        logging.info("Generated `sqli.patterns` file with default patterns.")
    else:
        with open('sqli.patterns', 'r') as f:
            patterns = [line.strip() for line in f.readlines()]

    # Process each domain
    for domain in domains:
        logging.info(f"Scanning domain: {domain}")

        # Fetch URLs from the Wayback Machine
        logging.info(f"Fetching URLs for {domain} from Wayback Machine...")
        raw_urls = fetch_urls_from_wayback(domain)
        
        if not raw_urls:
            logging.warning(f"No URLs found for {domain}. Skipping domain.")
            continue

        # Clean the fetched URLs
        logging.info(f"Fetched {len(raw_urls)} URLs for {domain}.")
        cleaned_urls = clean_urls(raw_urls, patterns)

        # Create output directory
        output_dir = create_output_directory(domain)
        raw_file_path = os.path.join(output_dir, 'raw_urls.txt')
        cleaned_file_path = os.path.join(output_dir, 'cleaned_urls.txt')

        # Write raw and cleaned URLs to files
        write_to_file(raw_file_path, raw_urls)
        write_to_file(cleaned_file_path, cleaned_urls)

        logging.info(f"Wrote {len(raw_urls)} raw URLs to {raw_file_path}.")
        logging.info(f"Wrote {len(cleaned_urls)} suspicious URLs to {cleaned_file_path}.")

        # Display SQLMap command for the user
        sqlmap_command = f"sqlmap -m {cleaned_file_path} --batch --level 5 --risk 3 --dbs"
        logging.info(f"SQLMap Command for {domain}:")
        logging.info(sqlmap_command)

        # Ask user if they want to run sqlmap
        run_sqlmap = input(f"Scanning for {domain} completed! Total URLs fetched: {len(raw_urls)}. Suspicious URLs found: {len(cleaned_urls)}.\nDo you want to run sqlmap with the above command? (Y/N) [Y]: ").strip().lower()
        if run_sqlmap != 'n':
            logging.info(f"Running SQLMap for {domain}...")
            subprocess.run(sqlmap_command, shell=True)
        else:
            logging.info("SQLmap command not executed. You can copy and paste it manually.")

if __name__ == "__main__":
    main()
"""

# Guardamos el código actualizado como archivo Python
file_path = "/mnt/data/sqlihunter_updated.py"
with open(file_path, 'w') as f:
    f.write(updated_python_code)

file_path
