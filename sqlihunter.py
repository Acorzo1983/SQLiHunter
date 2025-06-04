#!/usr/bin/env python3
"""
SQLiHunter Tool - Enhanced Version 2.0
A tool for finding potential SQL injection vulnerabilities from Wayback Machine URLs
"""

import os
import sys
import time
import logging
import asyncio
import aiohttp
import subprocess
from datetime import datetime
from argparse import ArgumentParser
from pathlib import Path
from typing import List, Set, Optional
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    # Fallback if colorama is not available
    class Fore:
        BLUE = CYAN = MAGENTA = RED = GREEN = YELLOW = ""
    class Style:
        BRIGHT = ""

# Configure logging with better formatting
logging.basicConfig(
    level=logging.INFO,
    format=f'{Fore.CYAN}%(asctime)s{Style.BRIGHT} - {Fore.GREEN}%(levelname)s{Style.BRIGHT} - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('sqlihunter.log', mode='a', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

class SQLiHunter:
    """Main class for SQLiHunter functionality."""
    
    def __init__(self, patterns_file: str = 'sqli.patterns'):
        self.patterns_file = patterns_file
        self.patterns = self._load_patterns()
        self.session = None
        
        # Enhanced SQL injection patterns with regex support
        self.advanced_patterns = [
            re.compile(r'\b(id|user|search|query|name|sort|order|filter)\s*=', re.IGNORECASE),
            re.compile(r'\b(select|union|insert|update|delete|drop|exec)\b', re.IGNORECASE),
            re.compile(r'[\'";].*(\bor\b|\band\b).*[\'";]', re.IGNORECASE),
            re.compile(r'\b\d+\s*=\s*\d+\b'),
        ]

    def show_credits(self):
        """Display enhanced credits and version information."""
        header = f"""
{Fore.BLUE}{'='*50}
{Style.BRIGHT}         SQLiHunter Tool v2.0
   made with {Fore.MAGENTA}❤{Fore.CYAN} by Albert C @yz9yt
        {Fore.YELLOW}Enhanced Edition
{'='*50}{Style.BRIGHT}
{Fore.GREEN}Features:{Style.BRIGHT}
• Advanced pattern detection
• Async URL processing  
• Enhanced filtering
• Better error handling
• Progress tracking
{'='*50}
"""
        print(header)

    def _load_patterns(self) -> List[str]:
        """Load SQL injection patterns from file with enhanced defaults."""
        if not Path(self.patterns_file).exists():
            logger.warning(f"{self.patterns_file} not found. Creating with enhanced patterns...")
            self._create_default_patterns()

        try:
            with open(self.patterns_file, 'r', encoding='utf-8') as file:
                patterns = [line.strip().lower() for line in file if line.strip() and not line.startswith('#')]
            logger.info(f"Loaded {len(patterns)} patterns from {self.patterns_file}")
            return patterns
        except Exception as e:
            logger.error(f"Error loading patterns from {self.patterns_file}: {e}")
            return self._get_minimal_patterns()

    def _create_default_patterns(self):
        """Create enhanced default patterns file."""
        enhanced_patterns = [
            "# SQL Injection Patterns - Enhanced Edition",
            "# Parameter names commonly vulnerable to SQLi",
            "id=", "user_id=", "product_id=", "category_id=",
            "search=", "q=", "query=", "keyword=", "term=",
            "user=", "username=", "email=", "login=",
            "name=", "firstname=", "lastname=", "title=",
            "sort=", "sortby=", "order=", "orderby=", "direction=",
            "page=", "limit=", "offset=", "count=", "size=",
            "filter=", "where=", "having=", "group=",
            "table=", "view=", "column=", "field=", "select=",
            "update=", "delete=", "insert=", "drop=",
            "report=", "role=", "process=", "action=",
            "params=", "row=", "results=", "data=",
            "fetch=", "get=", "show=", "display=",
            "string=", "number=", "value=", "content=",
            "# Database-specific functions",
            "sleep=", "benchmark=", "waitfor=", "delay=",
            "version=", "database=", "schema=", "information_schema",
            "# Common vulnerable endpoints",
            "admin=", "debug=", "test=", "demo="
        ]
        
        with open(self.patterns_file, 'w', encoding='utf-8') as file:
            file.write('\n'.join(enhanced_patterns))

    def _get_minimal_patterns(self) -> List[str]:
        """Return minimal patterns as fallback."""
        return ["id=", "search=", "user=", "query=", "name=", "sort="]

    async def fetch_urls_wayback_async(self, domain: str, max_retries: int = 3) -> List[str]:
        """Async fetch URLs from Wayback Machine with better error handling."""
        url = f'https://web.archive.org/cdx/search/cdx?url={domain}//*&output=txt&fl=original&collapse=urlkey'
        
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=60)
            self.session = aiohttp.ClientSession(timeout=timeout)

        for attempt in range(max_retries):
            try:
                logger.info(f"Fetching URLs for {domain} (attempt {attempt + 1}/{max_retries})")
                async with self.session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        urls = [line.strip() for line in content.splitlines() if line.strip()]
                        logger.info(f"Successfully fetched {len(urls)} URLs for {domain}")
                        return urls
                    else:
                        logger.warning(f"HTTP {response.status} for {domain}")
                        
            except Exception as e:
                logger.error(f"Attempt {attempt + 1} failed for {domain}: {str(e)}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff

        logger.error(f"Failed to fetch URLs for {domain} after {max_retries} attempts")
        return []

    def is_potential_sqli_url(self, url: str) -> bool:
        """Enhanced SQLi detection using multiple methods."""
        if '?' not in url:
            return False

        url_lower = url.lower()
        
        # Check basic patterns
        for pattern in self.patterns:
            if pattern in url_lower:
                return True
        
        # Check advanced regex patterns
        for regex_pattern in self.advanced_patterns:
            if regex_pattern.search(url):
                return True

        # Check for suspicious parameter structures
        try:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            # Look for numeric parameters (common SQLi targets)
            for param_name, param_values in params.items():
                if any(value.isdigit() for value in param_values):
                    return True
                    
            # Check for base64 or encoded parameters
            if any(len(value) > 20 and value.replace('=', '').replace('+', '').replace('/', '').isalnum() 
                   for values in params.values() for value in values):
                return True
                
        except Exception:
            pass

        return False

    def filter_and_deduplicate_urls(self, urls: List[str]) -> List[str]:
        """Enhanced URL filtering with better deduplication."""
        if not urls:
            return []
        
        logger.info(f"Processing {len(urls)} URLs for SQLi patterns...")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in urls:
            url_normalized = url.lower().strip()
            if url_normalized not in seen and url_normalized:
                seen.add(url_normalized)
                unique_urls.append(url)
        
        # Filter for potential SQLi URLs
        suspicious_urls = []
        for url in unique_urls:
            if self.is_potential_sqli_url(url):
                suspicious_urls.append(url)
        
        logger.info(f"Found {len(suspicious_urls)} potentially vulnerable URLs")
        return suspicious_urls

    def create_output_directory(self, base_name: str) -> Path:
        """Create timestamped output directory."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path(f"output_{base_name}_{timestamp}")
        output_dir.mkdir(exist_ok=True)
        return output_dir

    def write_urls_to_file(self, urls: List[str], output_path: Path, filename: str):
        """Write URLs to file with metadata."""
        file_path = output_path / filename
        
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(f"# Generated by SQLiHunter v2.0 on {datetime.now().isoformat()}\n")
            file.write(f"# Total URLs: {len(urls)}\n")
            file.write(f"# Patterns used: {len(self.patterns)}\n\n")
            
            for url in urls:
                file.write(f"{url}\n")
        
        logger.info(f"Written {len(urls)} URLs to {file_path}")

    def generate_sqlmap_commands(self, suspicious_urls_file: Path) -> List[str]:
        """Generate multiple SQLMap command variations."""
        base_commands = [
            f"sqlmap -m {suspicious_urls_file} --batch --level 3 --risk 2 --dbs --random-agent",
            f"sqlmap -m {suspicious_urls_file} --batch --level 5 --risk 3 --dbs --tamper=space2comment",
            f"sqlmap -m {suspicious_urls_file} --batch --threads 5 --technique=BEUST --dbs"
        ]
        return base_commands

    async def process_domains(self, domains: List[str], output_dir: Path) -> Optional[Path]:
        """Process multiple domains asynchronously."""
        try:
            all_suspicious_urls = []
            
            # Process domains concurrently
            tasks = [self.fetch_urls_wayback_async(domain.strip()) for domain in domains if domain.strip()]
            
            logger.info(f"Processing {len(tasks)} domains concurrently...")
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                domain = domains[i].strip()
                
                if isinstance(result, Exception):
                    logger.error(f"Error processing {domain}: {result}")
                    continue
                
                if not result:
                    logger.warning(f"No URLs found for {domain}")
                    continue
                
                # Create domain-specific directory
                domain_dir = output_dir / domain.replace('.', '_')
                domain_dir.mkdir(exist_ok=True)
                
                # Write raw URLs
                self.write_urls_to_file(result, domain_dir, f"{domain}_raw_urls.txt")
                
                # Filter suspicious URLs
                suspicious = self.filter_and_deduplicate_urls(result)
                if suspicious:
                    self.write_urls_to_file(suspicious, domain_dir, f"{domain}_suspicious_urls.txt")
                    all_suspicious_urls.extend(suspicious)
            
            if all_suspicious_urls:
                # Deduplicate all suspicious URLs
                final_suspicious = list(dict.fromkeys(all_suspicious_urls))
                all_suspicious_file = output_dir / "all_suspicious_urls.txt"
                self.write_urls_to_file(final_suspicious, output_dir, "all_suspicious_urls.txt")
                
                # Generate SQLMap commands
                commands = self.generate_sqlmap_commands(all_suspicious_file)
                
                commands_file = output_dir / "sqlmap_commands.txt"
                with open(commands_file, 'w') as f:
                    f.write("# SQLMap Commands Generated by SQLiHunter v2.0\n\n")
                    for i, cmd in enumerate(commands, 1):
                        f.write(f"# Command {i} - Level {i+2}\n{cmd}\n\n")
                
                print(f"\n{Fore.GREEN}Processing complete!{Style.BRIGHT}")
                print(f"{Fore.YELLOW}Suspicious URLs: {len(final_suspicious)}")
                print(f"Output directory: {output_dir}")
                print(f"SQLMap commands saved to: {commands_file}")
                
                return all_suspicious_file
            
            else:
                logger.warning("No suspicious URLs found across all domains")
                return None
                
        except Exception as e:
            logger.error(f"Error processing domains: {e}")
            return None

    async def cleanup(self):
        """Cleanup async resources."""
        if self.session:
            await self.session.close()

def main():
    """Enhanced main function with better error handling."""
    parser = ArgumentParser(
        description="SQLiHunter v2.0: Enhanced SQL injection vulnerability finder",
        epilog="Example: python sqlihunter.py -d example.com -o ./results"
    )
    parser.add_argument('-d', '--domain', help='Target domain to scan')
    parser.add_argument('-l', '--list', help='File containing list of domains')
    parser.add_argument('-o', '--output', help='Output directory name', default='scan_results')
    parser.add_argument('-p', '--patterns', help='Custom patterns file', default='sqli.patterns')
    parser.add_argument('--run-sqlmap', action='store_true', help='Automatically run SQLMap')
    
    args = parser.parse_args()
    
    # Initialize SQLiHunter
    hunter = SQLiHunter(args.patterns)
    hunter.show_credits()
    
    # Determine domains to process
    domains = []
    if args.domain:
        domains = [args.domain]
    elif args.list:
        try:
            with open(args.list, 'r', encoding='utf-8') as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            logger.error(f"Domain list file not found: {args.list}")
            sys.exit(1)
    else:
        logger.error("Please provide either -d <domain> or -l <domain_list_file>")
        sys.exit(1)
    
    if not domains:
        logger.error("No valid domains found to process")
        sys.exit(1)
    
    async def run_scan():
        try:
            output_dir = hunter.create_output_directory(args.output)
            logger.info(f"Output directory: {output_dir}")
            
            suspicious_file = await hunter.process_domains(domains, output_dir)
            
            if suspicious_file and suspicious_file.exists():
                # Show SQLMap command suggestions
                commands = hunter.generate_sqlmap_commands(suspicious_file)
                print(f"\n{Fore.CYAN}Suggested SQLMap commands:{Style.BRIGHT}")
                for i, cmd in enumerate(commands, 1):
                    print(f"\n{Fore.YELLOW}Command {i}:{Style.BRIGHT}\n{cmd}")
                
                if args.run_sqlmap or input(f"\n{Fore.MAGENTA}Run SQLMap now? (y/N): ").lower().startswith('y'):
                    logger.info("Executing SQLMap...")
                    subprocess.run(commands[0], shell=True)
            
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Scan interrupted by user. Exiting gracefully...")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
        finally:
            await hunter.cleanup()
    
    # Run the async scan
    if sys.version_info >= (3, 7):
        asyncio.run(run_scan())
    else:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(run_scan())

if __name__ == '__main__':
    main()
