# SQLi Hunter

SQLi Hunter is a tool designed to find potential SQL injection vulnerabilities by fetching URLs from the Wayback Machine and checking for common SQLi patterns. It supports integration with `proxychains` for enhanced anonymity and security during network requests.

## Features
- Fetches URLs for a given domain (including subdomains) from the Wayback Machine.
- Checks for potential SQL injection vulnerabilities.
- Supports rate limiting to avoid connection issues.
- Integration with `proxychains` for anonymized network requests.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/Acorzo1983/SQLiHunter.git
    cd SQLiHunter
    ```

2. Install the required Python packages:
    ```sh
    pip install -r requirements.txt
    ```

3. Ensure `subfinder`, `proxychains`, and `sqlmap` are installed and configured correctly on your system.

## Usage Examples

1. **Run without proxychains:**
    ```sh
    subfinder -d testphp.vulnweb.com -all -silent | python3 sqlihunter.py -o sqliurls.txt -r 1
    ```

2. **Run with a file:**
    ```sh
    python3 sqlihunter.py -f domains.txt -o sqliurls.txt -r 2
    ```

3. **Combined with sqlmap:**
    ```sh
    subfinder -d testphp.vulnweb.com -all -silent | python3 sqlihunter.py -o sqliurls.txt; sqlmap -m sqliurls.txt --batch --dbs --risk 2 --level 5 --random-agent | tee -a sqli.txt
    ```
4. **Start Proxychains:**
    ```sh
    sudo service tor start
    ```
    **Test Proxychains:**
    ```sh
    proxychains curl -I https://www.google.com
    ```
    We wait for 200 ok

5. **Run with proxychains:**
    ```sh
    proxychains subfinder -d testphp.vulnweb.com -all -silent | proxychains python3 sqlihunter.py -o sqliurls.txt -r 1 --use-proxychains
    ```

6. **Run with proxychains and combined with sqlmap:**
    ```sh
   proxychains subfinder -d testphp.vulnweb.com -all -silent | proxychains python3 sqlihunter.py -o sqliurls.txt -r 1 --use-proxychains ; sqlmap -m sqliurls.txt --batch --dbs --risk 2 --level 5 --random-agent | tee -a sqli.txt
    ```

## Disclaimer
Increasing the rate limit may cause the Wayback Machine to close the connection. A recommended rate limit is between 1 and 2 seconds.

## Author
Tool made with love by Albert C.
