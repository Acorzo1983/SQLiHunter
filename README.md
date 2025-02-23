# SQLiHunter

SQLiHunter is a tool designed to identify SQL Injection (SQLi) vulnerabilities in web applications by utilizing the Wayback Machine to fetch URLs from domains and subdomains. This tool automates the collection of URLs from the Wayback Machine, filters them, cleans them, and generates a `sqlmap` command for analysis.

---

## Features  
- Fetches URLs from the Wayback Machine for a domain or list of domains.  
- Filters URLs to find potential SQL injection points (URLs with query parameters).  
- Generates `sqlmap` commands to test the identified URLs.  
- Supports processing single domains or lists of domains.  
- Saves raw and processed URLs in output files.  

---

## Requirements  
- **Python 3**  
- **cURL**  
- **sqlmap** ([Installation Guide](#installing-sqlmap))  

---

## Dependencies  
The script uses the following Python libraries:  
- `colorama` for console colorization.  
- `argparse` for command-line argument handling.  
- `subprocess` to interact with cURL and execute system commands.  

## Install dependencies using `pip`:  
```bash
pip install colorama
```

Installation
Run this one-liner to install SQLiHunter globally:
```bash
git clone https://github.com/tuusuario/sqlifinder.git && cd sqlifinder && chmod +x sqlihunter.py && sudo ln -s $(pwd)/sqlihunter.py /usr/local/bin/sqlihunter
```

## This will:

- Clone the repository.
- Make the script executable.
- Create a symbolic link to run sqlihunter from any directory.

## Usage
Scanning a Single Domain

```bash
sqlihunter -d example.com
```
## This will:

- Fetch URLs for example.com from the Wayback Machine.
- Filter URLs with query parameters.
- Save raw/cleaned URLs to the output directory.

## Generate a sqlmap command for testing.

Scanning Multiple Domains
Create a text file (e.g., domains.txt) and run:

```bash
sqlihunter -l domains.txt
```
This will:

- Fetch URLs for all domains in the list.
- Save raw/cleaned URLs in separate files per domain.
- Generate a combined sqlmap command for all domains.

## Arguments

Argument	Description
```bash
-d, --domain	Specify a single domain to scan.
-l, --list	Specify a text file containing a list of domains.
-o, --output	Set the output directory (default: ./output).
```
Example Output
```bash

============================================
         SQLiHunter Tool
   made with ❤ by Albert C @yz9yt
             Version 1.0
============================================

2025-02-23 16:01:24,177 - INFO - Fetching URLs for saas.aiwriter.fi from Wayback Machine...
2025-02-23 16:01:30,628 - INFO - Fetched 101 URLs for saas.aiwriter.fi.
2025-02-23 16:01:30,629 - INFO - Wrote 101 raw URLs to output_saas.aiwriter.fi_1740344484177/raw_urls.txt.
2025-02-23 16:01:30,630 - INFO - Wrote 16 cleaned URLs to output_saas.aiwriter.fi_1740344484177/cleaned_urls.txt.
2025-02-23 16:01:30,630 - INFO - SQLMap Command for saas.aiwriter.fi:
sqlmap -m output_saas.aiwriter.fi_1740344484177/cleaned_urls.txt --batch --level 5 --risk 3 --dbs

SQLMap command suggestion:
sqlmap -m output_saas.aiwriter.fi_1740344484177/cleaned_urls.txt --batch --level 5 --risk 3 --dbs

Do you want to run sqlmap with the above command? (Y/N) [Y]:
```

## Contributing
Feel free to contribute to this project! Open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

Made with ❤️ by Albert C.
