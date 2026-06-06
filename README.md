# PySecKit - Python Security Toolkit

A command-line security toolkit written in Python.

> WARNING: Use only on systems you own or have explicit written permission to test.
> Unauthorized use may be illegal in your jurisdiction.

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
python pySecKit.py --help
python pySecKit.py <tool> --help
```

---

## Tools

### Port Scanner
Scan open TCP ports on a target host.

```bash
python pySecKit.py portscan -t 192.168.1.1 -p 1-1024
python pySecKit.py portscan -t 192.168.1.1 -p 20-80 --threads 200 --timeout 1.5
python pySecKit.py portscan -t 192.168.1.1 -p 1-1024 -o results.json
```

### Hash Cracker
Crack a hash using a wordlist or brute-force.

```bash
# Wordlist mode
python pySecKit.py hashcrack -H 5f4dcc3b5aa765d61d8327deb882cf99 -a md5 -w rockyou.txt

# Brute-force mode
python pySecKit.py hashcrack -H 5f4dcc3b5aa765d61d8327deb882cf99 -a md5 -b --charset abc123 --min-len 4 --max-len 6

# Save result
python pySecKit.py hashcrack -H <hash> -a sha256 -w wordlist.txt -o result.json
```

### Phishing URL Detector
Analyze URLs for phishing indicators using ML.

```bash
python pySecKit.py phishing -u http://paypal-secure.login.com
python pySecKit.py phishing -f urls.txt -o results.json
python pySecKit.py phishing -u http://example.com --retrain
```

### Password Strength Checker
Analyze password strength or generate a secure password.

```bash
python pySecKit.py passcheck -p "MyPassword123"
python pySecKit.py passcheck -g
python pySecKit.py passcheck -g --length 20
```

### Password Vault
Encrypted password manager (interactive).

```bash
python pySecKit.py vault
```

---

## Global Options

| Option | Description |
|--------|-------------|
| `--log-level` | DEBUG / INFO / WARNING / ERROR (default: INFO) |

Example:
```bash
python pySecKit.py portscan -t 192.168.1.1 -p 1-1024 --log-level DEBUG
```

---

## Output Formats

All tools that support `-o / --output` accept `.json` or `.csv` extensions.

---

## Project Structure

```
PySecKit/
├── pySecKit.py                  # Main entry point
├── requirements.txt
├── Hash_cracker/
│   └── hash_cracker.py
├── Password_manager/
│   └── password_manager.py
├── Password_tool/
│   ├── password_tool.py
│   └── data/train.csv
├── Phishing_URL_Detector/
│   ├── phishing_detector.py
│   └── data/phishing_dataset.csv
└── Port_scanner/
    └── port_scanner.py
```
