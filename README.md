# Tr10d: Sensitive Data Hunting Tool
-Alham Rizvi
## Overview

**Tr10d** is a command-line tool designed for security researchers, penetration testers, and bug bounty hunters. Its primary purpose is to identify and extract sensitive information such as API keys, tokens, and other credentials from web pages. By automating the search for common patterns of sensitive data exposure, Tr10d helps users assess the security posture of web applications and identify potential vulnerabilities.

## Key Features

- **Pattern Matching:** Tr10d utilizes regular expressions to search for known patterns of sensitive data, including:
  - AWS Access Key IDs
  - AWS Secret Access Keys
  - API Keys
  - Bearer Tokens
  - GitHub Tokens
- **Web Content Fetching:** The tool fetches the HTML content of a specified URL, allowing it to scan for sensitive data directly from web applications.
- **User-Friendly Interface:** Tr10d provides a simple command-line interface that guides users through the process of entering a URL and viewing the results.

## Installation

Follow these steps to install and set up Tr01d:

1. **Install Python**: Ensure that Python is installed on your system. You can download it from [python.org](https://www.python.org/downloads/).

2. **Install Required Dependencies**: Open a terminal and run the following command to install the required Python packages:
   ```bash
   pip install pyfiglet requests
   python3 tr10dbyalhamv1.py
