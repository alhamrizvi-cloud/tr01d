import os
import re
import requests
import pyfiglet

# ANSI escape codes for colors
class TextStyle:
    WHITE_BOLD = "\033[1;37m"  # Bold white
    RESET = "\033[0m"           # Reset to default

# Define patterns for sensitive data
patterns = {
    'AWS Access Key ID': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Access Key': r'(?<=AWS_SECRET_ACCESS_KEY=)[A-Za-z0-9/+=]{40}',
    'API Key': r'(?<=api_key=)[A-Za-z0-9]{32}',
    'Bearer Token': r'(?<=Bearer\s)[A-Za-z0-9._-]{20,}',
    'GitHub Token': r'gh[0-9]{6,}.[A-Za-z0-9]{36}',
}

def search_content(content):
    found_secrets = {}
    for name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            found_secrets[name] = matches
    return found_secrets

def search_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad responses
        return search_content(response.text)
    except requests.RequestException as e:
        print(f"{TextStyle.WHITE_BOLD}Error fetching URL: {e}{TextStyle.RESET}")
        return {}

def print_title():
    ascii_title = pyfiglet.figlet_format("Tr10d", font="slant")
    print(f"{TextStyle.WHITE_BOLD}{ascii_title}{TextStyle.RESET}")

def print_disclaimer():
    disclaimer = (
        f"{TextStyle.WHITE_BOLD}Disclaimer: This tool is created by Alham Rizvi. "
        "Use it responsibly and only on systems you own or have explicit permission to test. "
        "Unauthorized access to systems is illegal and unethical.\n\n"
        "Description: Tr10d is a sensitive data hunting tool designed to search for "
        "API keys, tokens, and other sensitive information in web pages. "
        "It can help security researchers and bug bounty hunters identify potential "
        "security vulnerabilities in web applications by scanning for common patterns "
        "of sensitive data exposure.{TextStyle.RESET}"
    )
    print(disclaimer)

def main():
    # Print the title
    print_title()

    # Print disclaimer and description
    print_disclaimer()

    url = input(f"\n{TextStyle.WHITE_BOLD}Enter the URL to search for sensitive data: {TextStyle.RESET}")
    
    print(f"{TextStyle.WHITE_BOLD}Searching for sensitive data at {url}...{TextStyle.RESET}")
    secrets = search_url(url)

    if secrets:
        print(f"{TextStyle.WHITE_BOLD}Found sensitive data:{TextStyle.RESET}")
        for key, values in secrets.items():
            print(f"{TextStyle.WHITE_BOLD}{key}:{TextStyle.RESET}")
            for value in values:
                print(f"  - {value}")
    else:
        print(f"{TextStyle.WHITE_BOLD}No sensitive data found.{TextStyle.RESET}")

if __name__ == "__main__":
    main()
