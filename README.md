# TR01D v2 – JavaScript Secret Scanner

Fast & advanced secret scanner for JavaScript files. Detects 40+ secret types, supports filtering, multithreading, custom regex, and deep JS analysis.

## Features
- Detects API keys, tokens, passwords, AWS, Google, GitHub, Slack, Stripe, DB strings, OAuth, JWT, private keys & more  
- JS variable + comment analysis (`-v`)  
- Multi-threading (`-t`)  
- Filtering (`--only`, `--exclude`)  
- Custom patterns (`--ep`)  
- Output to file (`-o`)  
- Silent mode (`-s`)  
- No color mode (`--no-color`)  
- Cookie + User-Agent support  

## Install
```bash
git clone https://github.com/alhamrizvi-cloud/tr01d.git
pip3 install requests
chmod +x tr01d.py

Basic Usage

cat js_urls.txt | python3 tr01d.py

Examples

# Only API keys
cat js_urls.txt | python3 tr01d.py --only api_key

# Exclude passwords + generic
cat js_urls.txt | python3 tr01d.py --exclude password,generic

# Verbose mode
cat js_urls.txt | python3 tr01d.py -v

# Save output
cat js_urls.txt | python3 tr01d.py -o results.txt

# Add custom regex
cat js_urls.txt | python3 tr01d.py --ep "custom_[a-z0-9]{32}"

# High performance
cat js_urls.txt | python3 tr01d.py -t 100

Scan a Domain

echo "example.com" | waybackurls | grep "\.js$" | python3 tr01d.py -v -o results.txt

Supported Types

api_key, token, password, aws_key, private_key,
database, oauth, jwt, github, slack, stripe,
sendgrid, twilio, google, firebase, cloudflare,
mailgun, heroku, generic
