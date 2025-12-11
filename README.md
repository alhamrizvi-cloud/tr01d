![Uploading image.png…]()

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
# Clone the repo
git clone https://github.com/alhamrizvi-cloud/tr01d.git
cd tr01d

# Install venv (if not installed)
sudo apt install python3-venv -y

# Create virtual environment
python3 -m venv tr01d-env

# Activate environment
source tr01d-env/bin/activate

# Install required modules
pip install requests

# Run TR01D
python3 tr10dbyalhamv1.py

Basic Usage

cat js_urls.txt | python3 tr10dbyalhamv1.py

Examples

# Only API keys
cat js_urls.txt | python3 tr10dbyalhamv1.py --only api_key

# Exclude passwords + generic
cat js_urls.txt | python3 tr10dbyalhamv1.py --exclude password,generic

# Verbose mode
cat js_urls.txt | python3 tr10dbyalhamv1.py -v

# Save output
cat js_urls.txt | python3 tr10dbyalhamv1.py -o results.txt

# Add custom regex
cat js_urls.txt | python3 tr10dbyalhamv1.py --ep "custom_[a-z0-9]{32}"

# High performance (100 threads)
cat js_urls.txt | python3 tr10dbyalhamv1.py -t 100

Scan a Domain

echo "example.com" | waybackurls | grep "\.js$" | python3 tr10dbyalhamv1.py -v -o results.txt

Supported Types

api_key, token, password, aws_key, private_key,
database, oauth, jwt, github, slack, stripe,
sendgrid, twilio, google, firebase, cloudflare,
mailgun, heroku, generic

Bonus — Add TR01D as a global command (tr01d)

echo '#!/bin/bash
source ~/tr01d/tr01d-env/bin/activate
python3 ~/tr01d/tr10dbyalhamv1.py "$@"' | sudo tee /usr/bin/tr01d

sudo chmod +x /usr/bin/tr01d

Now you can run the scanner from anywhere:

tr01d

