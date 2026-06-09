import hashlib
import requests
import warnings

# Suppress connection warnings
warnings.filterwarnings("ignore")

# A mapping table of known framework file hashes to versions
# (Enterprise scanners use massive databases of these static asset hashes)
VERSION_HASH_DATABASE = {
    # Example MD5 hashes for specific Joomla release favicons/assets
    "d41d8cd98f00b204e9800998ecf8427e": "6.1.1",
    "3f8a213e4b77ad9c1234ef56789abcde": "5.4.6",
    "9a01a3c84f22bd8d9e71234abcdcdeef": "6.0.0"
}

def detect_version_by_hash(url):
    try:
        # Request a static core asset that rarely changes but varies by version
        asset_url = f"{url.rstrip('/')}/media/system/images/joomla-favicon.ico"
        
        response = requests.get(asset_url, timeout=10, verify=False)
        
        if response.status_code == 200:
            # Calculate MD5 hash of the file bytes
            file_hash = hashlib.md5(response.content).hexdigest()
            
            # Lookup version based on file signature
            version = VERSION_HASH_DATABASE.get(file_hash)
            
            if version:
                print(f"Joomla ({version})")
            else:
                # Fallback if hash isn't in local DB but asset exists
                print(f"Detected Application (Version Unmapped - Hash: {file_hash})")
        else:
            # Alternate fallback to read internal script tags if asset is blocked
            detect_via_inline_strings(url)
            
    except Exception:
        pass

def detect_via_inline_strings(url):
    try:
        # Search the raw HTML source for meta generators or script strings
        response = requests.get(url, timeout=10, verify=False)
        html = response.text
        
        # Look for the hidden generator tag patterns if present
        if 'name="generator" content="Joomla!' in html:
            # Standard scrapers pull text inside the content attribute here
            print("Joomla (Hidden Version)")
    except Exception:
        pass

if __name__ == "__main__":
    target_url = "https://joomla.org"
    detect_version_by_hash(target_url)
