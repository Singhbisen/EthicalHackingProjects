import requests
import re
import collections
import math

def get_session_id(url, cookies):
    response = requests.get(url, cookies=cookies, allow_redirects=False)
    set_cookie_header = response.headers.get('Set-Cookie')
    if set_cookie_header:
        # Regex to find any cookie starting with 'sessionId-' followed by digits, '=', and the value
        match = re.search(r'(sessionId-\d+)=([^;]+)', set_cookie_header)
        if match:
            cookie_name = match.group(1)
            cookie_value = match.group(2)
            return cookie_name, cookie_value
    return None, None

def calculate_entropy(data):
    if not data:
        return 0
    probabilities = [float(data.count(c)) / len(data) for c in set(data)]
    entropy = -sum([p * math.log2(p) for p in probabilities if p > 0])
    return entropy

def parse_cookies(cookie_string):
    """Parses a cookie string into a dictionary."""
    cookies = {}
    if cookie_string:
        for cookie in cookie_string.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                cookies[key] = value
    return cookies

# Get target URL from user
target_url = input("Enter the target URL (e.g., https://example.com/login): ").strip()
if not target_url:
    print("Error: Target URL cannot be empty.")
    exit()

# Get initial cookies from user
cookie_string = input("Enter the initial cookies (e.g., key1=value1; key2=value2): ").strip()
initial_cookies = parse_cookies(cookie_string)

try:
    response = requests.get(target_url, cookies=initial_cookies, verify=False)  # Disable verification
    response.raise_for_status()
    print("Successfully connected (SSL verification disabled).")
    print(response.text)
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")

# You might see a warning about insecure requests.
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

session_ids = {} # Dictionary to store cookie names and their values
num_samples = 100
for _ in range(num_samples):
    cookie_name, new_session_id = get_session_id(target_url, initial_cookies)
    if new_session_id:
        session_ids.setdefault(cookie_name, []).append(new_session_id)
        initial_cookies[cookie_name] = new_session_id # Update with the dynamic cookie name
    else:
        print("Failed to retrieve session ID")
        break

print(f"Collected session IDs for {len(session_ids.keys())} cookie names:")
for name, values in session_ids.items():
    print(f"\nCookie Name: {name}")
    print(f"First 10 values: {values[:10]}")

    lengths = [len(sid) for sid in values]
    print(f"  Session ID Lengths: {collections.Counter(lengths)}")

    all_chars = "".join(values)
    entropy = calculate_entropy(all_chars)
    print(f"  Estimated Entropy (rough): {entropy} bits per character")

    # Basic UUIDv4 check (assuming the value *might* be a UUID)
    if values and all(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', val) for val in values):
        print("  All collected values appear to be in UUIDv4 format.")
    else:
        print("  Collected values do not consistently appear to be in UUIDv4 format.")