import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
from googleapiclient.discovery import build
import whois

# Function to check if the website is using HTTPS
def check_https(url):
    return url.startswith('https')

# Function to check if the website has a valid SSL certificate
def check_ssl(url):
    try:
        requests.get(url)
        return True
    except requests.exceptions.SSLError:
        return False

# Function to extract meta tags from the website
def extract_meta_tags(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        meta_tags = soup.find_all('meta')
        return [tag.attrs for tag in meta_tags]
    except:
        return []

# Function to check if the website is listed on Google Safe Browsing
def check_google_safe_browsing(url):
    api_key = 'AIzaSyB34xKoFCJb-3rLLs0ehuFNo2zEJQpw0p8'  # Replace with your actual API key
    service = build('safebrowsing', 'v4', developerKey=api_key)
    threat_type = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION']
    request_body = {
        'client': {
            'clientId': 'your_company_name',
            'clientVersion': '1.5.2'
        },
        'threatInfo': {
            'threatTypes': threat_type,
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }
    request = service.threatMatches().find(body=request_body)
    response = request.execute()
    if 'matches' in response:
        return True
    else:
        return False

# Function to check domain age
def check_domain_age(url):
    try:
        domain = whois.whois(urlparse(url).netloc)
        creation_date = domain.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        today = datetime.now()
        age = today - creation_date
        return age.days
    except:
        return None

# Function to check website legitimacy
def check_website_legitimacy(url):
    legitimacy_score = 0
    checks_passed = []

    if check_https(url):
        legitimacy_score += 1
        checks_passed.append("HTTPS")
    if check_ssl(url):
        legitimacy_score += 1
        checks_passed.append("SSL Certificate")
    meta_tags = extract_meta_tags(url)
    if meta_tags:
        legitimacy_score += 1
        checks_passed.append("Meta Tags")
    if check_google_safe_browsing(url):
        legitimacy_score += 1
        checks_passed.append("Google Safe Browsing")
    domain_age = check_domain_age(url)
    if domain_age and domain_age > 365:  # Consider domains older than 1 year as more legitimate
        legitimacy_score += 1
        checks_passed.append("Domain Age")

    return legitimacy_score, checks_passed

# Function to print safety level based on legitimacy score
def print_safety_level(legitimacy_score, checks_passed):
    if legitimacy_score == 0:
        print("This website is highly suspicious and might be unsafe.")
    elif legitimacy_score <= 2:
        print("This website has moderate safety, and caution is advised.")
    elif legitimacy_score <= 4:
        print("This website is considered safe with a good legitimacy score.")
    else:
        print("This website is very safe and legitimate.")

    if checks_passed:
        print("Criteria passed:")
        for check in checks_passed:
            print(f"- {check}")

# Example usage
url = 'https://scty6ef.cc/invite/i=41648'  # Replace with the URL you want to check
try:
    legitimacy_score, checks_passed = check_website_legitimacy(url)
    print("Website Legitimacy Score:", legitimacy_score)
    print_safety_level(legitimacy_score, checks_passed)
except requests.exceptions.RequestException as e:
    print(f"Error: {e}. This website may be illegitimate or inaccessible.")
