import streamlit as st
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

# Streamlit web interface
st.title("Website Legitimacy Checker")

# Get user input
url = st.text_input("Enter Website URL:")
if st.button("Check Legitimacy"):
    try:
        legitimacy_score, checks_passed = check_website_legitimacy(url)
        st.write(f"Website Legitimacy Score: {legitimacy_score}")
        if checks_passed:
            st.write("Criteria passed:")
            for check in checks_passed:
                st.write(f"- {check}")
    except requests.exceptions.RequestException as e:
        st.error(f"Error: {e}. This website may be illegitimate or inaccessible.")