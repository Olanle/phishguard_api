import re
import requests
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime

def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # === Fallback values ===
    domain_age = 0
    empty_title = 0
    domain_in_title = 0
    nb_hyperlinks = 0
    ratio_intHyperlinks = 0.0

    # === WHOIS: domain_age ===
    try:
        domain_info = whois.whois(hostname)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            domain_age = (datetime.now() - creation_date).days
    except Exception as e:
        print(f"[WHOIS FAIL] {e}")

    # === HTML Parsing ===
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        # Title features
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        empty_title = int(len(title) == 0)
        domain_in_title = int(hostname.split('.')[0].lower() in title.lower())

        # Hyperlink stats
        links = soup.find_all('a')
        nb_hyperlinks = len(links)
        internal_links = [a for a in links if a.get('href', '').startswith('/')]
        ratio_intHyperlinks = len(internal_links) / nb_hyperlinks if nb_hyperlinks else 0.0

    except Exception as e:
        print(f"[HTML FAIL] {e}")

    # === Feature helpers ===
    def is_ip(host): return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
    def digit_ratio(s): return sum(c.isdigit() for c in s) / len(s) if len(s) > 0 else 0
    def prefix_suffix(): return int('-' in hostname)
    def tld_in_subdomain():
        sub = hostname.split('.')[:-2]
        tlds = ['com', 'net', 'org', 'biz', 'ru', 'info', 'ng']
        return int(any(tld in sub for tld in tlds))
    def word_stats(s):
        words = re.split(r'\W+', s)
        return (len(min(words, key=len)) if words else 0, len(max(words, key=len)) if words else 0)

    shortest_host, _ = word_stats(hostname)
    _, longest_raw = word_stats(url)
    _, longest_path = word_stats(path)

    return {
        "length_url": len(url),
        "length_hostname": len(hostname),
        "ip": int(is_ip(hostname)),
        "nb_dots": url.count("."),
        "nb_qm": url.count("?"),
        "nb_eq": url.count("="),
        "nb_slash": url.count("/"),
        "nb_www": url.count("www"),
        "ratio_digits_url": digit_ratio(url),
        "ratio_digits_host": digit_ratio(hostname),
        "tld_in_subdomain": tld_in_subdomain(),
        "prefix_suffix": prefix_suffix(),
        "shortest_word_host": shortest_host,
        "longest_words_raw": longest_raw,
        "longest_word_path": longest_path,
        "phish_hints": int(any(x in url.lower() for x in ['login', 'update', 'secure', 'verify', 'account'])),
        "nb_hyperlinks": nb_hyperlinks,
        "ratio_intHyperlinks": ratio_intHyperlinks,
        "empty_title": empty_title,
        "domain_in_title": domain_in_title,
        "domain_age": domain_age,
        "google_index": 0,  # Optional for future
        "page_rank": 0      # Optional for future
    }
