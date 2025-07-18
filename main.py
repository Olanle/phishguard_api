import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import pandas as pd
import joblib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

# Initialize FastAPI app
app = FastAPI()

# Enable CORS so your browser extension can access this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change "*" to specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load trained model
model = joblib.load("vcf_model.joblib")

# Input data schema
class URLInput(BaseModel):
    url: str

# Feature extraction function
def extract_all_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    features = []

    features.append(1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain) else -1)
    features.append(1 if len(url) >= 75 else -1)
    shortening_services = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 't.co']
    features.append(1 if any(service in url for service in shortening_services) else -1)
    features.append(1 if '@' in url else -1)
    features.append(1 if url[7:].find('//') != -1 else -1)
    features.append(1 if '-' in domain else -1)
    features.append(1 if domain.count('.') > 2 else -1)
    features.append(-1 if parsed.scheme == 'https' else 1)
    features.append(-1)  # Placeholder for Domain Registration Length

    try:
        resp = requests.get(url, timeout=5)
        soup = BeautifulSoup(resp.text, 'html.parser')
        favicon = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
        if favicon and 'href' in favicon.attrs:
            favicon_url = favicon['href']
            if domain not in favicon_url and not favicon_url.startswith('/'):
                features.append(1)
            else:
                features.append(-1)
        else:
            features.append(-1)
    except:
        features.append(-1)

    features.append(1 if parsed.port and parsed.port not in [80, 443] else -1)
    features.append(1 if 'https' in domain else -1)

    try:
        tags = soup.find_all(['img', 'audio', 'embed', 'iframe'])
        total = len(tags)
        external = sum(1 for tag in tags if tag.has_attr('src') and domain not in tag['src'])
        percent = external / total if total > 0 else 0
        features.append(-1 if percent < 0.22 else 0 if percent < 0.61 else 1)
    except:
        features.append(-1)

    try:
        anchors = soup.find_all('a', href=True)
        total = len(anchors)
        external = sum(1 for a in anchors if domain not in a['href'])
        percent = external / total if total > 0 else 0
        features.append(-1 if percent < 0.31 else 0 if percent < 0.67 else 1)
    except:
        features.append(-1)

    try:
        scripts = soup.find_all(['script', 'link'])
        total = len(scripts)
        external = sum(1 for tag in scripts if tag.has_attr('src') and domain not in tag['src'])
        percent = external / total if total > 0 else 0
        features.append(-1 if percent < 0.17 else 0 if percent < 0.81 else 1)
    except:
        features.append(-1)

    # Pad the rest to reach 30 features
    features.extend([-1] * (30 - len(features)))
    return features

# Feature names (required by model)
all_features = [
    'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-', 'SubDomains', 'HTTPS',
    'DomainRegLen', 'Favicon', 'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL', 'LinksInScriptTags',
    'ServerFormHandler', 'InfoEmail', 'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
    'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording', 'WebsiteTraffic', 'PageRank',
    'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
]

# Prediction endpoint
@app.post("/")
def predict_url(input_data: URLInput):
    try:
        features = extract_all_features(input_data.url)
        features_df = pd.DataFrame([features], columns=all_features)

        prediction = model.predict(features_df)[0]

        # Confidence score (fallback if needed)
        try:
            proba = model.predict_proba(features_df)[0]
            confidence = round(float(max(proba)) * 100, 2)
        except Exception:
            confidence = 90.0 if prediction == 1 else 95.0

        if prediction == 1:
            severity = "high" if confidence >= 90 else "medium" if confidence >= 70 else "low"
        else:
            severity = "none"

        return {
            "url": input_data.url,
            "prediction": "Phishing" if prediction == 1 else "Legitimate",
            "severity": severity,
            "confidence": confidence
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")
