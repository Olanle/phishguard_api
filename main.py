from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import pandas as pd
from feature_extractor import extract_features
from fastapi.middleware.cors import CORSMiddleware

# Load model and scaler
model = joblib.load("rf_phishing_model.joblib")
scaler = joblib.load("rf_scaler.joblib")

app = FastAPI()

# Allow CORS for your extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Consider restricting in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define request body
class URLInput(BaseModel):
    url: str

@app.post("/predict")
def predict_url(data: URLInput):
    try:
        # Extract features and scale
        features = extract_features(data.url)
        df = pd.DataFrame([features])
        scaled = scaler.transform(df)

        # Predict
        proba_all = model.predict_proba(scaled)[0]  # e.g., [0.8, 0.2]
        phishing_proba = proba_all[1]
        pred = int(phishing_proba > 0.5)

        # Determine severity
        if phishing_proba > 0.75:
            severity = "high"
        elif phishing_proba > 0.5:
            severity = "medium"
        else:
            severity = "low"

        return {
            "prediction": pred,  # 1 = phishing, 0 = safe
            "confidence": round(phishing_proba if pred == 1 else 1 - phishing_proba, 4),
            "severity": severity
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
