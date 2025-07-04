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
    allow_origins=["*"],  # or specify the exact origin of your extension
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
        features = extract_features(data.url)
        df = pd.DataFrame([features])
        scaled = scaler.transform(df)

        pred = model.predict(scaled)[0]
        proba = model.predict_proba(scaled)[0][pred]

        return {
            "prediction": int(pred),
            "confidence": round(float(proba), 4)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
