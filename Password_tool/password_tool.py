import os
import re
import sys
import json
import string
import random
import logging
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

logger = logging.getLogger(__name__)

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_PATH  = os.path.join(BASE_DIR, "data",   "train.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "password_strength_model.pkl")

STRENGTH_LABELS = ["Weak", "Medium", "Strong"]

# ---------- Feature extraction ----------

def _extract_features(pwd: str) -> list:
    return [
        len(pwd),
        sum(c.isupper() for c in pwd),
        sum(c.islower() for c in pwd),
        sum(c.isdigit() for c in pwd),
        sum(c in string.punctuation for c in pwd),
        len(set(pwd)),                          # unique character count
        int(bool(re.search(r"(.)\1{2,}", pwd))),# has 3+ repeated chars
        int(len(pwd) >= 12),                    # meets minimum length
    ]


# ---------- Training ----------

def _train_model() -> RandomForestClassifier:
    if not os.path.exists(DATA_PATH):
        logger.error("Training data not found: %s", DATA_PATH)
        sys.exit(1)

    data = pd.read_csv(DATA_PATH)
    if not {"password", "strength"}.issubset(data.columns):
        logger.error("CSV must contain 'password' and 'strength' columns.")
        sys.exit(1)

    # Drop rows with missing values
    data = data.dropna(subset=["password", "strength"])
    data["password"] = data["password"].astype(str)

    X = np.array([_extract_features(p) for p in data["password"]])
    y = data["strength"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    logger.info("Model training complete.\n%s", classification_report(y_test, y_pred,
                target_names=STRENGTH_LABELS, zero_division=0))

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    logger.info("Model saved to %s", MODEL_PATH)
    return model


def _load_or_train(force_retrain: bool = False) -> RandomForestClassifier:
    if not force_retrain and os.path.exists(MODEL_PATH):
        logger.debug("Loading existing model from %s", MODEL_PATH)
        return joblib.load(MODEL_PATH)
    logger.info("Training model...")
    return _train_model()


# ---------- Password generator ----------

def generate_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + string.punctuation
    while True:
        pwd = "".join(random.choice(chars) for _ in range(length))
        if (
            re.search(r"[A-Z]", pwd)
            and re.search(r"[a-z]", pwd)
            and re.search(r"\d", pwd)
            and re.search(r"[^A-Za-z0-9]", pwd)
        ):
            return pwd


# ---------- Analysis ----------

def analyze_password(password: str, model: RandomForestClassifier) -> dict:
    features = np.array(_extract_features(password)).reshape(1, -1)
    strength_idx = int(model.predict(features)[0])
    proba        = model.predict_proba(features)[0]

    return {
        "password":        password,
        "strength":        STRENGTH_LABELS[strength_idx],
        "length":          len(password),
        "has_uppercase":   bool(re.search(r"[A-Z]", password)),
        "has_lowercase":   bool(re.search(r"[a-z]", password)),
        "has_digit":       bool(re.search(r"\d", password)),
        "has_symbol":      bool(re.search(r"[^A-Za-z0-9]", password)),
        "unique_chars":    len(set(password)),
        "confidence":      round(float(proba[strength_idx]) * 100, 1),
    }


def _print_analysis(result: dict):
    strength  = result["strength"]
    indicator = {"Weak": "[-]", "Medium": "[~]", "Strong": "[+]"}[strength]
    print(f"\n  {indicator} Strength   : {strength} ({result['confidence']}% confidence)")
    print(f"  Length        : {result['length']}")
    print(f"  Uppercase     : {'yes' if result['has_uppercase'] else 'no'}")
    print(f"  Lowercase     : {'yes' if result['has_lowercase'] else 'no'}")
    print(f"  Digits        : {'yes' if result['has_digit'] else 'no'}")
    print(f"  Symbols       : {'yes' if result['has_symbol'] else 'no'}")
    print(f"  Unique chars  : {result['unique_chars']}")


# ---------- Entry point ----------

def run_password_tool(args):
    force_retrain = getattr(args, "retrain", False)
    model = _load_or_train(force_retrain)

    if args.generate:
        length = getattr(args, "length", 16)
        pwd    = generate_password(length)
        print(f"\n  Generated password : {pwd}")
        print("  Store it securely.")
        logger.info("Password generated (length=%d).", length)
        return

    result = analyze_password(args.password, model)
    _print_analysis(result)

    output = getattr(args, "output", None)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        logger.info("Result saved to %s", output)
