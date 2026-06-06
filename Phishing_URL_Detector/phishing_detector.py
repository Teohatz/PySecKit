import os
import sys
import re
import json
import math
import logging
import urllib.parse
from collections import Counter

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

logger = logging.getLogger(__name__)

MODEL_VERSION = "3.1"

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_PATH  = os.path.join(BASE_DIR, "data",   "phishing_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_detector.pkl")

os.makedirs(os.path.dirname(DATA_PATH),  exist_ok=True)
os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

KNOWN_LEGIT_DOMAINS = {
    "youtube.com", "google.com", "paypal.com", "amazon.com",
    "facebook.com", "twitter.com", "microsoft.com", "apple.com",
    "chase.com", "bankofamerica.com", "netflix.com", "ebay.com",
    "linkedin.com", "instagram.com", "dropbox.com", "spotify.com",
}

COMMON_BRANDS = [
    "paypal", "google", "amazon", "apple", "microsoft", "facebook",
    "ebay", "netflix", "bank", "chase", "verizon", "wellsfargo",
    "citi", "irs", "dropbox", "spotify", "linkedin", "instagram",
    "twitter", "yahoo", "outlook", "hotmail", "icloud",
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "security",
    "alert", "authentication", "verification", "recovery", "service",
    "confirm", "validation", "password", "banking", "payment",
]


# ---------- Feature extraction ----------

class URLFeatureExtractor:

    @staticmethod
    def _base_domain(domain: str) -> str:
        parts = domain.split(".")
        return ".".join(parts[-2:]) if len(parts) > 1 else domain

    @classmethod
    def is_typosquatting(cls, domain: str) -> bool:
        base = cls._base_domain(domain)
        if base in KNOWN_LEGIT_DOMAINS:
            return False
        for legit in KNOWN_LEGIT_DOMAINS:
            if base == legit:
                return False
            if len(base) == len(legit):
                if sum(a != b for a, b in zip(base, legit)) == 1:
                    return True
            if legit.replace(".", "") == base:
                return True
        return False

    @staticmethod
    def domain_entropy(domain: str) -> float:
        if not domain:
            return 0.0
        counts = Counter(domain)
        probs  = [v / len(domain) for v in counts.values()]
        return -sum(p * math.log(p) for p in probs)

    @classmethod
    def contains_brand_in_suspicious_context(cls, domain: str) -> bool:
        """
        Returns True only when a known brand name appears in a domain
        that is NOT itself a known legitimate domain.
        Fixes the original bug where linkedin.com was flagged.
        """
        base = cls._base_domain(domain)
        if base in KNOWN_LEGIT_DOMAINS:
            return False
        return any(brand in domain for brand in COMMON_BRANDS)

    @staticmethod
    def count_suspicious_keywords(text: str) -> int:
        return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in text)

    @classmethod
    def extract(cls, url: str) -> np.ndarray:
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower().split(":")[0].replace("www.", "")
            path   = parsed.path.lower()
            query  = parsed.query.lower()
            tld    = domain.split(".")[-1] if "." in domain else ""

            features = [
                len(url),
                len(domain),
                int(parsed.scheme == "https"),
                int("@" in url),
                domain.count("."),
                int("-" in domain),
                int("_" in domain),
                int("=" in query),
                int("?" in url),
                int("#" in url),
                int("//" in path),
                int(domain.split(".")[0].isdigit()),
                len(path.split("/")),
                int(len(path) > 20),
                int(not query),
                int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))),
                int(bool(re.search(r"[^\w\-.]", domain))),
                int(len(tld) > 3),
                int(parsed.port is not None),
                int(parsed.username is not None or parsed.password is not None),
                int(url != url.lower()),
                int("%" in url),
                int(any(k in domain for k in KNOWN_LEGIT_DOMAINS)),
                int(cls.is_typosquatting(domain)),
                cls.domain_entropy(domain.split(".")[0]),
                int(cls.contains_brand_in_suspicious_context(domain)),
                cls.count_suspicious_keywords(domain),
                int(len(domain) > 30),
                int(any(kw in path for kw in SUSPICIOUS_KEYWORDS)),
            ]
            return np.array(features)
        except Exception as e:
            logger.debug("Feature extraction error for '%s': %s", url, e)
            return np.zeros(29)


# ---------- Model ----------

def _train_model() -> RandomForestClassifier:
    if not os.path.exists(DATA_PATH):
        logger.error("Dataset not found: %s", DATA_PATH)
        sys.exit(1)

    df = pd.read_csv(DATA_PATH)
    df["label"] = df["label"].astype(int)
    logger.info("Dataset loaded. Class distribution:\n%s", df["label"].value_counts().to_string())

    extractor = URLFeatureExtractor()
    X = np.array([extractor.extract(u) for u in df["url"]])
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        class_weight="balanced",
        random_state=42,
        min_samples_split=5,
        min_samples_leaf=2,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)
    logger.info("Training complete | accuracy=%.2f%%\n%s",
                acc * 100,
                classification_report(y_test, y_pred,
                                      target_names=["Legitimate", "Phishing"],
                                      zero_division=0))

    joblib.dump(model, MODEL_PATH)
    logger.info("Model saved to %s", MODEL_PATH)
    return model


def _load_or_train(force_retrain: bool = False) -> RandomForestClassifier:
    if not force_retrain and os.path.exists(MODEL_PATH):
        logger.debug("Loading model from %s", MODEL_PATH)
        return joblib.load(MODEL_PATH)
    logger.info("Training phishing detection model...")
    return _train_model()


# ---------- Analysis ----------

def analyze_url(url: str, model: RandomForestClassifier) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower().replace("www.", "")
    extractor = URLFeatureExtractor()

    # Rule-based shortcuts
    base = extractor._base_domain(domain)
    if base in KNOWN_LEGIT_DOMAINS:
        return _build_result(url, domain, 0, 0.0, "Exact match with known legitimate domain", extractor)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        return _build_result(url, domain, 1, 1.0, "Uses raw IP address instead of domain name", extractor)
    if "@" in url:
        return _build_result(url, domain, 1, 1.0, "Contains @ symbol (obfuscation technique)", extractor)

    features    = extractor.extract(url).reshape(1, -1)
    prediction  = int(model.predict(features)[0])
    probability = float(model.predict_proba(features)[0][1])
    return _build_result(url, domain, prediction, probability, None, extractor)


def _build_result(url, domain, prediction, probability, rule_reason, extractor) -> dict:
    indicators = []
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        indicators.append("Missing HTTPS")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        indicators.append("IP address used instead of domain")
    if extractor.is_typosquatting(domain):
        indicators.append("Possible typosquatting detected")
    if extractor.contains_brand_in_suspicious_context(domain):
        indicators.append("Brand name in suspicious context")
    if len(domain) > 30:
        indicators.append("Unusually long domain name")
    if extractor.count_suspicious_keywords(domain) >= 2:
        indicators.append("Multiple suspicious keywords in domain")

    return {
        "url":         url,
        "verdict":     "PHISHING" if prediction else "LEGITIMATE",
        "confidence":  round(probability * 100 if prediction else (1 - probability) * 100, 1),
        "rule_reason": rule_reason,
        "indicators":  indicators,
    }


def _print_result(result: dict):
    label     = result["verdict"]
    indicator = "[!]" if label == "PHISHING" else "[+]"
    print(f"\n  {indicator} Verdict     : {label}")
    print(f"  Confidence  : {result['confidence']}%")
    if result["rule_reason"]:
        print(f"  Reason      : {result['rule_reason']}")
    if result["indicators"]:
        print("  Indicators  :")
        for item in result["indicators"]:
            print(f"    - {item}")
    else:
        print("  Indicators  : None detected")


# ---------- Entry point ----------

def run_phishing_detector(args):
    force_retrain = getattr(args, "retrain", False)
    model         = _load_or_train(force_retrain)
    output_path   = getattr(args, "output", None)
    results       = []

    urls = []
    if getattr(args, "url", None):
        urls = [args.url]
    elif getattr(args, "file", None):
        if not os.path.isfile(args.file):
            logger.error("File not found: %s", args.file)
            return
        with open(args.file, encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        logger.error("Provide --url or --file.")
        return

    for url in urls:
        result = analyze_url(url, model)
        _print_result(result)
        results.append(result)

    if output_path:
        ext = os.path.splitext(output_path)[1].lower()
        if ext == ".json":
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
        else:
            import csv
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["url", "verdict", "confidence", "rule_reason", "indicators"])
                writer.writeheader()
                for r in results:
                    r2 = r.copy()
                    r2["indicators"] = "; ".join(r2["indicators"])
                    writer.writerow(r2)
        logger.info("Results saved to %s", output_path)
