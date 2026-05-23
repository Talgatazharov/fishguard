"""
PhishGuard AI — Flask backend for phishing URL detection.
Prepared for TensorFlow/Keras model integration via models/ directory.
"""

import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Known brands for typo / homoglyph detection
KNOWN_BRANDS = [
    "instagram",
    "google",
    "facebook",
    "paypal",
    "kaspi",
    "halykbank",
    "microsoft",
    "apple",
    "amazon",
    "netflix",
]

# Suspicious keywords (+10 each)
SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "bank",
    "update",
    "payment",
    "signin",
]

# URL shortening services (+25)
SHORTENING_SERVICES = [
    "bit.ly",
    "tinyurl.com",
    "tinyurl",
    "t.co",
]

# Homoglyph normalization (0→o, 1→l, etc.)
HOMOGLYPH_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "@": "a",
    "$": "s",
}

# Minimum similarity to treat domain as brand typo (0–1)
BRAND_TYPO_RATIO_THRESHOLD = 0.72

# Feature order for future Keras model input
FEATURE_VECTOR_ORDER = [
    "url_length",
    "dot_count",
    "digit_count",
    "special_char_count",
    "has_https",
    "has_ip_address",
    "at_symbol",
    "dash_count",
    "suspicious_word_count",
    "subdomain_count",
    "is_shortened",
    "brand_typo",
    "brand_with_suspicious",
]

# Standard explanation messages (shown when the rule fires)
MSG_BRAND_TYPO = "Домен похож на известный бренд, но написан с ошибкой"
MSG_SUSPICIOUS_WORDS = "В URL найдены подозрительные слова"
MSG_NO_HTTPS = "HTTPS отсутствует"
MSG_SHORTENER = "Используется короткая ссылка"
MSG_AT_SYMBOL = "Обнаружен символ @"
MSG_IP_ADDRESS = "Обнаружен IP вместо домена"


def normalize_brand_string(text: str) -> str:
    """Normalize homoglyphs for brand comparison."""
    text = text.lower()
    for src, dst in HOMOGLYPH_MAP.items():
        text = text.replace(src, dst)
    return text


def similarity_ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def get_registrable_label(hostname: str) -> str:
    """Second-level domain label (e.g. intalgram from intalgram.com)."""
    host = (hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


def split_domain_segments(label: str) -> list[str]:
    return [s for s in re.split(r"[-_.]", label.lower()) if s]


def detect_brand_typo(domain_label: str) -> tuple[bool, str | None, str]:
    """
    Detect typo or homoglyph impersonation of a known brand.
    Returns (is_typo, matched_brand, detection_type).
    detection_type: 'homoglyph' | 'typo' | ''
    """
    if not domain_label:
        return False, None, ""

    raw_label = domain_label.lower()
    normalized_label = normalize_brand_string(raw_label)
    segments = split_domain_segments(raw_label)

    candidates = [raw_label, normalized_label, *segments]

    for candidate in candidates:
        if not candidate:
            continue
        cand_norm = normalize_brand_string(candidate)

        for brand in KNOWN_BRANDS:
            # Exact legitimate spelling
            if candidate == brand or cand_norm == brand:
                if candidate == brand:
                    continue
                # Homoglyph: looks like brand only after normalization (g00gle → google)
                if cand_norm == brand and candidate != brand:
                    return True, brand, "homoglyph"

            # Typo: similar but not the real brand
            ratio = similarity_ratio(cand_norm, brand)
            if ratio >= BRAND_TYPO_RATIO_THRESHOLD and cand_norm != brand:
                return True, brand, "typo"

            ratio_raw = similarity_ratio(candidate, brand)
            if ratio_raw >= BRAND_TYPO_RATIO_THRESHOLD and candidate != brand:
                return True, brand, "typo"

    return False, None, ""


def brand_in_domain(domain_label: str) -> str | None:
    """Return brand name if exactly present in domain label or its segments."""
    label_lower = domain_label.lower()
    segments = split_domain_segments(label_lower)

    for brand in KNOWN_BRANDS:
        if brand == label_lower or brand in segments:
            return brand
        if brand in label_lower and re.search(rf"(^|[-_.]){re.escape(brand)}([-.]|$)", label_lower):
            return brand
    return None


def extract_features(url: str) -> dict:
    """Extract numerical and boolean features from a URL string."""
    url = url.strip()
    if not url:
        return _empty_features()

    parse_url = url if "://" in url else f"http://{url}"
    try:
        parsed = urlparse(parse_url)
    except Exception:
        parsed = urlparse("")

    hostname = (parsed.netloc or parsed.path.split("/")[0]).split("@")[-1]
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    path_query = (parsed.path or "") + (parsed.query or "") + (parsed.fragment or "")
    full_lower = url.lower()
    domain_label = get_registrable_label(hostname)

    url_length = len(url)
    dot_count = url.count(".")
    digit_count = sum(c.isdigit() for c in url)
    special_chars = re.findall(r"[^a-zA-Z0-9.\-/:?&=#]", url)
    special_char_count = len(special_chars)
    dash_count = url.count("-")
    at_symbol = 1 if "@" in url else 0

    has_https = 1 if full_lower.startswith("https://") else 0

    ip_pattern = re.compile(r"(\d{1,3}\.){3}\d{1,3}")
    has_ip_address = 1 if ip_pattern.search(hostname) else 0

    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_lower]
    suspicious_word_count = len(found_keywords)

    subdomain_count = max(0, hostname.count(".") - 1) if hostname else 0

    host_lower = hostname.lower()
    is_shortened = 1 if any(svc in host_lower for svc in SHORTENING_SERVICES) else 0

    brand_typo_flag, matched_brand, typo_type = detect_brand_typo(domain_label)
    brand_typo = 1 if brand_typo_flag else 0

    detected_brand = brand_in_domain(domain_label)
    brand_with_suspicious = 0
    if detected_brand and suspicious_word_count > 0 and not brand_typo_flag:
        brand_with_suspicious = 1

    has_dash_in_domain = 1 if "-" in domain_label else 0

    return {
        "url_length": url_length,
        "dot_count": dot_count,
        "digit_count": digit_count,
        "special_char_count": special_char_count,
        "has_https": has_https,
        "has_ip_address": has_ip_address,
        "at_symbol": at_symbol,
        "dash_count": dash_count,
        "suspicious_word_count": suspicious_word_count,
        "subdomain_count": subdomain_count,
        "is_shortened": is_shortened,
        "brand_typo": brand_typo,
        "brand_with_suspicious": brand_with_suspicious,
        "has_dash_in_domain": has_dash_in_domain,
        "found_keywords": found_keywords,
        "matched_brand": matched_brand,
        "typo_type": typo_type,
        "detected_brand": detected_brand,
        "domain_label": domain_label,
        "hostname": hostname,
    }


def _empty_features() -> dict:
    base = {key: 0 for key in FEATURE_VECTOR_ORDER}
    base.update(
        {
            "has_dash_in_domain": 0,
            "found_keywords": [],
            "matched_brand": None,
            "typo_type": "",
            "detected_brand": None,
            "domain_label": "",
            "hostname": "",
        }
    )
    return base


def features_to_vector(features: dict) -> list:
    """Convert feature dict to ordered list for Keras model.predict()."""
    return [float(features.get(k, 0)) for k in FEATURE_VECTOR_ORDER]


def predict_phishing(features: dict) -> tuple[str, int, list[str]]:
    """
    Rule-based risk scoring.
    Returns: (status, risk_percent, explanations)
    """
    score = 0
    explanations: list[str] = []
    added_messages: set[str] = set()

    def add_explanation(message: str) -> None:
        if message not in added_messages:
            added_messages.add(message)
            explanations.append(message)

    # IP address (+30)
    if features["has_ip_address"]:
        score += 30
        add_explanation(MSG_IP_ADDRESS)

    # @ symbol (+25)
    if features["at_symbol"]:
        score += 25
        add_explanation(MSG_AT_SYMBOL)

    # No HTTPS (+15)
    if not features["has_https"]:
        score += 15
        add_explanation(MSG_NO_HTTPS)

    # URL length (+15)
    if features["url_length"] > 75:
        score += 15
        add_explanation(f"Слишком длинный URL ({features['url_length']} символов)")

    # Suspicious words (+10 each)
    if features["suspicious_word_count"] > 0:
        score += 10 * features["suspicious_word_count"]
        add_explanation(MSG_SUSPICIOUS_WORDS)

    # Shortening service (+25)
    if features["is_shortened"]:
        score += 25
        add_explanation(MSG_SHORTENER)

    # Many subdomains (+15)
    if features["subdomain_count"] >= 3:
        score += 15
        add_explanation(
            f"Избыточное количество поддоменов ({features['subdomain_count']})"
        )

    # Dash in domain (+10)
    if features.get("has_dash_in_domain"):
        score += 10
        add_explanation("В доменном имени используются дефисы")

    # Brand typo / homoglyph (+45)
    if features["brand_typo"]:
        score += 45
        brand = features.get("matched_brand") or "известный"
        add_explanation(MSG_BRAND_TYPO)
        if features.get("typo_type") == "homoglyph":
            add_explanation(
                f"Домен имитирует «{brand}» с подменой похожих символов (0/O, 1/l и т.д.)"
            )
        elif brand:
            add_explanation(f"Похоже на бренд «{brand.capitalize()}», но домен не является официальным")

    # Brand + suspicious words (+35)
    if features["brand_with_suspicious"]:
        score += 35
        brand = features.get("detected_brand") or "бренд"
        add_explanation(
            f"Сочетание бренда «{brand.capitalize()}» и подозрительных слов в URL"
        )

    risk = min(100, score)

    if risk <= 30:
        status = "Safe"
    elif risk <= 65:
        status = "Suspicious"
    else:
        status = "Phishing"

    if status == "Safe" and not explanations:
        explanations.append(
            "URL не содержит критических признаков фишинга. "
            "Рекомендуется дополнительная проверка вручную."
        )

    return status, risk, explanations


@app.route("/")
def index():
    """Serve main dashboard page."""
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    """
    Analyze URL and return phishing prediction JSON.
    Expected body: { "url": "https://example.com" }
    """
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "URL не указан"}), 400

    features = extract_features(url)
    # Remove internal-only fields from API response features
    api_features = {
        k: features[k]
        for k in FEATURE_VECTOR_ORDER
        if k in features
    }

    status, risk, explanation = predict_phishing(features)

    return jsonify(
        {
            "status": status,
            "risk": risk,
            "features": api_features,
            "explanation": explanation,
            "feature_vector": features_to_vector(features),
            "domain_label": features.get("domain_label", ""),
            "matched_brand": features.get("matched_brand"),
        }
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
