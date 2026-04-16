"""
PhishGuard — Flask Backend
Render pe deploy hoga.
"""

import pickle
import re
import urllib.parse
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import os

app = Flask(__name__)

# ── CORS: Vercel frontend ka domain allow karo ──────────────────────────
CORS(app)

# ── Models load karo ───────────────────────────────────────────────────
BASE = os.path.dirname(__file__)

with open(os.path.join(BASE, "best_model.pkl"), "rb") as f:
    MODEL = pickle.load(f)

with open(os.path.join(BASE, "scaler.pkl"), "rb") as f:
    SCALER = pickle.load(f)

with open(os.path.join(BASE, "selected_features.pkl"), "rb") as f:
    FEATURES = pickle.load(f)   # List of 30 feature names

print(f"[PhishGuard] Model loaded | Features: {len(FEATURES)}")


# ═══════════════════════════════════════════════════════════════
#  FEATURE EXTRACTION HELPERS
#  30 features match karne chahiye training ke saath
# ═══════════════════════════════════════════════════════════════

def safe_get(url, timeout=6):
    """URL fetch karo — error pe None return karo"""
    try:
        headers = {"User-Agent": "Mozilla/5.0 (PhishGuard Security Scanner)"}
        r = requests.get(url, timeout=timeout, headers=headers,
                         allow_redirects=True, verify=False)
        return r
    except Exception:
        return None


def extract_features(url: str) -> dict:
    """URL se saare 30 features extract karo"""
    parsed   = urllib.parse.urlparse(url)
    domain   = parsed.netloc.lower().replace("www.", "")
    path     = parsed.path
    full_url = url.lower()

    # ── Address Bar features ──────────────────────────────────
    url_length       = len(url)
    domain_length    = len(domain)
    letters          = sum(c.isalpha() for c in url)
    digits           = sum(c.isdigit() for c in url)
    special_chars    = sum(1 for c in url if not c.isalnum() and c not in "-._~:/?#[]@!$&'()*+,;=%")
    is_https         = 1 if parsed.scheme == "https" else 0
    has_obfuscation  = 1 if "%" in url or "0x" in full_url else 0
    n_obfuscated     = url.count("%")

    letter_ratio   = letters / url_length if url_length else 0
    digit_ratio    = digits / url_length if url_length else 0
    special_ratio  = special_chars / url_length if url_length else 0

    # Continuation rate — longest run of same char type
    def char_continuation(s):
        if not s:
            return 0
        max_run = cur = 1
        for i in range(1, len(s)):
            cur = cur + 1 if s[i].isalpha() == s[i-1].isalpha() else 1
            max_run = max(max_run, cur)
        return max_run / len(s)

    char_cont_rate = char_continuation(url)

    # URL char probability (ratio of alpha chars)
    url_char_prob = letters / url_length if url_length else 0

    # URL similarity index — digit/special mix heuristic
    url_sim_index = int((1 - digit_ratio - special_ratio) * 100)

    # ── HTML / JS features — webpage fetch karo ──────────────
    resp = safe_get(url)
    html = resp.text if resp else ""
    soup = BeautifulSoup(html, "html.parser") if html else None

    line_of_code       = html.count("\n") if html else 0
    largest_line_len   = max((len(l) for l in html.split("\n")), default=0) if html else 0
    has_title          = 1 if soup and soup.title and soup.title.string else 0
    title_text         = (soup.title.string or "") if (soup and soup.title) else ""

    # Domain-title match score (simple overlap)
    domain_clean = domain.split(".")[0]
    title_lower  = title_text.lower()
    dom_title_match = 1 if domain_clean and domain_clean in title_lower else 0

    # URL-title match
    url_keywords   = set(re.findall(r"[a-z]{3,}", full_url))
    title_keywords = set(re.findall(r"[a-z]{3,}", title_lower))
    url_title_match = len(url_keywords & title_keywords) / max(len(url_keywords), 1)

    has_favicon     = 1 if soup and soup.find("link", rel=lambda r: r and "icon" in str(r).lower()) else 0
    robots          = 0  # Would need separate /robots.txt fetch — default 0

    is_responsive   = 1 if soup and soup.find("meta", attrs={"name": "viewport"}) else 0
    n_redirects     = len(resp.history) if resp else 0
    has_description = 1 if soup and soup.find("meta", attrs={"name": "description"}) else 0
    n_popups        = html.lower().count("window.open") if html else 0
    n_iframes       = len(soup.find_all("iframe")) if soup else 0

    # External form submit
    has_ext_form = 0
    if soup:
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action and not action.startswith("/") and domain not in action:
                has_ext_form = 1
                break

    has_social  = 1 if html and any(s in html.lower() for s in ["facebook", "twitter", "instagram", "linkedin"]) else 0
    has_submit  = 1 if soup and soup.find("input", {"type": "submit"}) else 0
    has_hidden  = 1 if soup and soup.find("input", {"type": "hidden"}) else 0
    has_password= 1 if soup and soup.find("input", {"type": "password"}) else 0

    # ── Domain / keyword features ─────────────────────────────
    bank_kw   = ["bank", "chase", "wells", "citibank", "hdfc", "icici", "sbi", "axis"]
    pay_kw    = ["paypal", "payment", "pay", "checkout", "billing", "invoice"]
    crypto_kw = ["crypto", "bitcoin", "btc", "ethereum", "wallet", "binance"]

    bank   = 1 if any(k in full_url for k in bank_kw)   else 0
    pay    = 1 if any(k in full_url for k in pay_kw)    else 0
    crypto = 1 if any(k in full_url for k in crypto_kw) else 0

    has_copyright = 1 if html and ("©" in html or "copyright" in html.lower()) else 0

    # HTML asset counts
    n_images   = len(soup.find_all("img"))  if soup else 0
    n_css      = len(soup.find_all("link", rel="stylesheet")) if soup else 0
    n_js       = len(soup.find_all("script")) if soup else 0

    all_links  = [a.get("href", "") for a in soup.find_all("a")] if soup else []
    n_self_ref = sum(1 for h in all_links if h.startswith("/") or (domain in h)) if all_links else 0
    n_empty    = sum(1 for h in all_links if not h or h == "#") if all_links else 0
    n_ext_ref  = sum(1 for h in all_links if h.startswith("http") and domain not in h) if all_links else 0

    # ── Assemble feature dict matching FEATURES list ──────────
    feat_map = {
        "URLLength":                 url_length,
        "DomainLength":              domain_length,
        "URLSimilarityIndex":        url_sim_index,
        "CharContinuationRate":      char_cont_rate,
        "URLCharProb":               url_char_prob,
        "NoOfLettersInURL":          letters,
        "LetterRatioInURL":          letter_ratio,
        "DegitRatioInURL":           digit_ratio,
        "NoOfOtherSpecialCharsInURL":special_chars,
        "SpacialCharRatioInURL":     special_ratio,
        "IsHTTPS":                   is_https,
        "LineOfCode":                line_of_code,
        "HasTitle":                  has_title,
        "DomainTitleMatchScore":     dom_title_match,
        "URLTitleMatchScore":        url_title_match,
        "HasFavicon":                has_favicon,
        "Robots":                    robots,
        "IsResponsive":              is_responsive,
        "HasDescription":            has_description,
        "NoOfiFrame":                n_iframes,
        "HasSocialNet":              has_social,
        "HasSubmitButton":           has_submit,
        "HasHiddenFields":           has_hidden,
        "Bank":                      bank,
        "Pay":                       pay,
        "HasCopyrightInfo":          has_copyright,
        "NoOfImage":                 n_images,
        "NoOfJS":                    n_js,
        "NoOfSelfRef":               n_self_ref,
        "NoOfExternalRef":           n_ext_ref,
    }

    return feat_map


# ═══════════════════════════════════════════════════════════════
#  API ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "PhishGuard API running", "features": len(FEATURES)})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True)
    url  = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "URL required"}), 400

    # Basic URL validation
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        # Step 1: Feature extraction
        feat_dict = extract_features(url)

        # Step 2: Ordered feature vector (same order as training)
        vec = np.array([[feat_dict.get(f, 0) for f in FEATURES]])

        # Note: Random Forest doesn't need scaling, but we keep scaler
        # for consistency (scaler was fit but RF ignores it)
        # If model uses scaled input, uncomment below:
        # vec = SCALER.transform(vec)

        # Step 3: Prediction
        proba     = MODEL.predict_proba(vec)[0]   # [P(phishing), P(legit)]
        pred      = int(MODEL.predict(vec)[0])    # 0=phishing, 1=legit
        confidence= float(max(proba)) * 100

        # Step 4: Risk score (0-100, higher = more dangerous)
        risk_score = round((1 - proba[1]) * 100, 1)

        # Step 5: Which features flagged as suspicious
        suspicious = []
        if feat_dict.get("IsHTTPS") == 0:         suspicious.append("No HTTPS")
        if feat_dict.get("HasHiddenFields") == 1: suspicious.append("Hidden form fields")
        if feat_dict.get("NoOfiFrame") > 0:       suspicious.append(f"{feat_dict['NoOfiFrame']} iFrames detected")
        if feat_dict.get("HasExternalFormSubmit", 0) == 1: suspicious.append("External form submission")
        if feat_dict.get("URLLength", 0) > 100:  suspicious.append("Unusually long URL")
        if feat_dict.get("Bank") or feat_dict.get("Pay"): suspicious.append("Banking/Payment keywords in URL")
        if feat_dict.get("HasTitle") == 0:        suspicious.append("No page title")
        if feat_dict.get("DomainTitleMatchScore") == 0 and feat_dict.get("HasTitle"): suspicious.append("Domain ≠ page title")

        return jsonify({
            "url":        url,
            "prediction": "phishing" if pred == 0 else "legitimate",
            "confidence": round(confidence, 1),
            "risk_score": risk_score,
            "is_safe":    pred == 1,
            "suspicious_flags": suspicious,
            "features": {
                "url_features": {k: feat_dict[k] for k in FEATURES[:11] if k in feat_dict},
                "html_features":{k: feat_dict[k] for k in FEATURES[11:22] if k in feat_dict},
                "domain_features":{k: feat_dict[k] for k in FEATURES[22:] if k in feat_dict},
            }
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
