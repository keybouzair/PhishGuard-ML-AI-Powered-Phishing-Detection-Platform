"""Unified feature pipeline used by both training and inference.

This module is the single source of truth for URL feature extraction.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

import pandas as pd

FEATURE_NAMES = [
    "URL_Length",
    "URL_Depth",
    "TinyURL",
    "Prefix/Suffix",
    "No_Of_Dots",
    "Sensitive_Words",
    "Domain_Age",
    "Domain_End",
    "Have_Symbol",
    "domain_att",
]

TINY_URL_PATTERN = r"bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|is\.gd|buff\.ly|adf\.ly|t\.co"
SENSITIVE_WORDS = [
    "login",
    "bank",
    "update",
    "security",
    "verify",
    "account",
    "signin",
    "password",
    "confirm",
    "suspend",
]
SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc"]
TRUSTED_DOMAINS = [
    "google",
    "facebook",
    "amazon",
    "microsoft",
    "apple",
    "twitter",
    "linkedin",
    "github",
    "youtube",
    "instagram",
]


def extract_feature_vector(url: str) -> list[float]:
    """Extract canonical URL feature vector.

    The output order must always match ``FEATURE_NAMES``.
    """
    u = str(url).strip().lower()
    parsed = urlparse(u)
    domain = parsed.netloc

    f_url_length = len(u)
    f_url_depth = parsed.path.count("/")
    f_is_tiny_url = 1 if re.search(TINY_URL_PATTERN, u) else 0
    f_has_prefix_suffix = 1 if "-" in domain else 0
    f_num_dots = u.count(".")
    f_has_sensitive_words = 1 if any(w in u for w in SENSITIVE_WORDS) else 0
    f_domain_age_indicator = 0 if any(td in domain for td in TRUSTED_DOMAINS) else 1
    f_domain_end = 1 if any(u.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0
    f_has_symbol = sum(1 for c in u if c in "@-_~")
    f_domain_att = (f_has_prefix_suffix + f_has_sensitive_words + f_domain_end) / 3.0

    return [
        f_url_length,
        f_url_depth,
        f_is_tiny_url,
        f_has_prefix_suffix,
        f_num_dots,
        f_has_sensitive_words,
        f_domain_age_indicator,
        f_domain_end,
        f_has_symbol,
        f_domain_att,
    ]


def build_feature_frame(url: str) -> pd.DataFrame:
    """Build a one-row DataFrame with canonical feature names."""
    return pd.DataFrame([extract_feature_vector(url)], columns=FEATURE_NAMES)
