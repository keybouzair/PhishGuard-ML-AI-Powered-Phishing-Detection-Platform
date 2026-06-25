"""
Simple Phishing URL Classifier - Works without pycaret
Uses scikit-learn for prediction based on URL features
"""

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import os

class PhishingClassifier:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.model_path = 'model/simple_model.joblib'
        self.scaler_path = 'model/simple_scaler.joblib'
        self._load_or_create_model()
    
    def _load_or_create_model(self):
        """Load existing model (C-11: Refuse to serve if deleted/missing)."""
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                print("Model loaded successfully!")
                return
            except Exception as e:
                raise RuntimeError(f"Error loading classifier model: {e}")
        
        # C-11: Do not silently fallback to creating a synthetic model
        raise FileNotFoundError(
            f"Classifier model files not found: {self.model_path} or {self.scaler_path}. "
            "Run train.py to generate them."
        )
    
    def _create_pretrained_model(self):
        """Removed to prevent silent synthetic fallback (C-11)."""
        pass
    
    def predict(self, features):
        """
        Predict if URL is phishing
        
        Args:
            features: numpy array or list of 10 features
            
        Returns:
            tuple: (prediction_label, prediction_score)
        """
        if self.model is None:
            raise RuntimeError("Model not loaded")
        
        try:
            features = np.array(features).reshape(1, -1)
            features_scaled = self.scaler.transform(features)
            
            prediction = self.model.predict(features_scaled)[0]
            proba = self.model.predict_proba(features_scaled)[0]
            
            # Get probability of phishing (class 1)
            phishing_score = proba[1] if len(proba) > 1 else proba[0]
            
            return int(prediction), float(phishing_score)
        except Exception as e:
            print(f"Prediction error: {e}")
            raise e


# Create global classifier instance
classifier = PhishingClassifier()


def extract_simple_features(url):
    """Extract features from URL for prediction"""
    import re
    from urllib.parse import urlparse
    
    features = []
    
    # 1. URL Length
    features.append(len(url))
    
    # 2. URL Depth (number of slashes in path)
    parsed = urlparse(url)
    path = parsed.path
    features.append(path.count('/'))
    
    # 3. Is Tiny URL
    tiny_url_pattern = r"bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|is\.gd|buff\.ly|adf\.ly|t\.co"
    features.append(1 if re.search(tiny_url_pattern, url.lower()) else 0)
    
    # 4. Has Prefix/Suffix (dash in domain)
    domain = parsed.netloc
    features.append(1 if '-' in domain else 0)
    
    # 5. Number of dots
    features.append(url.count('.'))
    
    # 6. Has sensitive words
    sensitive_words = ['login', 'bank', 'update', 'security', 'verify', 'account', 
                       'signin', 'password', 'confirm', 'suspend']
    has_sensitive = any(word in url.lower() for word in sensitive_words)
    features.append(1 if has_sensitive else 0)
    
    # 7. Domain age indicator (based on known trusted domains)
    trusted_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 
                       'twitter', 'linkedin', 'github', 'youtube', 'instagram']
    is_trusted = any(td in domain.lower() for td in trusted_domains)
    features.append(0 if is_trusted else 1)
    
    # 8. Domain end indicator (suspicious TLDs)
    suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc']
    has_suspicious_tld = any(url.lower().endswith(tld) for tld in suspicious_tlds)
    features.append(1 if has_suspicious_tld else 0)
    
    # 9. Has symbols (@, -, _, etc.)
    symbol_count = sum(1 for c in url if c in '@-_~')
    features.append(symbol_count)
    
    # 10. Domain attribute (combination score)
    domain_att = (features[3] + features[5] + features[7]) / 3.0
    features.append(domain_att)
    
    return features


def predict_url(url):
    """
    Main prediction function
    
    Args:
        url: URL string to analyze
        
    Returns:
        dict with prediction results
    """
    try:
        features = extract_simple_features(url)
        prediction, score = classifier.predict(features)
        
        if prediction == 1:
            label = "Unsafe"
        else:
            label = "Safe"
        
        return {
            'url': url,
            'prediction_label': label,
            'prediction_score': score * 100,
            'is_phishing': prediction == 1
        }
    except Exception as e:
        print(f"Error predicting URL: {e}")
        return {
            'url': url,
            'prediction_label': 'Error',
            'prediction_score': 0,
            'is_phishing': False
        }


if __name__ == "__main__":
    # Test the classifier
    test_urls = [
        "https://www.google.com",
        "https://www.facebook.com/login",
        "http://suspicious-login-bank-verify.xyz/account/update",
        "https://bit.ly/abc123",
        "https://github.com/user/repo",
        "http://192.168.1.1/admin/login.php"
    ]
    
    print("\nTesting URL Classifier:")
    print("-" * 60)
    for url in test_urls:
        result = predict_url(url)
        print(f"URL: {url[:50]}...")
        print(f"  Prediction: {result['prediction_label']}")
        print(f"  Risk Score: {result['prediction_score']:.1f}%")
        print()
