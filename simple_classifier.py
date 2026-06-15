"""
Simple Phishing URL Classifier - Works without pycaret
Uses scikit-learn for prediction based on URL features
"""

import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import os

class PhishingClassifier:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.model_path = 'model/simple_model.pkl'
        self.scaler_path = 'model/simple_scaler.pkl'
        self._load_or_create_model()
    
    def _load_or_create_model(self):
        """Load existing model or create a new pre-trained one"""
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                print("Model loaded successfully!")
                return
            except Exception as e:
                print(f"Error loading model: {e}")
        
        # Create and train a simple model with synthetic data
        self._create_pretrained_model()
    
    def _create_pretrained_model(self):
        """Create a pre-trained model with synthetic training data"""
        print("Creating new model...")
        
        # Generate synthetic training data
        # Features: [url_length, url_depth, is_tiny_url, has_prefix_suffix, 
        #            num_dots, has_sensitive_words, domain_age, domain_end, 
        #            has_symbol, domain_att]
        np.random.seed(42)
        n_samples = 1000
        
        # Safe URLs - typical characteristics
        safe_features = np.column_stack([
            np.random.normal(50, 15, n_samples // 2),      # url_length (shorter)
            np.random.randint(1, 4, n_samples // 2),       # url_depth (shallow)
            np.zeros(n_samples // 2),                       # is_tiny_url (no)
            np.zeros(n_samples // 2),                       # has_prefix_suffix (no)
            np.random.randint(1, 4, n_samples // 2),       # num_dots (few)
            np.zeros(n_samples // 2),                       # has_sensitive_words (no)
            np.random.randint(0, 2, n_samples // 2),       # domain_age (established)
            np.zeros(n_samples // 2),                       # domain_end (not suspicious)
            np.random.randint(0, 2, n_samples // 2),       # has_symbol (few)
            np.random.normal(0.3, 0.2, n_samples // 2),    # domain_att (low)
        ])
        
        # Phishing URLs - typical characteristics
        phish_features = np.column_stack([
            np.random.normal(100, 30, n_samples // 2),     # url_length (longer)
            np.random.randint(3, 8, n_samples // 2),       # url_depth (deep)
            np.random.randint(0, 2, n_samples // 2),       # is_tiny_url (sometimes)
            np.ones(n_samples // 2),                        # has_prefix_suffix (yes)
            np.random.randint(3, 8, n_samples // 2),       # num_dots (many)
            np.ones(n_samples // 2),                        # has_sensitive_words (yes)
            np.ones(n_samples // 2),                        # domain_age (new)
            np.ones(n_samples // 2),                        # domain_end (suspicious)
            np.random.randint(2, 5, n_samples // 2),       # has_symbol (many)
            np.random.normal(0.8, 0.2, n_samples // 2),    # domain_att (high)
        ])
        
        X = np.vstack([safe_features, phish_features])
        y = np.array([0] * (n_samples // 2) + [1] * (n_samples // 2))
        
        # Shuffle the data
        indices = np.random.permutation(n_samples)
        X = X[indices]
        y = y[indices]
        
        # Fit scaler and model
        X_scaled = self.scaler.fit_transform(X)
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_scaled, y)
        
        # Save model
        os.makedirs('model', exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        with open(self.scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        
        print("Model created and saved successfully!")
    
    def predict(self, features):
        """
        Predict if URL is phishing
        
        Args:
            features: numpy array or list of 10 features
            
        Returns:
            tuple: (prediction_label, prediction_score)
        """
        if self.model is None:
            return 0, 0.5
        
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
            return 0, 0.5


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
