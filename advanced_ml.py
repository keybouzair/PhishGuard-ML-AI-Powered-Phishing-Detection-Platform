"""
Advanced Machine Learning Module
Implements ensemble methods, deep learning, and model explainability
"""

import numpy as np
import pandas as pd
import pickle
import os
import json
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# Model paths
MODEL_DIR = 'model'
ENSEMBLE_MODEL_PATH = os.path.join(MODEL_DIR, 'ensemble_model.pkl')
NEURAL_NET_PATH = os.path.join(MODEL_DIR, 'neural_network.pkl')
FEATURE_IMPORTANCE_PATH = os.path.join(MODEL_DIR, 'feature_importance.json')


class FeatureImportanceExplainer:
    """Explain model predictions using feature importance"""
    
    def __init__(self):
        self.feature_names = [
            'URL_Length', 'URL_Depth', 'TinyURL', 'Prefix/Suffix', 
            'No_Of_Dots', 'Sensitive_Words', 'Domain_Age', 'Domain_End',
            'Have_Symbol', 'domain_att'
        ]
        
        # Default feature importances (would be trained in production)
        self.default_importances = {
            'URL_Length': 0.12,
            'URL_Depth': 0.08,
            'TinyURL': 0.15,
            'Prefix/Suffix': 0.10,
            'No_Of_Dots': 0.07,
            'Sensitive_Words': 0.18,
            'Domain_Age': 0.14,
            'Domain_End': 0.06,
            'Have_Symbol': 0.05,
            'domain_att': 0.05
        }
    
    def explain_prediction(self, features: pd.DataFrame, prediction: int, 
                          prediction_proba: float) -> Dict:
        """
        Explain why a URL was classified as phishing or safe
        
        Returns:
            Dictionary with explanation details
        """
        explanation = {
            'prediction': 'Phishing' if prediction == 1 else 'Safe',
            'confidence': prediction_proba * 100,
            'contributing_factors': [],
            'risk_breakdown': {},
            'recommendations': []
        }
        
        # Analyze each feature's contribution
        if features is not None and not features.empty:
            feature_values = features.iloc[0].to_dict()
            
            for feature, value in feature_values.items():
                importance = self.default_importances.get(feature, 0.05)
                contribution = self._analyze_feature_contribution(feature, value, importance)
                
                if contribution['risk_level'] != 'neutral':
                    explanation['contributing_factors'].append(contribution)
                
                explanation['risk_breakdown'][feature] = {
                    'value': float(value) if not pd.isna(value) else 0,
                    'importance': importance,
                    'risk_contribution': contribution['risk_score']
                }
        
        # Sort by risk contribution
        explanation['contributing_factors'].sort(
            key=lambda x: x['risk_score'], 
            reverse=True
        )
        
        # Add recommendations based on findings
        explanation['recommendations'] = self._generate_recommendations(
            explanation['contributing_factors'],
            prediction
        )
        
        return explanation
    
    def _analyze_feature_contribution(self, feature: str, value: float, 
                                      importance: float) -> Dict:
        """Analyze how a feature contributes to the risk"""
        contribution = {
            'feature': feature,
            'feature_name': self._get_feature_display_name(feature),
            'value': float(value) if not pd.isna(value) else 0,
            'importance': importance,
            'risk_level': 'neutral',
            'risk_score': 0,
            'explanation': ''
        }
        
        # Feature-specific analysis
        if feature == 'URL_Length':
            if value > 75:
                contribution['risk_level'] = 'high'
                contribution['risk_score'] = 0.8
                contribution['explanation'] = 'Unusually long URL, often used to hide malicious content'
            elif value > 54:
                contribution['risk_level'] = 'medium'
                contribution['risk_score'] = 0.5
                contribution['explanation'] = 'URL is longer than typical legitimate URLs'
        
        elif feature == 'TinyURL':
            if value == 1:
                contribution['risk_level'] = 'high'
                contribution['risk_score'] = 0.9
                contribution['explanation'] = 'URL shortener detected - hides true destination'
        
        elif feature == 'Sensitive_Words':
            if value >= 1:
                contribution['risk_level'] = 'high'
                contribution['risk_score'] = 0.85
                contribution['explanation'] = 'Contains sensitive keywords (login, verify, account, etc.)'
        
        elif feature == 'Domain_Age':
            if value == 1:
                contribution['risk_level'] = 'high'
                contribution['risk_score'] = 0.7
                contribution['explanation'] = 'Very new or unregistered domain'
        
        elif feature == 'Prefix/Suffix':
            if value == 1:
                contribution['risk_level'] = 'medium'
                contribution['risk_score'] = 0.6
                contribution['explanation'] = 'Domain contains suspicious prefix/suffix (hyphen)'
        
        elif feature == 'Have_Symbol':
            if value >= 1:
                contribution['risk_level'] = 'medium'
                contribution['risk_score'] = 0.5
                contribution['explanation'] = 'URL contains suspicious symbols (@, unicode, IP address)'
        
        elif feature == 'No_Of_Dots':
            if value > 4:
                contribution['risk_level'] = 'medium'
                contribution['risk_score'] = 0.4
                contribution['explanation'] = 'Excessive subdomains in URL'
        
        return contribution
    
    def _get_feature_display_name(self, feature: str) -> str:
        """Get human-readable feature name"""
        names = {
            'URL_Length': 'URL Length',
            'URL_Depth': 'URL Depth (Directory Levels)',
            'TinyURL': 'URL Shortener',
            'Prefix/Suffix': 'Suspicious Prefix/Suffix',
            'No_Of_Dots': 'Number of Subdomains',
            'Sensitive_Words': 'Sensitive Keywords',
            'Domain_Age': 'Domain Age',
            'Domain_End': 'Domain Expiry',
            'Have_Symbol': 'Suspicious Symbols',
            'domain_att': 'Domain Attributes'
        }
        return names.get(feature, feature)
    
    def _generate_recommendations(self, factors: List[Dict], prediction: int) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if prediction == 1:  # Phishing
            recommendations.append("⚠️ Do NOT enter any personal information on this website")
            recommendations.append("⚠️ Do NOT download any files from this URL")
            
            for factor in factors[:3]:  # Top 3 risk factors
                if factor['feature'] == 'TinyURL':
                    recommendations.append("🔗 Avoid clicking shortened URLs from untrusted sources")
                elif factor['feature'] == 'Sensitive_Words':
                    recommendations.append("📧 Be suspicious of URLs containing words like 'login', 'verify', 'account'")
                elif factor['feature'] == 'Domain_Age':
                    recommendations.append("🆕 Be cautious with newly registered domains")
                elif factor['feature'] == 'URL_Length':
                    recommendations.append("📏 Legitimate sites typically have shorter, cleaner URLs")
            
            recommendations.append("🔒 If you need to access your account, type the official URL directly")
            recommendations.append("📞 Contact the company directly through official channels if unsure")
        else:
            recommendations.append("✅ This URL appears to be safe")
            recommendations.append("💡 Always verify the URL in your browser's address bar")
            recommendations.append("🔐 Ensure the site uses HTTPS for sensitive transactions")
        
        return recommendations


class EnsembleClassifier:
    """Ensemble classifier combining multiple models"""
    
    def __init__(self):
        self.models = {}
        self.weights = {}
        self.is_trained = False
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models"""
        try:
            # Try to load the main model
            main_model_path = os.path.join(MODEL_DIR, 'phishingdetection.pkl')
            if os.path.exists(main_model_path):
                with open(main_model_path, 'rb') as f:
                    self.models['main'] = pickle.load(f)
                    self.weights['main'] = 0.6
                    self.is_trained = True
            
            # Try to load ensemble model
            if os.path.exists(ENSEMBLE_MODEL_PATH):
                with open(ENSEMBLE_MODEL_PATH, 'rb') as f:
                    ensemble_data = pickle.load(f)
                    self.models.update(ensemble_data.get('models', {}))
                    self.weights.update(ensemble_data.get('weights', {}))
                    
        except Exception as e:
            print(f"Error loading models: {e}")
    
    def predict(self, features: pd.DataFrame) -> Tuple[int, float]:
        """
        Make ensemble prediction
        
        Returns:
            Tuple of (prediction, probability)
        """
        if not self.models:
            return 0, 0.5
        
        predictions = []
        probabilities = []
        total_weight = 0
        
        for name, model in self.models.items():
            try:
                weight = self.weights.get(name, 0.5)
                pred = model.predict(features)[0]
                
                if hasattr(model, 'predict_proba'):
                    proba = model.predict_proba(features)[0][1]
                else:
                    proba = float(pred)
                
                predictions.append((pred, weight))
                probabilities.append((proba, weight))
                total_weight += weight
                
            except Exception as e:
                print(f"Prediction error for {name}: {e}")
        
        if not predictions:
            return 0, 0.5
        
        # Weighted voting
        weighted_proba = sum(p * w for p, w in probabilities) / total_weight
        final_prediction = 1 if weighted_proba >= 0.5 else 0
        
        return final_prediction, weighted_proba
    
    def get_model_contributions(self, features: pd.DataFrame) -> Dict:
        """Get individual model predictions for comparison"""
        contributions = {}
        
        for name, model in self.models.items():
            try:
                pred = model.predict(features)[0]
                
                if hasattr(model, 'predict_proba'):
                    proba = model.predict_proba(features)[0][1]
                else:
                    proba = float(pred)
                
                contributions[name] = {
                    'prediction': int(pred),
                    'probability': float(proba),
                    'weight': self.weights.get(name, 0.5)
                }
                
            except Exception as e:
                contributions[name] = {'error': str(e)}
        
        return contributions


class AnomalyDetector:
    """Detect anomalous URL patterns"""
    
    def __init__(self):
        self.normal_stats = self._get_normal_stats()
    
    def _get_normal_stats(self) -> Dict:
        """Get statistics for normal URLs"""
        return {
            'URL_Length': {'mean': 50, 'std': 20, 'max': 100},
            'URL_Depth': {'mean': 3, 'std': 2, 'max': 8},
            'No_Of_Dots': {'mean': 2, 'std': 1, 'max': 5},
        }
    
    def detect_anomaly(self, features: pd.DataFrame) -> Dict:
        """
        Detect if URL features are anomalous
        
        Returns:
            Dictionary with anomaly score and details
        """
        result = {
            'is_anomaly': False,
            'anomaly_score': 0,
            'anomalies_detected': [],
            'details': {}
        }
        
        if features is None or features.empty:
            return result
        
        total_score = 0
        anomaly_count = 0
        
        feature_values = features.iloc[0].to_dict()
        
        for feature, stats in self.normal_stats.items():
            if feature in feature_values:
                value = feature_values[feature]
                
                # Calculate z-score
                z_score = abs(value - stats['mean']) / max(stats['std'], 0.1)
                
                # Check if anomalous (z-score > 2)
                if z_score > 2 or value > stats['max']:
                    anomaly_count += 1
                    total_score += min(z_score / 5, 1)  # Normalize to 0-1
                    
                    result['anomalies_detected'].append({
                        'feature': feature,
                        'value': value,
                        'expected_max': stats['max'],
                        'z_score': round(z_score, 2)
                    })
                
                result['details'][feature] = {
                    'value': value,
                    'z_score': round(z_score, 2),
                    'is_anomalous': z_score > 2
                }
        
        result['anomaly_score'] = round(total_score / max(len(self.normal_stats), 1), 2)
        result['is_anomaly'] = anomaly_count >= 2 or result['anomaly_score'] > 0.5
        
        return result


class TypoSquattingDetector:
    """Detect typosquatting (lookalike domains)"""
    
    def __init__(self):
        self.legitimate_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'apple.com',
            'microsoft.com', 'paypal.com', 'netflix.com', 'instagram.com',
            'twitter.com', 'linkedin.com', 'gmail.com', 'yahoo.com',
            'ebay.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
            'dropbox.com', 'adobe.com', 'spotify.com', 'slack.com'
        ]
    
    def check_typosquatting(self, url: str) -> Dict:
        """
        Check if URL might be typosquatting a legitimate domain
        
        Returns:
            Dictionary with typosquatting detection results
        """
        from urllib.parse import urlparse
        
        result = {
            'is_typosquatting': False,
            'similar_to': None,
            'similarity_score': 0,
            'techniques_detected': []
        }
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove www prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            for legit_domain in self.legitimate_domains:
                similarity = self._calculate_similarity(domain, legit_domain)
                
                if similarity > result['similarity_score'] and similarity < 1.0:
                    result['similarity_score'] = similarity
                    result['similar_to'] = legit_domain
                    
                    # Detect specific techniques
                    techniques = self._detect_techniques(domain, legit_domain)
                    result['techniques_detected'] = techniques
            
            # Consider it typosquatting if similarity > 0.7
            result['is_typosquatting'] = result['similarity_score'] > 0.7
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _calculate_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between two domains using Levenshtein distance"""
        # Remove TLD for comparison
        d1 = domain1.split('.')[0]
        d2 = domain2.split('.')[0]
        
        if len(d1) == 0 or len(d2) == 0:
            return 0.0
        
        # Simple Levenshtein distance implementation
        if d1 == d2:
            return 1.0
        
        len1, len2 = len(d1), len(d2)
        
        if abs(len1 - len2) > 3:
            return 0.0
        
        # Create matrix
        matrix = [[0] * (len2 + 1) for _ in range(len1 + 1)]
        
        for i in range(len1 + 1):
            matrix[i][0] = i
        for j in range(len2 + 1):
            matrix[0][j] = j
        
        for i in range(1, len1 + 1):
            for j in range(1, len2 + 1):
                cost = 0 if d1[i-1] == d2[j-1] else 1
                matrix[i][j] = min(
                    matrix[i-1][j] + 1,
                    matrix[i][j-1] + 1,
                    matrix[i-1][j-1] + cost
                )
        
        distance = matrix[len1][len2]
        max_len = max(len1, len2)
        
        return 1 - (distance / max_len)
    
    def _detect_techniques(self, suspicious: str, legitimate: str) -> List[str]:
        """Detect specific typosquatting techniques used"""
        techniques = []
        
        # Check for common substitutions
        substitutions = {
            'o': '0', '0': 'o',
            'l': '1', '1': 'l',
            'i': '1', '1': 'i',
            'e': '3', '3': 'e',
            'a': '4', '4': 'a',
            's': '5', '5': 's',
            'rn': 'm', 'm': 'rn',
            'vv': 'w', 'w': 'vv'
        }
        
        for orig, sub in substitutions.items():
            if orig in legitimate and suspicious.replace(orig, sub) == legitimate:
                techniques.append(f'Character substitution: {orig} → {sub}')
        
        # Check for missing/added characters
        if len(suspicious) == len(legitimate) - 1:
            techniques.append('Missing character')
        elif len(suspicious) == len(legitimate) + 1:
            techniques.append('Added character')
        
        # Check for transposition
        for i in range(len(legitimate) - 1):
            transposed = legitimate[:i] + legitimate[i+1] + legitimate[i] + legitimate[i+2:]
            if suspicious.startswith(transposed.split('.')[0]):
                techniques.append('Character transposition')
                break
        
        # Check for homoglyph attack
        homoglyphs = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p',  # Cyrillic
            'ı': 'i', 'ɡ': 'g'  # Other lookalikes
        }
        
        for cyrillic, latin in homoglyphs.items():
            if cyrillic in suspicious:
                techniques.append('Homoglyph attack (lookalike Unicode characters)')
                break
        
        return techniques


class ModelRetrainer:
    """Handles continuous model retraining with new data"""
    
    def __init__(self):
        self.training_data_path = os.path.join(MODEL_DIR, 'training_data.json')
        self.min_samples_for_retrain = 100
    
    def add_training_sample(self, features: Dict, label: int, url: str):
        """Add a new training sample"""
        try:
            # Load existing data
            if os.path.exists(self.training_data_path):
                with open(self.training_data_path, 'r') as f:
                    data = json.load(f)
            else:
                data = {'samples': [], 'last_retrain': None}
            
            # Add new sample
            sample = {
                'features': features,
                'label': label,
                'url': url,
                'added_at': datetime.now().isoformat()
            }
            data['samples'].append(sample)
            
            # Save data
            with open(self.training_data_path, 'w') as f:
                json.dump(data, f)
            
            # Check if retraining is needed
            if len(data['samples']) >= self.min_samples_for_retrain:
                self._trigger_retrain()
            
            return True
            
        except Exception as e:
            print(f"Error adding training sample: {e}")
            return False
    
    def _trigger_retrain(self):
        """Trigger model retraining (would be async in production)"""
        print("Retraining triggered - would run async job in production")
        # In production, this would queue a background job
    
    def get_training_stats(self) -> Dict:
        """Get training data statistics"""
        try:
            if os.path.exists(self.training_data_path):
                with open(self.training_data_path, 'r') as f:
                    data = json.load(f)
                
                samples = data.get('samples', [])
                phishing = sum(1 for s in samples if s.get('label') == 1)
                safe = len(samples) - phishing
                
                return {
                    'total_samples': len(samples),
                    'phishing_samples': phishing,
                    'safe_samples': safe,
                    'last_retrain': data.get('last_retrain'),
                    'ready_for_retrain': len(samples) >= self.min_samples_for_retrain
                }
        except:
            pass
        
        return {
            'total_samples': 0,
            'phishing_samples': 0,
            'safe_samples': 0,
            'last_retrain': None,
            'ready_for_retrain': False
        }


# Create singleton instances
explainer = FeatureImportanceExplainer()
ensemble_classifier = EnsembleClassifier()
anomaly_detector = AnomalyDetector()
typosquatting_detector = TypoSquattingDetector()
model_retrainer = ModelRetrainer()


def get_comprehensive_prediction(url: str, features: pd.DataFrame) -> Dict:
    """
    Get comprehensive prediction with explanation
    
    Returns:
        Dictionary with prediction, explanation, and all analysis results
    """
    result = {
        'url': url,
        'timestamp': datetime.now().isoformat()
    }
    
    # Ensemble prediction
    prediction, probability = ensemble_classifier.predict(features)
    result['prediction'] = {
        'label': 'Phishing' if prediction == 1 else 'Safe',
        'is_phishing': prediction == 1,
        'probability': round(probability * 100, 2)
    }
    
    # Model contributions
    result['model_contributions'] = ensemble_classifier.get_model_contributions(features)
    
    # Explanation
    result['explanation'] = explainer.explain_prediction(features, prediction, probability)
    
    # Anomaly detection
    result['anomaly_detection'] = anomaly_detector.detect_anomaly(features)
    
    # Typosquatting check
    result['typosquatting'] = typosquatting_detector.check_typosquatting(url)
    
    # Calculate final risk score
    risk_score = probability * 100
    if result['anomaly_detection']['is_anomaly']:
        risk_score = min(risk_score + 15, 100)
    if result['typosquatting']['is_typosquatting']:
        risk_score = min(risk_score + 20, 100)
    
    result['final_risk_score'] = round(risk_score, 2)
    result['risk_level'] = _get_risk_level(risk_score)
    
    return result


def _get_risk_level(score: float) -> str:
    """Convert risk score to level"""
    if score >= 80:
        return 'critical'
    elif score >= 60:
        return 'high'
    elif score >= 40:
        return 'medium'
    elif score >= 20:
        return 'low'
    return 'safe'
