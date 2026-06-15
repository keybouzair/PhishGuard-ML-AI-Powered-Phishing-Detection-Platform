"""
Threat Intelligence Module
Integrates with external threat intelligence APIs for enhanced phishing detection
"""

import requests
import hashlib
import base64
import json
import time
from urllib.parse import urlparse
from datetime import datetime, timedelta
from functools import lru_cache
import os

# Configuration
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', 'your_virustotal_api_key_here')
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY', 'your_google_api_key_here')
URLHAUS_API_URL = 'https://urlhaus-api.abuse.ch/v1'
PHISHTANK_API_KEY = os.environ.get('PHISHTANK_API_KEY', '')

# Cache for API responses (in-memory)
_threat_cache = {}
CACHE_DURATION = 3600  # 1 hour


class ThreatIntelligence:
    """Main class for threat intelligence operations"""
    
    def __init__(self):
        self.results = {}
        self.total_score = 0
        self.max_score = 100
    
    def check_url(self, url):
        """
        Comprehensive URL check against multiple threat intelligence sources
        Returns a combined threat assessment
        """
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'sources': {},
            'threat_score': 0,
            'is_malicious': False,
            'threat_level': 'unknown',
            'details': []
        }
        
        # Check cache first
        cache_key = hashlib.md5(url.encode()).hexdigest()
        if cache_key in _threat_cache:
            cached = _threat_cache[cache_key]
            if datetime.now() - cached['cached_at'] < timedelta(seconds=CACHE_DURATION):
                return cached['data']
        
        # Run all checks
        vt_result = self.check_virustotal(url)
        gsb_result = self.check_google_safe_browsing(url)
        urlhaus_result = self.check_urlhaus(url)
        phishtank_result = self.check_phishtank(url)
        
        results['sources']['virustotal'] = vt_result
        results['sources']['google_safe_browsing'] = gsb_result
        results['sources']['urlhaus'] = urlhaus_result
        results['sources']['phishtank'] = phishtank_result
        
        # Calculate combined threat score
        threat_score = self._calculate_threat_score(results['sources'])
        results['threat_score'] = threat_score
        
        # Determine threat level
        if threat_score >= 70:
            results['threat_level'] = 'critical'
            results['is_malicious'] = True
        elif threat_score >= 50:
            results['threat_level'] = 'high'
            results['is_malicious'] = True
        elif threat_score >= 30:
            results['threat_level'] = 'medium'
            results['is_malicious'] = False
        elif threat_score >= 10:
            results['threat_level'] = 'low'
            results['is_malicious'] = False
        else:
            results['threat_level'] = 'safe'
            results['is_malicious'] = False
        
        # Cache the result
        _threat_cache[cache_key] = {
            'data': results,
            'cached_at': datetime.now()
        }
        
        return results
    
    def _calculate_threat_score(self, sources):
        """Calculate combined threat score from all sources"""
        score = 0
        weights = {
            'virustotal': 0.35,
            'google_safe_browsing': 0.30,
            'urlhaus': 0.20,
            'phishtank': 0.15
        }
        
        for source, result in sources.items():
            if result.get('is_malicious'):
                score += weights.get(source, 0.1) * 100
            elif result.get('score'):
                score += weights.get(source, 0.1) * result['score']
        
        return min(round(score, 2), 100)
    
    def check_virustotal(self, url):
        """Check URL against VirusTotal API"""
        result = {
            'checked': False,
            'is_malicious': False,
            'score': 0,
            'positives': 0,
            'total': 0,
            'details': None,
            'error': None
        }
        
        if VIRUSTOTAL_API_KEY == 'your_virustotal_api_key_here':
            result['error'] = 'API key not configured'
            return result
        
        try:
            # VirusTotal API v3
            headers = {
                'x-apikey': VIRUSTOTAL_API_KEY
            }
            
            # URL needs to be base64 encoded without padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            
            response = requests.get(
                f'https://www.virustotal.com/api/v3/urls/{url_id}',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())
                
                result['checked'] = True
                result['positives'] = malicious + suspicious
                result['total'] = total
                result['is_malicious'] = malicious > 2
                result['score'] = (malicious + suspicious * 0.5) / max(total, 1) * 100
                result['details'] = stats
            elif response.status_code == 404:
                # URL not found, submit it
                result['checked'] = True
                result['details'] = 'URL not previously scanned'
            else:
                result['error'] = f'API error: {response.status_code}'
                
        except requests.exceptions.Timeout:
            result['error'] = 'Request timeout'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_google_safe_browsing(self, url):
        """Check URL against Google Safe Browsing API"""
        result = {
            'checked': False,
            'is_malicious': False,
            'threat_types': [],
            'error': None
        }
        
        if GOOGLE_SAFE_BROWSING_API_KEY == 'your_google_api_key_here':
            result['error'] = 'API key not configured'
            return result
        
        try:
            api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}'
            
            payload = {
                'client': {
                    'clientId': 'phishing-detector',
                    'clientVersion': '1.0.0'
                },
                'threatInfo': {
                    'threatTypes': [
                        'MALWARE',
                        'SOCIAL_ENGINEERING',
                        'UNWANTED_SOFTWARE',
                        'POTENTIALLY_HARMFUL_APPLICATION'
                    ],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                matches = data.get('matches', [])
                
                result['checked'] = True
                result['is_malicious'] = len(matches) > 0
                result['threat_types'] = [m.get('threatType') for m in matches]
                
        except requests.exceptions.Timeout:
            result['error'] = 'Request timeout'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_urlhaus(self, url):
        """Check URL against URLhaus database (free, no API key required)"""
        result = {
            'checked': False,
            'is_malicious': False,
            'threat_type': None,
            'tags': [],
            'error': None
        }
        
        try:
            response = requests.post(
                f'{URLHAUS_API_URL}/url/',
                data={'url': url},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                result['checked'] = True
                
                if data.get('query_status') == 'ok':
                    result['is_malicious'] = True
                    result['threat_type'] = data.get('threat')
                    result['tags'] = data.get('tags', [])
                elif data.get('query_status') == 'no_results':
                    result['is_malicious'] = False
                    
        except requests.exceptions.Timeout:
            result['error'] = 'Request timeout'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_phishtank(self, url):
        """Check URL against PhishTank database"""
        result = {
            'checked': False,
            'is_malicious': False,
            'in_database': False,
            'verified': False,
            'error': None
        }
        
        try:
            # PhishTank API
            data = {
                'url': base64.b64encode(url.encode()).decode(),
                'format': 'json'
            }
            
            if PHISHTANK_API_KEY:
                data['app_key'] = PHISHTANK_API_KEY
            
            response = requests.post(
                'https://checkurl.phishtank.com/checkurl/',
                data=data,
                timeout=10
            )
            
            if response.status_code == 200:
                resp_data = response.json()
                results = resp_data.get('results', {})
                
                result['checked'] = True
                result['in_database'] = results.get('in_database', False)
                result['verified'] = results.get('verified', False)
                result['is_malicious'] = result['in_database'] and results.get('valid', False)
                
        except requests.exceptions.Timeout:
            result['error'] = 'Request timeout'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def get_domain_reputation(self, url):
        """Get domain reputation and age information"""
        result = {
            'domain': None,
            'age_days': None,
            'registrar': None,
            'country': None,
            'reputation_score': 50,  # Default neutral score
            'error': None
        }
        
        try:
            import whois
            parsed = urlparse(url)
            domain = parsed.netloc
            result['domain'] = domain
            
            domain_info = whois.whois(domain)
            
            if domain_info.creation_date:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                age_days = (datetime.now() - creation_date).days
                result['age_days'] = age_days
                
                # Adjust reputation based on domain age
                if age_days < 30:
                    result['reputation_score'] = 20  # Very new domain - suspicious
                elif age_days < 90:
                    result['reputation_score'] = 40  # New domain
                elif age_days < 365:
                    result['reputation_score'] = 60  # Relatively new
                else:
                    result['reputation_score'] = 80  # Established domain
            
            result['registrar'] = domain_info.registrar
            result['country'] = domain_info.country
            
        except Exception as e:
            result['error'] = str(e)
        
        return result


class ThreatScorer:
    """Calculate comprehensive threat scores"""
    
    @staticmethod
    def calculate_combined_score(ml_prediction, threat_intel, domain_reputation):
        """
        Combine ML prediction with threat intelligence for final score
        """
        weights = {
            'ml_prediction': 0.40,
            'threat_intel': 0.40,
            'domain_reputation': 0.20
        }
        
        ml_score = ml_prediction.get('prediction_score', 0)
        threat_score = threat_intel.get('threat_score', 0)
        
        # Invert reputation score (lower age = higher threat)
        reputation_score = 100 - domain_reputation.get('reputation_score', 50)
        
        combined_score = (
            ml_score * weights['ml_prediction'] +
            threat_score * weights['threat_intel'] +
            reputation_score * weights['domain_reputation']
        )
        
        return min(round(combined_score, 2), 100)


# Singleton instance
threat_intel = ThreatIntelligence()


def check_url_threat(url):
    """Quick function to check URL threats"""
    return threat_intel.check_url(url)


def get_comprehensive_analysis(url, ml_prediction):
    """
    Get comprehensive URL analysis combining ML and threat intelligence
    """
    threat_result = threat_intel.check_url(url)
    domain_rep = threat_intel.get_domain_reputation(url)
    
    combined_score = ThreatScorer.calculate_combined_score(
        ml_prediction, threat_result, domain_rep
    )
    
    return {
        'url': url,
        'ml_prediction': ml_prediction,
        'threat_intelligence': threat_result,
        'domain_reputation': domain_rep,
        'combined_threat_score': combined_score,
        'final_verdict': 'DANGEROUS' if combined_score >= 50 else 'SAFE',
        'confidence': 'high' if abs(combined_score - 50) > 30 else 'medium',
        'analyzed_at': datetime.now().isoformat()
    }
