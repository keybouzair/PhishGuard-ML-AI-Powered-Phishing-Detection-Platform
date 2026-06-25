"""
Webhook and SIEM Integration Module
Supports integration with external systems like Slack, Teams, and SIEM platforms
"""

import requests
import json
import hashlib
import hmac
import time
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional
import os
import urllib.parse
import socket
from queue import Queue
from threading import Thread

if os.environ.get("VERCEL") == "1":
    DATABASE_PATH = '/tmp/phishing_detection.db'
else:
    DATABASE_PATH = 'phishing_detection.db'


class WebhookManager:
    """Manage and trigger webhooks for events"""
    
    def __init__(self, db_path=DATABASE_PATH):
        self.db_path = db_path
        self._init_table()
        self.event_queue = Queue()
        self._start_worker()
    
    def _init_table(self):
        """Initialize webhooks table"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS webhooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                secret TEXT,
                events TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                retry_count INTEGER DEFAULT 3,
                last_triggered TIMESTAMP,
                failure_count INTEGER DEFAULT 0,
                created_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS webhook_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                webhook_id INTEGER,
                event_type TEXT,
                payload TEXT,
                response_code INTEGER,
                response_body TEXT,
                success INTEGER,
                triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def _start_worker(self):
        """Start background worker for async webhook delivery"""
        def worker():
            while True:
                try:
                    event = self.event_queue.get()
                    if event is None:
                        break
                    self._process_event(event)
                except Exception as e:
                    print(f"Webhook worker error: {e}")
        
        thread = Thread(target=worker, daemon=True)
        thread.start()
    
    def register_webhook(self, name: str, url: str, events: List[str],
                        secret: str = None, created_by: str = 'system') -> Dict:
        """
        Register a new webhook
        
        Args:
            name: Webhook name
            url: Webhook URL
            events: List of events to subscribe to
            secret: Optional secret for signing payloads
            created_by: User who created the webhook
        
        Returns:
            Dictionary with webhook info
        """
        # C-33: Validate URL scheme and safety against SSRF
        from services.visual_analysis import _is_safe_target
        if not url or not (url.startswith('http://') or url.startswith('https://')):
            raise ValueError("Invalid URL scheme. Only http and https are allowed.")
        if not _is_safe_target(url):
            raise ValueError("Webhook URL points to an unsafe or internal address.")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO webhooks (name, url, secret, events, created_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, url, secret, json.dumps(events), created_by))
            webhook_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return {
                'id': webhook_id,
                'name': name,
                'url': url,
                'events': events,
                'is_active': True
            }
        except Exception as e:
            return {'error': str(e)}
    
    def trigger_event(self, event_type: str, payload: Dict):
        """Trigger an event (async)"""
        self.event_queue.put({
            'event_type': event_type,
            'payload': payload,
            'timestamp': datetime.now().isoformat()
        })
    
    def _process_event(self, event: Dict):
        """Process and deliver event to webhooks"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get webhooks subscribed to this event
        cursor.execute('''
            SELECT id, url, secret, retry_count, events FROM webhooks 
            WHERE is_active = 1
        ''')
        
        webhooks = cursor.fetchall()
        
        for webhook in webhooks:
            webhook_id, url, secret, retry_count, events_str = webhook
            
            events = json.loads(events_str)
            
            if event['event_type'] not in events and '*' not in events:
                continue
            
            # Prepare payload
            payload = {
                'event': event['event_type'],
                'timestamp': event['timestamp'],
                'data': event['payload']
            }
            
            # Sign payload if secret exists
            headers = {'Content-Type': 'application/json'}
            if secret:
                signature = hmac.new(
                    secret.encode(),
                    json.dumps(payload).encode(),
                    hashlib.sha256
                ).hexdigest()
                headers['X-Webhook-Signature'] = f'sha256={signature}'
            
            # Send webhook with retries
            success = False
            response_code = None
            response_body = None
            
            for attempt in range(retry_count):
                try:
                    response = requests.post(
                        url,
                        json=payload,
                        headers=headers,
                        timeout=10
                    )
                    response_code = response.status_code
                    response_body = response.text[:500]
                    
                    if response.status_code < 400:
                        success = True
                        break
                except Exception as e:
                    response_body = str(e)
                
                time.sleep(2 ** attempt)  # Exponential backoff
            
            # Log the attempt
            cursor.execute('''
                INSERT INTO webhook_logs 
                (webhook_id, event_type, payload, response_code, response_body, success)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (webhook_id, event['event_type'], json.dumps(payload),
                  response_code, response_body, 1 if success else 0))
            
            # Update webhook stats
            if success:
                cursor.execute('''
                    UPDATE webhooks SET last_triggered = ?, failure_count = 0 
                    WHERE id = ?
                ''', (datetime.now(), webhook_id))
            else:
                cursor.execute('''
                    UPDATE webhooks SET failure_count = failure_count + 1 
                    WHERE id = ?
                ''', (webhook_id,))
        
        conn.commit()
        conn.close()
    
    def get_webhooks(self) -> List[Dict]:
        """Get all webhooks"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM webhooks')
        results = cursor.fetchall()
        conn.close()
        
        return [
            {
                'id': r[0], 'name': r[1], 'url': r[2],
                'events': json.loads(r[4]), 'is_active': bool(r[5]),
                'last_triggered': r[7], 'failure_count': r[8]
            }
            for r in results
        ]
    
    def delete_webhook(self, webhook_id: int) -> bool:
        """Delete a webhook"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM webhooks WHERE id = ?', (webhook_id,))
            cursor.execute('DELETE FROM webhook_logs WHERE webhook_id = ?', (webhook_id,))
            conn.commit()
            conn.close()
            return True
        except:
            return False


class SlackIntegration:
    """Slack integration for alerts and notifications"""
    
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url or os.environ.get('SLACK_WEBHOOK_URL')
    
    def send_alert(self, title: str, message: str, severity: str = 'warning',
                   fields: Dict = None, url: str = None) -> bool:
        """
        Send alert to Slack
        
        Args:
            title: Alert title
            message: Alert message
            severity: 'info', 'warning', 'critical'
            fields: Additional fields to display
            url: Optional URL that triggered the alert
        """
        if not self.webhook_url:
            return False
        
        colors = {
            'info': '#36a64f',
            'warning': '#ff9800',
            'critical': '#dc3545'
        }
        
        emojis = {
            'info': '✅',
            'warning': '⚠️',
            'critical': '🚨'
        }
        
        attachment = {
            'color': colors.get(severity, '#36a64f'),
            'title': f"{emojis.get(severity, '📢')} {title}",
            'text': message,
            'ts': int(time.time()),
            'fields': []
        }
        
        if url:
            attachment['fields'].append({
                'title': 'URL',
                'value': f'`{url}`',
                'short': False
            })
        
        if fields:
            for key, value in fields.items():
                attachment['fields'].append({
                    'title': key,
                    'value': str(value),
                    'short': True
                })
        
        payload = {
            'attachments': [attachment]
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            return response.status_code == 200
        except:
            return False
    
    def send_phishing_alert(self, url: str, threat_score: float,
                           details: Dict = None) -> bool:
        """Send phishing detection alert"""
        severity = 'critical' if threat_score >= 70 else 'warning'
        
        return self.send_alert(
            title='Phishing URL Detected',
            message=f'A potentially malicious URL has been detected with a threat score of {threat_score:.1f}%',
            severity=severity,
            fields={
                'Threat Score': f'{threat_score:.1f}%',
                'Detection Time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                **(details or {})
            },
            url=url
        )
    
    def send_daily_summary(self, stats: Dict) -> bool:
        """Send daily summary to Slack"""
        message = (
            f"*Daily Security Summary - {datetime.now().strftime('%Y-%m-%d')}*\n\n"
            f"• URLs Checked: {stats.get('urls_today', 0)}\n"
            f"• Phishing Detected: {stats.get('phishing_today', 0)}\n"
            f"• Active Users: {stats.get('active_users', 0)}\n"
            f"• Detection Rate: {stats.get('detection_rate', 0):.1f}%"
        )
        
        return self.send_alert(
            title='Daily Security Report',
            message=message,
            severity='info',
            fields=stats
        )


class TeamsIntegration:
    """Microsoft Teams integration"""
    
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url or os.environ.get('TEAMS_WEBHOOK_URL')
    
    def send_alert(self, title: str, message: str, severity: str = 'warning',
                   facts: Dict = None, url: str = None) -> bool:
        """Send alert to Microsoft Teams"""
        if not self.webhook_url:
            return False
        
        colors = {
            'info': '00ff00',
            'warning': 'ffaa00',
            'critical': 'ff0000'
        }
        
        card = {
            '@type': 'MessageCard',
            '@context': 'http://schema.org/extensions',
            'themeColor': colors.get(severity, 'ffaa00'),
            'summary': title,
            'sections': [{
                'activityTitle': title,
                'activitySubtitle': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'activityImage': '',
                'facts': [],
                'markdown': True,
                'text': message
            }]
        }
        
        if url:
            card['sections'][0]['facts'].append({
                'name': 'URL',
                'value': url
            })
        
        if facts:
            for key, value in facts.items():
                card['sections'][0]['facts'].append({
                    'name': key,
                    'value': str(value)
                })
        
        try:
            response = requests.post(
                self.webhook_url,
                json=card,
                timeout=10
            )
            return response.status_code == 200
        except:
            return False
    
    def send_phishing_alert(self, url: str, threat_score: float,
                           details: Dict = None) -> bool:
        """Send phishing detection alert"""
        severity = 'critical' if threat_score >= 70 else 'warning'
        
        return self.send_alert(
            title='🚨 Phishing URL Detected',
            message=f'A potentially malicious URL has been detected.',
            severity=severity,
            facts={
                'Threat Score': f'{threat_score:.1f}%',
                'Detection Time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                **(details or {})
            },
            url=url
        )


class SIEMConnector:
    """Connect to SIEM platforms (Splunk, ELK, etc.)"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.splunk_url = self.config.get('splunk_url') or os.environ.get('SPLUNK_HEC_URL')
        self.splunk_token = self.config.get('splunk_token') or os.environ.get('SPLUNK_HEC_TOKEN')
        self.elastic_url = self.config.get('elastic_url') or os.environ.get('ELASTIC_URL')
        self.elastic_api_key = self.config.get('elastic_api_key') or os.environ.get('ELASTIC_API_KEY')
    
    def send_to_splunk(self, event_type: str, data: Dict) -> bool:
        """Send event to Splunk via HTTP Event Collector"""
        if not self.splunk_url or not self.splunk_token:
            return False
        
        payload = {
            'event': {
                'type': event_type,
                'source': 'phishing_detector',
                'timestamp': datetime.now().isoformat(),
                **data
            },
            'sourcetype': 'phishing_detection',
            'source': 'phishing_detector'
        }
        
        try:
            response = requests.post(
                self.splunk_url,
                json=payload,
                headers={
                    'Authorization': f'Splunk {self.splunk_token}',
                    'Content-Type': 'application/json'
                },
                timeout=10
            )
            return response.status_code == 200
        except:
            return False
    
    def send_to_elastic(self, index: str, event_type: str, data: Dict) -> bool:
        """Send event to Elasticsearch"""
        if not self.elastic_url:
            return False
        
        document = {
            '@timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'source': 'phishing_detector',
            **data
        }
        
        headers = {'Content-Type': 'application/json'}
        if self.elastic_api_key:
            headers['Authorization'] = f'ApiKey {self.elastic_api_key}'
        
        try:
            response = requests.post(
                f'{self.elastic_url}/{index}/_doc',
                json=document,
                headers=headers,
                timeout=10
            )
            return response.status_code in [200, 201]
        except:
            return False
    
    def log_phishing_event(self, url: str, threat_score: float,
                          prediction: Dict, user: str = None) -> Dict:
        """Log phishing detection event to all configured SIEMs"""
        event_data = {
            'url': url,
            'threat_score': threat_score,
            'is_phishing': threat_score >= 50,
            'user': user,
            'prediction_details': prediction
        }
        
        results = {
            'splunk': self.send_to_splunk('phishing_detection', event_data),
            'elastic': self.send_to_elastic('phishing-events', 'detection', event_data)
        }
        
        return results


class ActiveDefenseAgent:
    """Agentic Automated Response Engine for Active Defense"""
    
    def __init__(self):
        self.action_queue = Queue()
        self._start_worker()
        
    def _start_worker(self):
        """Start async background worker for defense actions"""
        def worker():
            while True:
                try:
                    action = self.action_queue.get()
                    if action is None:
                        break
                    self._process_defense_action(action)
                except Exception as e:
                    print(f"ActiveDefense worker error: {e}")
        
        thread = Thread(target=worker, daemon=True)
        thread.start()
        
    def _extract_domain(self, url: str) -> str:
        """Extract the root domain from a full URL using tldextract (B-18)."""
        try:
            import tldextract
            ext = tldextract.extract(url)
            if ext.registered_domain:
                return ext.registered_domain
            return ext.domain
        except Exception:
            try:
                parsed = urllib.parse.urlparse(url)
                domain = parsed.netloc or parsed.path
                domain = domain.split(':')[0]
                return domain
            except Exception:
                return url

    def _perform_whois_lookup(self, domain: str) -> Dict[str, str]:
        """Simulate a WHOIS lookup to find the abuse contact."""
        try:
             # In a production environment, use python-whois or a WHOIS API
             # This is a mock implementation for demonstration
             return {
                 "registrar": "Example Registrar LLC",
                 "abuse_email": f"abuse@{domain}",
                 "hosting_provider": "Cloud Host Provider"
             }
        except Exception as e:
            return {"error": str(e)}
            
    def _generate_takedown_email(self, url: str, domain: str, whois_info: Dict, details: Dict) -> str:
        """Use an LLM or template to generate a structured DMCA/Abuse takedown email."""
        # Simulated LLM generation
        score = details.get('threat_score', 99)
        template = f"""
URGENT: Notice of Malicious Activity / Phishing on your network

To the Abuse Team at {whois_info.get('registrar', 'Registrar')}:

This is an automated notice from the Phishing Defense Engine. 
We have detected with a high degree of confidence ({score}%) that the following URL is actively dropping malware or conducting a phishing campaign:

Malicious URL: {url}
Root Domain: {domain}

Please investigate this asset immediately and suspend the account to prevent further harm to end users.

Thank you,
Automated Security Operations Center
        """
        return template.strip()
        
    def _trigger_firewall_block(self, domain: str) -> bool:
        """Simulate API calls to Cloudflare Zero Trust / DNS sinkholes."""
        # In production: requests.post('https://api.cloudflare.com/client/v4/accounts/xxx/gateway/rules...')
        print(f"[ACTIVE DEFENSE] 🛡️ Simulated Cloudflare / Pi-hole block rule applied for domain: {domain}")
        return True

    def _process_defense_action(self, action: Dict):
        """Process the agentic workflow for a critical threat."""
        url = action.get('url', '')
        details = action.get('details', {})
        
        domain = self._extract_domain(url)
        print(f"[ACTIVE DEFENSE] 🤖 Initiating automated takedown workflow for {domain}")
        
        # 1. WHOIS Lookup
        whois_data = self._perform_whois_lookup(domain)
        
        # 2. Generate Takedown Draft
        abuse_email = whois_data.get('abuse_email', 'abuse@registrar.com')
        draft = self._generate_takedown_email(url, domain, whois_data, details)
        
        print(f"[ACTIVE DEFENSE] 📧 Generated abuse request for {abuse_email}:\n---\n{draft}\n---")
        
        # 3. Apply Firewall Blocking
        self._trigger_firewall_block(domain)
        
        # Log resolution
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            # If a table for active defense logs existed, we'd log it here.
            # Using activity log instead.
            cursor.execute('''
                INSERT INTO activity_log (username, action, details, ip_address)
                VALUES (?, ?, ?, ?)
            ''', ('system_agent', 'Auto Takedown Triggered', f"Auto blocked {domain} and drafted abuse email.", "127.0.0.1"))
            conn.commit()
            conn.close()
        except:
            pass

    def take_action_if_critical(self, url: str, threat_score: float, details: Dict = None):
        """Entrypoint for the automated response agent. Queues action if score > 90."""
        if threat_score > 90:
             self.action_queue.put({
                 'url': url,
                 'threat_score': threat_score,
                 'details': details or {},
                 'timestamp': datetime.now().isoformat()
             })

class EventType:
    """Event types for webhooks and integrations"""
    PHISHING_DETECTED = 'phishing.detected'
    URL_CHECKED = 'url.checked'
    USER_LOGIN = 'user.login'
    USER_LOGOUT = 'user.logout'
    USER_CREATED = 'user.created'
    BLOCKLIST_ADDED = 'blocklist.added'
    BLOCKLIST_REMOVED = 'blocklist.removed'
    THREAT_CRITICAL = 'threat.critical'
    DAILY_REPORT = 'report.daily'


# Create singleton instances
webhook_manager = WebhookManager()
slack = SlackIntegration()
teams = TeamsIntegration()
siem = SIEMConnector()
defense_agent = ActiveDefenseAgent()


def notify_phishing_detection(url: str, threat_score: float, 
                             details: Dict = None, user: str = None):
    """Send phishing detection notifications to all channels"""
    event_data = {
        'url': url,
        'threat_score': threat_score,
        'user': user,
        'details': details
    }
    
    # Trigger webhook
    webhook_manager.trigger_event(EventType.PHISHING_DETECTED, event_data)
    
    # Send to Slack if critical
    if threat_score >= 70:
        slack.send_phishing_alert(url, threat_score, details)
        teams.send_phishing_alert(url, threat_score, details)
    
    # Trigger Autonomous Defense Actions
    defense_agent.take_action_if_critical(url, threat_score, details)
    
    # Log to SIEM
    siem.log_phishing_event(url, threat_score, details or {}, user)
