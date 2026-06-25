"""
Advanced Analytics Module
Provides analytics, reporting, and visualization capabilities
"""

import sqlite3
import json
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import io
import csv
import os

if os.environ.get("VERCEL") == "1":
    DATABASE_PATH = '/tmp/phishing_detection.db'
else:
    DATABASE_PATH = 'phishing_detection.db'


class AnalyticsEngine:
    """Advanced analytics for phishing detection data"""
    
    def __init__(self, db_path=DATABASE_PATH):
        self.db_path = db_path
    
    def _get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def get_dashboard_stats(self):
        """Get comprehensive dashboard statistics"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        stats = {}
        
        # Total URLs checked
        cursor.execute('SELECT COUNT(*) as total FROM url_checks')
        stats['total_urls_checked'] = cursor.fetchone()['total']
        
        # Safe vs Unsafe breakdown
        cursor.execute('SELECT COUNT(*) as count FROM url_checks WHERE is_phishing = 0')
        stats['safe_urls'] = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM url_checks WHERE is_phishing = 1')
        stats['unsafe_urls'] = cursor.fetchone()['count']
        
        # Detection rate
        if stats['total_urls_checked'] > 0:
            stats['detection_rate'] = round(stats['unsafe_urls'] / stats['total_urls_checked'] * 100, 2)
        else:
            stats['detection_rate'] = 0
        
        # URLs checked today
        cursor.execute('''
            SELECT COUNT(*) as count FROM url_checks 
            WHERE DATE(checked_at) = DATE('now')
        ''')
        stats['urls_today'] = cursor.fetchone()['count']
        
        # URLs checked this week
        cursor.execute('''
            SELECT COUNT(*) as count FROM url_checks 
            WHERE checked_at >= DATE('now', '-7 days')
        ''')
        stats['urls_this_week'] = cursor.fetchone()['count']
        
        # Active users today
        cursor.execute('''
            SELECT COUNT(DISTINCT username) as count FROM url_checks 
            WHERE DATE(checked_at) = DATE('now')
        ''')
        stats['active_users_today'] = cursor.fetchone()['count']
        
        # Total users
        cursor.execute('SELECT COUNT(*) as count FROM users')
        stats['total_users'] = cursor.fetchone()['count']
        
        # Blocklist size
        cursor.execute('SELECT COUNT(*) as count FROM blocklist')
        stats['blocklist_size'] = cursor.fetchone()['count']
        
        conn.close()
        return stats
    
    def get_time_series_data(self, days=30):
        """Get URL checks over time for charting"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                DATE(checked_at) as date,
                COUNT(*) as total,
                SUM(CASE WHEN is_phishing = 1 THEN 1 ELSE 0 END) as phishing,
                SUM(CASE WHEN is_phishing = 0 THEN 1 ELSE 0 END) as safe
            FROM url_checks
            WHERE checked_at >= DATE('now', ?)
            GROUP BY DATE(checked_at)
            ORDER BY date ASC
        ''', (f'-{days} days',))
        
        data = []
        for row in cursor.fetchall():
            data.append({
                'date': row['date'],
                'total': row['total'],
                'phishing': row['phishing'],
                'safe': row['safe']
            })
        
        conn.close()
        return data
    
    def get_hourly_distribution(self, days=7):
        """Get URL checks distribution by hour of day"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                CAST(strftime('%H', checked_at) AS INTEGER) as hour,
                COUNT(*) as count
            FROM url_checks
            WHERE checked_at >= DATE('now', ?)
            GROUP BY hour
            ORDER BY hour
        ''', (f'-{days} days',))
        
        data = {i: 0 for i in range(24)}
        for row in cursor.fetchall():
            data[row['hour']] = row['count']
        
        conn.close()
        return data
    
    def get_top_phishing_domains(self, limit=20):
        """Get most frequently detected phishing domains"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT url, COUNT(*) as count
            FROM url_checks
            WHERE is_phishing = 1
            GROUP BY url
            ORDER BY count DESC
            LIMIT ?
        ''', (limit,))
        
        data = []
        for row in cursor.fetchall():
            # Extract domain from URL
            try:
                from urllib.parse import urlparse
                domain = urlparse(row['url']).netloc
            except:
                domain = row['url']
            
            data.append({
                'url': row['url'],
                'domain': domain,
                'count': row['count']
            })
        
        conn.close()
        return data
    
    def get_keyword_analysis(self):
        """Analyze common keywords in phishing URLs"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT url FROM url_checks WHERE is_phishing = 1
        ''')
        
        # Common phishing keywords to look for
        keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'update',
            'confirm', 'banking', 'paypal', 'amazon', 'apple', 'microsoft',
            'google', 'facebook', 'instagram', 'netflix', 'password',
            'credential', 'suspended', 'locked', 'alert', 'urgent'
        ]
        
        keyword_counts = {k: 0 for k in keywords}
        
        for row in cursor.fetchall():
            url_lower = row['url'].lower()
            for keyword in keywords:
                if keyword in url_lower:
                    keyword_counts[keyword] += 1
        
        # Sort by count
        sorted_keywords = sorted(
            keyword_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        conn.close()
        return dict(sorted_keywords)
    
    def get_user_leaderboard(self, limit=10):
        """Get top users by URL checks"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                username,
                COUNT(*) as total_checks,
                SUM(CASE WHEN is_phishing = 1 THEN 1 ELSE 0 END) as phishing_found
            FROM url_checks
            GROUP BY username
            ORDER BY total_checks DESC
            LIMIT ?
        ''', (limit,))
        
        data = []
        for row in cursor.fetchall():
            data.append({
                'username': row['username'],
                'total_checks': row['total_checks'],
                'phishing_found': row['phishing_found']
            })
        
        conn.close()
        return data
    
    def get_threat_heatmap_data(self, days=30):
        """Get data for threat heatmap (day of week vs hour)"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                CAST(strftime('%w', checked_at) AS INTEGER) as day_of_week,
                CAST(strftime('%H', checked_at) AS INTEGER) as hour,
                COUNT(*) as count
            FROM url_checks
            WHERE is_phishing = 1 AND checked_at >= DATE('now', ?)
            GROUP BY day_of_week, hour
        ''', (f'-{days} days',))
        
        # Initialize 7x24 grid
        heatmap = [[0 for _ in range(24)] for _ in range(7)]
        
        for row in cursor.fetchall():
            heatmap[row['day_of_week']][row['hour']] = row['count']
        
        conn.close()
        return heatmap
    
    def get_geographic_data(self):
        """Get phishing attempts by country (based on domain TLD)"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT url FROM url_checks WHERE is_phishing = 1
        ''')
        
        # Country code TLDs
        country_counts = defaultdict(int)
        
        for row in cursor.fetchall():
            try:
                from urllib.parse import urlparse
                domain = urlparse(row['url']).netloc
                tld = domain.split('.')[-1].upper()
                
                # Map common TLDs to countries
                tld_map = {
                    'RU': 'Russia', 'CN': 'China', 'BR': 'Brazil',
                    'IN': 'India', 'UK': 'UK', 'DE': 'Germany',
                    'FR': 'France', 'JP': 'Japan', 'KR': 'South Korea',
                    'COM': 'Global', 'NET': 'Global', 'ORG': 'Global',
                    'IO': 'Tech', 'XYZ': 'Generic'
                }
                
                country = tld_map.get(tld, 'Other')
                country_counts[country] += 1
            except:
                pass
        
        conn.close()
        return dict(sorted(country_counts.items(), key=lambda x: x[1], reverse=True))
    
    def generate_report_data(self, start_date=None, end_date=None):
        """Generate comprehensive report data"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        if not start_date:
            start_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        if not end_date:
            end_date = datetime.now().strftime('%Y-%m-%d')
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'period': {
                'start': start_date,
                'end': end_date
            },
            'summary': {},
            'daily_breakdown': [],
            'top_threats': [],
            'user_activity': []
        }
        
        # Summary statistics
        cursor.execute('''
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN is_phishing = 1 THEN 1 ELSE 0 END) as phishing,
                SUM(CASE WHEN is_phishing = 0 THEN 1 ELSE 0 END) as safe,
                COUNT(DISTINCT username) as unique_users
            FROM url_checks
            WHERE DATE(checked_at) BETWEEN ? AND ?
        ''', (start_date, end_date))
        
        row = cursor.fetchone()
        report['summary'] = {
            'total_checks': row['total'],
            'phishing_detected': row['phishing'],
            'safe_urls': row['safe'],
            'unique_users': row['unique_users'],
            'detection_rate': round(row['phishing'] / max(row['total'], 1) * 100, 2)
        }
        
        # Daily breakdown
        cursor.execute('''
            SELECT 
                DATE(checked_at) as date,
                COUNT(*) as total,
                SUM(CASE WHEN is_phishing = 1 THEN 1 ELSE 0 END) as phishing
            FROM url_checks
            WHERE DATE(checked_at) BETWEEN ? AND ?
            GROUP BY DATE(checked_at)
            ORDER BY date
        ''', (start_date, end_date))
        
        report['daily_breakdown'] = [dict(row) for row in cursor.fetchall()]
        
        # Top threats
        cursor.execute('''
            SELECT url, COUNT(*) as count
            FROM url_checks
            WHERE is_phishing = 1 AND DATE(checked_at) BETWEEN ? AND ?
            GROUP BY url
            ORDER BY count DESC
            LIMIT 10
        ''', (start_date, end_date))
        
        report['top_threats'] = [dict(row) for row in cursor.fetchall()]
        
        # User activity
        cursor.execute('''
            SELECT 
                username,
                COUNT(*) as checks,
                SUM(CASE WHEN is_phishing = 1 THEN 1 ELSE 0 END) as phishing_found
            FROM url_checks
            WHERE DATE(checked_at) BETWEEN ? AND ?
            GROUP BY username
            ORDER BY checks DESC
            LIMIT 20
        ''', (start_date, end_date))
        
        report['user_activity'] = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return report


class ReportGenerator:
    """Generate various report formats"""
    
    def __init__(self, analytics_engine=None):
        self.analytics = analytics_engine or AnalyticsEngine()
    
    def generate_csv_report(self, data, filename=None):
        """Generate CSV report"""
        output = io.StringIO()
        
        if isinstance(data, list) and len(data) > 0:
            writer = csv.DictWriter(output, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        
        content = output.getvalue()
        output.close()
        
        if filename:
            with open(filename, 'w') as f:
                f.write(content)
        
        return content
    
    def generate_json_report(self, start_date=None, end_date=None, filename=None):
        """Generate JSON report"""
        report = self.analytics.generate_report_data(start_date, end_date)
        
        content = json.dumps(report, indent=2, default=str)
        
        if filename:
            with open(filename, 'w') as f:
                f.write(content)
        
        return content
    
    def generate_html_report(self, start_date=None, end_date=None, filename=None):
        """Generate HTML report"""
        report = self.analytics.generate_report_data(start_date, end_date)
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Phishing Detection Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary-cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
        .card.safe {{ background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }}
        .card.danger {{ background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%); }}
        .card h3 {{ margin: 0; font-size: 2em; }}
        .card p {{ margin: 5px 0 0; opacity: 0.9; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; font-weight: bold; }}
        tr:hover {{ background: #f5f5f5; }}
        .footer {{ text-align: center; color: #888; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Phishing Detection Report</h1>
        <p><strong>Report Period:</strong> {report['period']['start']} to {report['period']['end']}</p>
        <p><strong>Generated:</strong> {report['generated_at']}</p>
        
        <div class="summary-cards">
            <div class="card">
                <h3>{report['summary']['total_checks']}</h3>
                <p>Total URLs Checked</p>
            </div>
            <div class="card danger">
                <h3>{report['summary']['phishing_detected']}</h3>
                <p>Phishing Detected</p>
            </div>
            <div class="card safe">
                <h3>{report['summary']['safe_urls']}</h3>
                <p>Safe URLs</p>
            </div>
            <div class="card">
                <h3>{report['summary']['detection_rate']}%</h3>
                <p>Detection Rate</p>
            </div>
        </div>
        
        <h2>📈 Daily Breakdown</h2>
        <table>
            <thead>
                <tr><th>Date</th><th>Total Checks</th><th>Phishing Found</th></tr>
            </thead>
            <tbody>
                {''.join(f"<tr><td>{d['date']}</td><td>{d['total']}</td><td>{d['phishing']}</td></tr>" for d in report['daily_breakdown'][-10:])}
            </tbody>
        </table>
        
        <h2>⚠️ Top Threats</h2>
        <table>
            <thead>
                <tr><th>URL</th><th>Times Detected</th></tr>
            </thead>
            <tbody>
                {''.join(f"<tr><td>{t['url'][:80]}...</td><td>{t['count']}</td></tr>" for t in report['top_threats'])}
            </tbody>
        </table>
        
        <h2>👥 User Activity</h2>
        <table>
            <thead>
                <tr><th>Username</th><th>Checks</th><th>Phishing Found</th></tr>
            </thead>
            <tbody>
                {''.join(f"<tr><td>{u['username']}</td><td>{u['checks']}</td><td>{u['phishing_found']}</td></tr>" for u in report['user_activity'])}
            </tbody>
        </table>
        
        <div class="footer">
            <p>Generated by Phishing Detection System | Confidential Report</p>
        </div>
    </div>
</body>
</html>
"""
        
        if filename:
            with open(filename, 'w') as f:
                f.write(html)
        
        return html


# Create singleton instances
analytics = AnalyticsEngine()
report_generator = ReportGenerator(analytics)


def get_dashboard_data():
    """Quick function to get dashboard data"""
    return analytics.get_dashboard_stats()


def get_chart_data():
    """Get data for dashboard charts"""
    return {
        'time_series': analytics.get_time_series_data(30),
        'hourly_distribution': analytics.get_hourly_distribution(7),
        'keywords': analytics.get_keyword_analysis(),
        'top_phishing': analytics.get_top_phishing_domains(10),
        'geographic': analytics.get_geographic_data(),
        'leaderboard': analytics.get_user_leaderboard(10)
    }
