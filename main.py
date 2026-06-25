import concurrent.futures
from simple_classifier import predict_url
from app import analyze_url_risks

def predict(url):
    # B-25: Set a 5-second timeout using ThreadPoolExecutor to prevent Windows SIGALRM breakage
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(predict_url, url)
        try:
            result = future.result(timeout=5)
            prediction = 1 if result.get('is_phishing') else 0
            probability = float(result.get('prediction_score', 0)) / 100.0
            return {
                'prediction_label': prediction,
                'prediction_score': probability * 100,
            }
        except concurrent.futures.TimeoutError:
            print(f"Timeout while processing {url}")
            # Fall back to heuristic risk analysis instead of blindly labeling as phishing
            try:
                risk_analysis = analyze_url_risks(url)
                is_suspicious = risk_analysis['risk_score'] >= 30
                return {
                    'prediction_label': 1 if is_suspicious else 0,
                    'prediction_score': min(risk_analysis['risk_score'] + 20, 100) if is_suspicious else max(100 - risk_analysis['risk_score'], 10),
                    'degraded': True,
                    'note': 'Timeout fallback to heuristic'
                }
            except Exception:
                return {
                    'prediction_label': 0,
                    'prediction_score': 50,
                    'degraded': True
                }

if __name__ == "__main__": 
    phishing_url_1 = 'https://bafybeifqd2yktzvwjw5g42l2ghvxsxn76khhsgqpkaqfdhnqf3kiuiegw4.ipfs.dweb.link/'
    phishing_url_2 = 'http://about-ads-microsoft-com.o365.frc.skyfencenet.com'
    real_url_1 = 'https://chat.openai.com'
    real_url_2 = 'https://github.com/'
    
    print(f"Testing {phishing_url_1}...")
    print(predict(phishing_url_1))
    print(f"\nTesting {phishing_url_2}...")
    print(predict(phishing_url_2))
    print(f"\nTesting {real_url_1}...")
    print(predict(real_url_1))
    print(f"\nTesting {real_url_2}...")
    print(predict(real_url_2))