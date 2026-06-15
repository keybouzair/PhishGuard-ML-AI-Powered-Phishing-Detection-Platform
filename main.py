from simple_classifier import predict_url
import signal

# Set timeout for network requests
def timeout_handler(signum, frame):
    raise TimeoutError("Operation timed out")

def predict(url):
    # Set a 5-second timeout for URL analysis
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(5)
    
    try:
        result = predict_url(url)
    except TimeoutError:
        print(f"Timeout while processing {url}")
        return {
            'prediction_label': 1,  # Default to phishing on timeout
            'prediction_score': 0,
        }
    finally:
        signal.alarm(0)  # Cancel the alarm

    prediction = 1 if result.get('is_phishing') else 0
    probability = float(result.get('prediction_score', 0)) / 100.0

    return {
        'prediction_label': prediction,
        'prediction_score': probability * 100,
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