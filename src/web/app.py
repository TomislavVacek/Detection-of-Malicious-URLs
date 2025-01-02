from flask import Flask, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import datetime
import sys
import os
import numpy as np
from urllib.parse import urlparse  # Dodajemo ovaj import
import joblib  # Dodajemo import za joblib

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(project_root)

from src.features.feature_extractor import FeatureExtractor
from src.models.model_trainer import ModelTrainer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Dodajemo whitelist sigurnih domena
known_safe_domains = {
    'google.com', 'microsoft.com', 'github.com', 'wikipedia.org',
    'python.org', 'apple.com', 'amazon.com', 'facebook.com'
}

# Postavke za logging
logging.basicConfig(
    filename='url_detector.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Pojednostavljujemo inicijalizaciju Limitera
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["50 per hour", "3 per minute"],
    storage_uri="memory://"
)

# Initialize model trainer and feature extractor
trainer = ModelTrainer()
extractor = FeatureExtractor()
model_loaded = False

def load_model():
    """Function to load model only once"""
    global model_loaded
    if not model_loaded:
        try:
            model_path = os.path.join(project_root, 'models', 'best_model_random_forest.joblib')
            print(f"Loading model from: {model_path}")
            trainer.model = joblib.load(model_path)  # Promijenjen način učitavanja
            model_loaded = True
            print("Model loaded successfully!")
        except Exception as e:
            print(f"Error loading model: {str(e)}")
            sys.exit(1)

# Load model only on main thread
if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
    print("\nWeb aplikacija je pokrenuta!")
    print("Otvorite jedan od ovih linkova u browseru:")
    print("* http://localhost:5000")
    print("* http://127.0.0.1:5000")
    load_model()

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
@limiter.limit("3 per minute")
def predict():
    try:
        url = request.form['url']
        ip_address = request.remote_addr
        
        # Logiranje zahtjeva
        logging.info(f"Request from {ip_address} - URL: {url}")
        
        print(f"Processing URL: {url}")
        
        # Extract features first to avoid potential errors
        features = extractor.extract_features(url)
        feature_list = list(features.values())
        
        # Prvo provjerimo je li URL na whitelisti
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        base_domain = '.'.join(domain.split('.')[-2:])
        
        if base_domain in known_safe_domains:
            return render_template('result.html', result={
                'url': url,
                'is_malicious': False,
                'confidence': 0.95,
                'features': features,  # Dodano
                'warning': 'Known safe domain'
            })
        
        # Provjera očitih malicioznih znakova
        immediate_flags = any([
            features.get('is_shortened_url', False),
            features.get('has_typosquatting', False),
            features.get('has_number_letter_substitution', False),
            len(url) > 100,
            features.get('suspicious_word_count', 0) > 2,
            features.get('suspicious_domain', False),
            features.get('path_has_suspicious_word', False),
            features.get('has_suspicious_chars', False),
            sum(1 for word in ['admin', 'password', 'login'] if word in url.lower()) > 0
        ])
        
        if immediate_flags:
            return render_template('result.html', result={
                'url': url,
                'is_malicious': True,
                'confidence': 0.95,
                'features': features,  # Dodano
                'warning': 'Suspicious patterns detected'
            })
        
        # Model prediction ako nije očito maliciozan
        try:
            if not hasattr(trainer, 'model') or trainer.model is None:
                load_model()
            
            prediction = trainer.model.predict([feature_list])[0]
            probability = trainer.model.predict_proba([feature_list])[0]
            
            return render_template('result.html', result={
                'url': url,
                'is_malicious': bool(prediction),
                'confidence': float(max(probability)),
                'features': features,
                'warning': None
            })
            
        except Exception as e:
            logging.error(f"Model prediction error: {str(e)}")
            # Fallback na heuristički pristup ako model ne radi
            is_suspicious = any([
                features.get('suspicious_domain', False),
                features.get('has_suspicious_chars', False),
                features.get('suspicious_word_count', 0) > 1
            ])
            
            return render_template('result.html', result={
                'url': url,
                'is_malicious': is_suspicious,
                'confidence': 0.7,
                'features': features,
                'warning': 'Using heuristic detection (model unavailable)'
            })
            
    except Exception as e:
        logging.error(f"Error processing URL {url}: {str(e)}")
        return render_template('error.html', error_message=str(e))

if __name__ == '__main__':
    app.run(debug=True)
