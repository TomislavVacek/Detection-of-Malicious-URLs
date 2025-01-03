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
from collections import Counter
from datetime import datetime, timedelta
import sqlite3  # Dodajemo SQLite import na početak datoteke

# Promijenite import u:
import os
import sys
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(project_root)
from src.db.database import Database
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

# Modificiramo inicijalizaciju Limitera
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://"
)

# Initialize model trainer and feature extractor
trainer = ModelTrainer()
extractor = FeatureExtractor()
model_loaded = False

# Initialize database
db = Database()

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

# Samo predict ruta ima limit
@app.route('/predict', methods=['POST'])
@limiter.limit("3 per minute")  # Limit samo na predict endpoint
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
        
        if (base_domain in known_safe_domains):
            # Dodaj u bazu
            db.add_check(url, False, 0.95, features, ip_address, "Known safe domain")
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
            # Dodaj u bazu
            db.add_check(url, True, 0.95, features, ip_address, "Suspicious patterns detected")
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
            
            # Nakon predikcije modela
            db.add_check(url, bool(prediction), float(max(probability)), features, ip_address)
            
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

def get_most_common_domains(limit=10):
    """Get most common domains from log file"""
    domains = []
    with open('url_detector.log', 'r') as f:
        for line in f:
            if 'URL:' in line:
                try:
                    url = line.split('URL:')[1].strip()
                    domain = urlparse(url).netloc
                    domains.append(domain)
                except Exception as e:
                    logging.error(f"Error parsing URL from log: {str(e)}")
    
    domain_counts = Counter(domains)
    most_common = domain_counts.most_common(limit)
    return {
        'domain_names': [d[0] for d in most_common],
        'domain_counts': [d[1] for d in most_common]
    }

def get_daily_stats():
    """Get daily statistics from log file"""
    dates = []
    malicious = []
    
    with open('url_detector.log', 'r') as f:
        for line in f:
            try:
                date_str = line.split(' - ')[0]
                date = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S,%f').date()
                is_malicious = 'Malicious' in line
                
                dates.append(date.strftime('%Y-%m-%d'))
                malicious.append(1 if is_malicious else 0)
            except Exception as e:
                logging.error(f"Error parsing log line: {str(e)}")
    
    return {
        'dates': list(set(dates)),
        'daily_malicious': malicious
    }

@app.route('/stats', methods=['GET'])
def stats():
    try:
        # Dohvaćamo statistiku direktno iz baze
        with sqlite3.connect(db.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Dohvaćamo ukupne brojeve
            stats = cursor.execute('''
                SELECT 
                    COUNT(*) as total_checks,
                    SUM(CASE WHEN is_malicious THEN 1 ELSE 0 END) as malicious_count,
                    SUM(CASE WHEN NOT is_malicious THEN 1 ELSE 0 END) as safe_count
                FROM url_checks
            ''').fetchone()
            
            # Dohvaćamo najčešće domene
            domains = cursor.execute('''
                SELECT url, COUNT(*) as count 
                FROM url_checks 
                GROUP BY url 
                ORDER BY count DESC 
                LIMIT 10
            ''').fetchall()
            
            # Dohvaćamo dnevnu statistiku
            daily = cursor.execute('''
                SELECT 
                    date(check_date) as check_day,
                    COUNT(CASE WHEN is_malicious THEN 1 END) as malicious_count
                FROM url_checks 
                GROUP BY date(check_date)
                ORDER BY check_day
            ''').fetchall()
            
        stats_data = {
            'total_checks': stats['total_checks'],
            'malicious_detected': stats['malicious_count'] or 0,  # Dodajemo or 0 za slučaj NULL
            'safe_urls': stats['safe_count'] or 0,  # Dodajemo or 0 za slučaj NULL
            'domain_names': [d['url'] for d in domains],
            'domain_counts': [d['count'] for d in domains],
            'dates': [d['check_day'] for d in daily],
            'daily_malicious': [d['malicious_count'] or 0 for d in daily]  # Dodajemo or 0
        }
        
        return render_template('stats.html', stats=stats_data)
        
    except Exception as e:
        logging.error(f"Error generating stats: {str(e)}")
        return render_template('error.html', error_message=str(e))  # Pokazujemo stvarnu grešku

@app.route('/history', methods=['GET'])
def history():
    recent_checks = db.get_recent_checks()
    return render_template('history.html', checks=recent_checks)

if __name__ == '__main__':
    app.run(debug=True)
