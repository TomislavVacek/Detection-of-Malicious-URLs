from flask import Flask, render_template, request, jsonify
import sys
import os
import numpy as np  # Dodajemo numpy import

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(project_root)

from src.features.feature_extractor import FeatureExtractor
from src.models.model_trainer import ModelTrainer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Initialize model trainer and feature extractor
trainer = ModelTrainer()
extractor = FeatureExtractor()

# Load the trained model
try:
    model_path = os.path.join(project_root, 'models', 'best_model_random_forest.joblib')
    print(f"Loading model from: {model_path}")
    trainer.load_model(model_path)
    print("Model loaded successfully!")
except Exception as e:
    print(f"Error loading model: {str(e)}")
    print("Please ensure you have trained the model first by running: python src/train.py")
    sys.exit(1)

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        url = request.form['url']
        print(f"Processing URL: {url}")
        
        # Extract features
        features = extractor.extract_features(url)
        feature_list = list(features.values())
        
        # Dodajemo dodatnu provjeru za očite znakove malicioznosti
        obvious_malicious = (
            features.get('suspicious_domain', False) or
            features.get('path_has_suspicious_word', False) or
            features.get('has_suspicious_chars', False) or
            sum(1 for word in ['admin', 'password', 'login'] if word in url.lower()) > 0
        )
        
        # Make prediction
        if trainer.model is None:
            raise ValueError("Model not loaded")
            
        prediction = trainer.model.predict([feature_list])[0]
        probability = trainer.model.predict_proba([feature_list])[0]
        
        # Ako imamo očite znakove malicioznosti, overrideamo predikciju
        if obvious_malicious:
            prediction = 1
            probability = np.array([0.1, 0.9])  # Povećavamo sigurnost za maliciozne
        
        result = {
            'url': url,
            'is_malicious': bool(prediction),
            'confidence': float(max(probability)),
            'features': features,
            'obvious_signs': obvious_malicious
        }
        
        return render_template('result.html', result=result)
        
    except Exception as e:
        print(f"Error in prediction: {str(e)}")
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
