from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import pandas as pd
import joblib
import os

class ModelTrainer:
    def __init__(self, model_path='models'):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model_path = model_path
        
    def train(self, X, y):
        """Train the model"""
        self.model.fit(X, y)
        
    def evaluate(self, X_test, y_test):
        """Evaluate the model"""
        predictions = self.model.predict(X_test)
        return {
            'classification_report': classification_report(y_test, predictions),
            'confusion_matrix': confusion_matrix(y_test, predictions)
        }
    
    def save_model(self, filename):
        """Save the trained model"""
        if not os.path.exists(self.model_path):
            os.makedirs(self.model_path)
        joblib.dump(self.model, os.path.join(self.model_path, filename))
        
    def load_model(self, filename):
        """Load a trained model"""
        model_file = os.path.join(self.model_path, filename)
        if os.path.exists(model_file):
            self.model = joblib.load(model_file)
        else:
            raise FileNotFoundError(f"Model file not found: {model_file}")
