from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import pandas as pd
import numpy as np
import joblib
import os

class ModelTrainer:
    def __init__(self, model_path='models'):
        self.model_path = model_path
        self.current_model = None
        self.current_model_name = None
        
        # Improved parameter grids
        self.param_grids = {
            'random_forest': {
                'model': RandomForestClassifier(random_state=42),
                'params': {
                    'n_estimators': [1000],  # Povećano sa 500
                    'max_depth': [30],       # Povećano sa 20
                    'min_samples_split': [2],
                    'min_samples_leaf': [1],
                    'class_weight': [{0: 1, 1: 2}]  # Daje veću težinu malicioznim URL-ovima
                }
            },
            'logistic_regression': {
                'model': LogisticRegression(random_state=42),
                'params': {
                    'C': [0.01, 0.1, 1.0],  # Dodali smo manju vrijednost za C
                    'max_iter': [5000],      # Povećali smo broj iteracija
                    'solver': ['liblinear'], # Maknuli smo 'saga' jer je sporiji
                    'class_weight': ['balanced']
                }
            }
        }
        
    def train_all_models(self, X, y):
        """Train all models using GridSearchCV"""
        results = {}
        for name, config in self.param_grids.items():
            print(f"\nTraining {name} with GridSearchCV...")
            
            # Dodali verbose za praćenje napretka
            grid_search = GridSearchCV(
                config['model'],
                config['params'],
                cv=5,
                scoring='f1_weighted',
                n_jobs=-1,
                verbose=1
            )
            
            # Dodali try-except za hvatanje upozorenja
            import warnings
            with warnings.catch_warnings():
                warnings.filterwarnings('ignore')
                grid_search.fit(X, y)
            
            # Store the best model
            self.param_grids[name]['best_model'] = grid_search.best_estimator_
            
            # Calculate cross-validation score for best model
            cv_scores = cross_val_score(
                grid_search.best_estimator_,
                X, y,
                cv=5,
                scoring='f1_weighted'
            )
            
            results[name] = {
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'best_params': grid_search.best_params_
            }
            
            print(f"Best parameters: {grid_search.best_params_}")
            print(f"Best CV score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        return results
    
    def select_best_model(self, results):
        """Select best model based on CV scores"""
        best_model_name = max(results.items(), key=lambda x: x[1]['cv_mean'])[0]
        self.current_model_name = best_model_name
        self.current_model = self.param_grids[best_model_name]['best_model']
        
        print(f"\nBest model: {best_model_name}")
        print(f"Best parameters: {results[best_model_name]['best_params']}")
        return best_model_name

    def evaluate(self, X_test, y_test):
        """Evaluate the current model"""
        if self.current_model is None:
            raise ValueError("No model selected. Train models first.")
        predictions = self.current_model.predict(X_test)
        return {
            'classification_report': classification_report(y_test, predictions),
            'confusion_matrix': confusion_matrix(y_test, predictions)
        }
    
    def save_model(self, filename):
        """Save the current model"""
        if self.current_model is None:
            raise ValueError("No model selected. Train models first.")
        if not os.path.exists(self.model_path):
            os.makedirs(self.model_path)
        joblib.dump(self.current_model, os.path.join(self.model_path, filename))
        
    def load_model(self, filename):
        """Load a trained model"""
        model_file = os.path.join(self.model_path, filename)
        if os.path.exists(model_file):
            self.model = joblib.load(model_file)
        else:
            raise FileNotFoundError(f"Model file not found: {model_file}")
