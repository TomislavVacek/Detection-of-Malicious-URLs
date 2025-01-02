import unittest
import sys
import os
import numpy as np
from sklearn.datasets import make_classification

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.models.model_trainer import ModelTrainer

class TestModelTrainer(unittest.TestCase):
    def setUp(self):
        self.trainer = ModelTrainer()
        # Kreiramo sintetičke podatke za testiranje
        X, y = make_classification(n_samples=1000, n_features=37, 
                                 n_classes=2, random_state=42)
        self.X = X
        self.y = y
        
    def test_train_models(self):
        results = self.trainer.train_all_models(self.X, self.y)
        self.assertIn('random_forest', results)
        self.assertIn('logistic_regression', results)
        
    def test_model_save_load(self):
        # Prvo treniramo model
        self.trainer.train_all_models(self.X, self.y)
        # Modificiramo results dictionary da uključi sve potrebne ključeve
        results = {
            'random_forest': {
                'cv_mean': 0.9,
                'cv_std': 0.1,
                'best_params': {'n_estimators': 100}
            }
        }
        best_model = self.trainer.select_best_model(results)
        
        # Spremimo model
        test_model_path = os.path.join('models', 'test_model.joblib')
        self.trainer.save_model('test_model.joblib')
        
        # Provjerimo da li postoji
        self.assertTrue(os.path.exists(test_model_path))
        
        # Učitamo model
        new_trainer = ModelTrainer()
        new_trainer.load_model('test_model.joblib')
        
        # Obrišemo test model
        os.remove(test_model_path)

if __name__ == '__main__':
    unittest.main()
