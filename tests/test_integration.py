import unittest
import sys
import os
from urllib.parse import urlparse
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.features.feature_extractor import FeatureExtractor
from src.models.model_trainer import ModelTrainer

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor()
        self.trainer = ModelTrainer()
        
    def test_full_pipeline(self):
        # Test safe URL
        safe_url = "https://www.google.com"
        features = self.extractor.extract_features(safe_url)
        self.assertIsNotNone(features)
        self.assertFalse(features['suspicious_domain'])
        
        # Test malicious URL
        malicious_url = "http://suspicious-bank-login.com/admin/password.php"
        features = self.extractor.extract_features(malicious_url)
        self.assertIsNotNone(features)
        self.assertTrue(features['suspicious_domain'])

if __name__ == '__main__':
    unittest.main()
