import unittest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.features.feature_extractor import FeatureExtractor

class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor()
        
    def test_safe_url(self):
        url = "https://www.google.com"
        features = self.extractor.extract_features(url)
        self.assertFalse(features['suspicious_domain'])
        self.assertFalse(features['has_typosquatting'])
        self.assertEqual(features['domain_length'], len('www.google.com'))
        
    def test_malicious_url(self):
        url = "http://g00gle.com/admin/login.php"
        features = self.extractor.extract_features(url)
        self.assertTrue(features['has_number_letter_substitution'])
        self.assertTrue(features['path_has_suspicious_word'])
        
    def test_feature_completeness(self):
        url = "https://example.com"
        features = self.extractor.extract_features(url)
        expected_features = set(self.extractor._get_feature_names())
        self.assertEqual(set(features.keys()), expected_features)
        
    def test_shortened_url(self):
        url = "http://bit.ly/abc123"
        features = self.extractor.extract_features(url)
        self.assertTrue(features['is_shortened_url'])

if __name__ == '__main__':
    unittest.main()
