import re
from urllib.parse import urlparse
import numpy as np

class FeatureExtractor:
    def __init__(self):
        self.special_chars = ['@', '?', '!', '#', '$', '%', '^', '&', '*', '(', ')', '-', '+', '=', '[', ']', '{', '}', '|', '\\']
    
    def extract_features(self, url):
        """Extract features from a single URL"""
        features = {}
        
        # Basic features
        features['url_length'] = len(url)
        features['special_char_count'] = sum(url.count(char) for char in self.special_chars)
        
        # Domain features
        parsed_url = urlparse(url)
        features['domain_length'] = len(parsed_url.netloc)
        features['has_ip'] = self._has_ip(parsed_url.netloc)
        
        # Character distribution features
        features['digit_count'] = sum(c.isdigit() for c in url)
        features['letter_count'] = sum(c.isalpha() for c in url)
        
        return features
    
    def _has_ip(self, domain):
        """Check if domain contains an IP address"""
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(pattern, domain))
