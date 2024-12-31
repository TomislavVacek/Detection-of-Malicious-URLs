import re
from urllib.parse import urlparse
import numpy as np  # Ispravljeno iz "import numpy np"
from collections import Counter
import math
import pandas as pd

class FeatureExtractor:
    def __init__(self):
        self.special_chars = ['@', '?', '!', '#', '$', '%', '^', '&', '*', '(', ')', '-', '+', '=', '[', ']', '{', '}', '|', '\\']
        
        # Converted to set for better performance
        self.suspicious_words = {
            'login', 'bank', 'account', 'verify', 'secure', 'update',
            'payment', 'password', 'credential', 'confirm',
            'redirect', 'admin', 'backup', 'include', 'tmp', 'cgi-bin',
            'download', 'signin', 'signup', 'paypal', 'free', 'lucky'
        }
        
        self.vowels = set('aeiou')
        self.consonants = set('bcdfghjklmnpqrstvwxyz')
        self.tld_list = {'com', 'org', 'net', 'edu', 'gov', 'mil', 'info', 'biz'}

    def extract_features(self, url):
        """Extract features from a single URL"""
        try:
            features = {}
            parsed_url = urlparse(url)
            
            # Basic features
            features.update(self._get_basic_features(url))
            features.update(self._get_domain_features(parsed_url))
            features.update(self._get_path_features(parsed_url))
            features.update(self._get_char_distribution(url))
            features.update(self._get_entropy_features(url))
            features.update(self._get_suspicious_word_features(url.lower()))
            
            # Ensure no NaN values
            features = {k: 0 if pd.isna(v) else v for k, v in features.items()}
            
            return features
        except Exception as e:
            print(f"Error processing URL: {url}")
            print(f"Error: {str(e)}")
            # Return default values in case of error
            return {k: 0 for k in self._get_feature_names()}
            
    def _get_feature_names(self):
        """Get list of all feature names"""
        return [
            'url_length', 'special_char_count', 'digit_ratio', 'letter_ratio',
            'domain_length', 'has_ip', 'subdomain_count', 'domain_digit_ratio',
            'has_valid_tld', 'domain_hyphen_count', 'domain_token_count',
            'longest_domain_token', 'path_length', 'path_depth', 'has_query',
            'query_length', 'fragment_length', 'path_token_count',
            'query_param_count', 'path_extension', 'vowel_ratio',
            'consonant_ratio', 'uppercase_ratio', 'url_entropy',
            'suspicious_word_count', 'has_suspicious_words'
        ]
    
    def _get_basic_features(self, url):
        return {
            'url_length': len(url),
            'special_char_count': sum(url.count(char) for char in self.special_chars),
            'digit_ratio': sum(c.isdigit() for c in url) / len(url),
            'letter_ratio': sum(c.isalpha() for c in url) / len(url)
        }
    
    def _get_domain_features(self, parsed_url):
        domain = parsed_url.netloc
        parts = domain.split('.')
        
        features = {
            'domain_length': len(domain),
            'has_ip': self._has_ip(domain),
            'subdomain_count': domain.count('.'),
            'domain_digit_ratio': sum(c.isdigit() for c in domain) / len(domain) if domain else 0,
            'has_valid_tld': parts[-1].lower() in self.tld_list if parts else False,
            'domain_hyphen_count': domain.count('-'),
            'domain_token_count': len(parts),
            'longest_domain_token': max(len(token) for token in parts) if parts else 0
        }
        
        return features
        
    def _get_path_features(self, parsed_url):
        path = parsed_url.path
        query = parsed_url.query
        fragment = parsed_url.fragment
        
        features = {
            'path_length': len(path),
            'path_depth': path.count('/'),
            'has_query': len(query) > 0,
            'query_length': len(query),
            'fragment_length': len(fragment),
            'path_token_count': len([x for x in path.split('/') if x]),
            'query_param_count': len(query.split('&')) if query else 0,
            'path_extension': self._has_suspicious_extension(path)
        }
        
        return features
    
    def _has_suspicious_extension(self, path):
        suspicious_extensions = {'.exe', '.dll', '.bat', '.sh', '.php', '.jsp'}
        return any(path.lower().endswith(ext) for ext in suspicious_extensions)

    def _get_char_distribution(self, url):
        return {
            'vowel_ratio': sum(c.lower() in self.vowels for c in url) / len(url),
            'consonant_ratio': sum(c.lower() in self.consonants for c in url) / len(url),
            'uppercase_ratio': sum(c.isupper() for c in url) / len(url)
        }
    
    def _get_entropy_features(self, url):
        char_counts = Counter(url)
        entropy = self._calculate_entropy(char_counts, len(url))
        return {
            'url_entropy': entropy
        }
    
    def _get_suspicious_word_features(self, url):
        return {
            'suspicious_word_count': sum(word in url for word in self.suspicious_words),
            'has_suspicious_words': any(word in url for word in self.suspicious_words)
        }
    
    def _calculate_entropy(self, char_counts, total_length):
        entropy = 0
        for count in char_counts.values():
            prob = count / total_length
            entropy -= prob * math.log2(prob)
        return entropy
    
    def _has_ip(self, domain):
        """Check if domain contains an IP address"""
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(pattern, domain))
    
    def _get_default_features(self):
        """Return default feature values when URL processing fails"""
        return {name: 0 for name in self._get_feature_names()}
