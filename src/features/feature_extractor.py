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
            'download', 'signin', 'signup', 'paypal', 'free', 'lucky',
            'security', 'recover', 'unlock', 'authorize', 'root',
            'administrator', 'auth', 'validate', 'validation',
            'profile', 'manage', 'management', 'access', 'private',
            'dashboard', 'webscr', 'cmd', 'personal', 'update',
            'user', 'users', 'billing', 'subscribe', 'wallet'
        }
        
        self.vowels = set('aeiou')
        self.consonants = set('bcdfghjklmnpqrstvwxyz')
        self.tld_list = {'com', 'org', 'net', 'edu', 'gov', 'mil', 'info', 'biz'}
        self.suspicious_extensions = {
            '.exe', '.dll', '.bat', '.sh', '.php', '.jsp',
            '.cgi', '.scr', '.vbs', '.js', '.jar'
        }
        
        # Dodajemo nove suspicious patterns
        self.suspicious_patterns = {
            'bit.ly',          # URL shorteners
            'tinyurl.com',
            'goo.gl',
            't.co',
            'micr0s0ft',      # Typosquatting
            'micosoft',
            'mircosoft',
            'microsft',
            '0' # Zero instead of 'o'
        }

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
            'suspicious_word_count', 'has_suspicious_words',
            'suspicious_domain', 'domain_length_suspicious', 'multiple_subdomains',
            'path_has_suspicious_word', 'query_has_suspicious_word',
            'has_suspicious_chars', 'has_multiple_slashes', 'has_multiple_dots',
            'is_shortened_url', 'has_typosquatting', 'has_number_letter_substitution'
        ]
    
    def _get_basic_features(self, url):
        return {
            'url_length': len(url),
            'special_char_count': sum(url.count(char) for char in self.special_chars),
            'digit_ratio': sum(c.isdigit() for c in url) / len(url),
            'letter_ratio': sum(c.isalpha() for c in url) / len(url)
        }
    
    def _get_domain_features(self, parsed_url):
        domain = parsed_url.netloc.lower()
        parts = domain.split('.')
        
        features = {
            'domain_length': len(domain),
            'has_ip': self._has_ip(domain),
            'subdomain_count': domain.count('.'),
            'domain_digit_ratio': sum(c.isdigit() for c in domain) / len(domain) if domain else 0,
            'has_valid_tld': parts[-1].lower() in self.tld_list if parts else False,
            'domain_hyphen_count': domain.count('-'),
            'domain_token_count': len(parts),
            'longest_domain_token': max(len(token) for token in parts) if parts else 0,
            'suspicious_domain': any(word in domain.lower() for word in self.suspicious_words),
            'domain_length_suspicious': len(domain) > 30,
            'multiple_subdomains': domain.count('.') > 2
        }
        
        # Dodajemo nove provjere
        features.update({
            'is_shortened_url': any(shortener in domain for shortener in ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']),
            'has_typosquatting': self._check_typosquatting(domain),
            'has_number_letter_substitution': self._check_number_substitution(domain)
        })
        
        return features
        
    def _get_path_features(self, parsed_url):
        path = parsed_url.path.lower()
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
            'path_extension': self._has_suspicious_extension(path),
            'path_has_suspicious_word': any(word in path for word in self.suspicious_words),
            'query_has_suspicious_word': any(word in query for word in self.suspicious_words),
            'has_suspicious_chars': any(c in path for c in ['%', '\\', '..', '//']),
            'has_multiple_slashes': '//' in path,
            'has_multiple_dots': '..' in path
        }
        
        return features
    
    def _has_suspicious_extension(self, path):
        return any(path.lower().endswith(ext) for ext in self.suspicious_extensions)

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
    
    def _check_typosquatting(self, domain):
        """Check for common typosquatting patterns"""
        known_brands = ['microsoft', 'google', 'facebook', 'apple', 'amazon', 'paypal']
        # Dodajemo provjeru za točnu domenu
        if domain in ['www.google.com', 'google.com']:
            return False
        
        # Dodana stroža provjera - mora sadržavati barem 70% znakova branda
        for brand in known_brands:
            if brand in domain and domain != brand:
                similarity = sum(c in domain for c in brand) / len(brand)
                if similarity > 0.7:
                    return True
        return False
    
    def _check_number_substitution(self, domain):
        """Check for number substitutions (0 for o, 1 for l, etc)"""
        substitutions = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's'}
        # Provjeravamo samo ako domena nije potpuno brojčana
        if not domain.isdigit():
            return any(num in domain for num in substitutions.keys())
        return False
