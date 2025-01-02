import unittest
from src.web.app import app

class TestFlaskApp(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        
    def test_home_page(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        
    def test_predict_endpoint(self):
        response = self.client.post('/predict', data={
            'url': 'https://www.google.com'
        })
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()
