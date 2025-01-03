import sqlite3
import json
from datetime import datetime

class Database:
    def __init__(self, db_file='url_checks.db'):
        self.db_file = db_file
        self.init_db()
    
    def init_db(self):
        """Initialize database with required tables"""
        with sqlite3.connect(self.db_file) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS url_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    check_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_malicious BOOLEAN,
                    confidence FLOAT,
                    features JSON,
                    ip_address TEXT,
                    status_message TEXT
                );
                
                CREATE INDEX IF NOT EXISTS idx_check_date ON url_checks(check_date);
                CREATE INDEX IF NOT EXISTS idx_url ON url_checks(url);
            ''')
    
    def add_check(self, url, is_malicious, confidence, features, ip_address=None, status_message=None):
        """Add new URL check to database"""
        with sqlite3.connect(self.db_file) as conn:
            conn.execute('''
                INSERT INTO url_checks (url, is_malicious, confidence, features, ip_address, status_message)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (url, is_malicious, confidence, json.dumps(features), ip_address, status_message))
    
    def get_recent_checks(self, limit=50):
        """Get most recent URL checks"""
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            return conn.execute('''
                SELECT * FROM url_checks 
                ORDER BY check_date DESC 
                LIMIT ?
            ''', (limit,)).fetchall()
