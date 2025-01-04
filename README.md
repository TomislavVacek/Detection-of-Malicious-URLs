# Detection-of-Malicious-URLs

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.0.1-green.svg)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.0+-orange.svg)

This project implements a real-time malicious URL detection system using machine learning techniques. It provides both web interface and API access for URL analysis and classification.

## Features

- Real-time URL analysis
- Machine learning-based detection
- Feature visualization
- URL check history
- Statistical analysis
- Rate limiting protection
- Whitelist for known safe domains

## Project Structure
```
Detection of malicious URLs/
│
├── data/
│   └── raw/              # Raw dataset files
│
├── models/              # Trained model files
│
├── src/
│   ├── data/           # Data loading and preprocessing
│   ├── features/       # Feature extraction
│   ├── models/         # Model training and evaluation
│   ├── visualization/  # Results visualization
│   └── train.py       # Main training script
│
├── visualizations/     # Generated plots and visualizations
│
├── requirements.txt    # Project dependencies
└── README.md          # Project documentation
```

## Features

The system analyzes URLs based on multiple characteristics:

- URL length and structure analysis
- Domain name characteristics
- Special character distribution
- SSL/TLS certificate validation
- Lexical feature analysis
- Host-based features
- Content-based features
- Character distribution (digits, letters)
- IP address presence validation
- Domain length analysis

## Setup

1. Create virtual environment:
```bash
python -m venv venv
```

2. Activate virtual environment:
```bash
# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Train the model:
```bash
python src/train.py
```

## API Documentation

Endpoint: /predict

Method: POST
Input: JSON with URL field
Returns: Prediction and confidence score

Example request:
{
    "url": "https://example.com"
}

Example response:
{
    "prediction": "safe",
    "confidence": 0.95,
    "features_analyzed": 15
}

## Results

The model achieves:
- 92% overall accuracy
- 95% precision for malicious URL detection
- 91% precision for benign URL detection


## Dataset

- Source: Combined dataset from PhishTank and legitimate URLs
- Size: 100,000 URLs (50,000 malicious, 50,000 legitimate)
- Features: 15 extracted features per URL
- Format: CSV with URL and binary labels


## Acknowledgments

- PhishTank for malicious URL dataset
- Alexa Top Sites for legitimate URL dataset
- scikit-learn community
- Flask framework team