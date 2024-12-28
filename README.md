# Detection of Malicious URLs

This project aims to detect malicious URLs using machine learning techniques. It uses Random Forest classifier to identify potentially dangerous URLs based on their characteristics.

## Project Structure
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

## Results

The model achieves:
- 92% overall accuracy
- 95% precision for malicious URL detection
- 91% precision for benign URL detection

## Features

Current features extracted from URLs:
- URL length
- Special character count
- Domain length
- IP address presence
- Character distribution (digits, letters)