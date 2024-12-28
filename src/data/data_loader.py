import pandas as pd
from sklearn.model_selection import train_test_split
import os

class DataLoader:
    def __init__(self, data_path):
        self.data_path = data_path
        
    def load_data(self):
        """Load the URL dataset"""
        try:
            # Check if file exists
            if not os.path.exists(self.data_path):
                print(f"\nERROR: File not found!")
                print(f"Looking for file at: {os.path.abspath(self.data_path)}")
                print(f"Current working directory: {os.getcwd()}")
                print("\nPlease ensure that:")
                print("1. The dataset file is named 'malicious_urls.csv'")
                print("2. It is located in the 'data/raw' directory")
                return None
            
            # Try to read the CSV
            df = pd.read_csv(self.data_path)
            
            # Print unique values in 'type' column to debug
            if 'type' in df.columns:
                print("\nUnique values in 'type' column:", df['type'].unique())
                # Map all variations of malicious/phishing to 1 and benign to 0
                type_mapping = {
                    'benign': 0,
                    'phishing': 1,
                    'malicious': 1,
                    'defacement': 1,
                    'malware': 1
                }
                df['label'] = df['type'].map(type_mapping)
                df = df.drop('type', axis=1)
                
            # Basic validation of the dataset
            required_columns = ['url', 'label']
            if not all(col in df.columns for col in required_columns):
                print(f"\nERROR: Dataset is missing required columns!")
                print(f"Required columns: {required_columns}")
                print(f"Found columns: {df.columns.tolist()}")
                return None
                
            print(f"\nDataset loaded successfully:")
            print(f"- Shape: {df.shape}")
            print(f"- Number of malicious URLs: {sum(df['label'] == 1)}")
            print(f"- Number of benign URLs: {sum(df['label'] == 0)}")
            return df
            
        except Exception as e:
            print(f"\nERROR while loading data:")
            print(f"- Error type: {type(e).__name__}")
            print(f"- Error message: {str(e)}")
            print(f"- File path: {os.path.abspath(self.data_path)}")
            return None
    
    def split_data(self, df, test_size=0.2, random_state=42):
        """Split data into train and test sets"""
        if isinstance(df, pd.DataFrame):
            X = df
            y = df.pop('label') if 'label' in df.columns else None
        else:
            X = df
            y = None
        return train_test_split(X, y, test_size=test_size, random_state=random_state)

if __name__ == "__main__":
    # Construct path relative to the script location
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))
    data_path = os.path.join(project_root, 'data', 'raw', 'malicious_urls.csv')
    
    print(f"Looking for dataset at: {data_path}")
    
    loader = DataLoader(data_path)
    data = loader.load_data()
    
    if data is not None:
        X_train, X_test, y_train, y_test = loader.split_data(data)
        print("Train set shape:", X_train.shape)
        print("Test set shape:", X_test.shape)