from data.data_loader import DataLoader
from features.feature_extractor import FeatureExtractor
from models.model_trainer import ModelTrainer
from visualization.visualizer import ResultVisualizer
from tqdm import tqdm
import pandas as pd
import os
from sklearn.utils import resample
from sklearn.model_selection import train_test_split
import warnings

def create_feature_matrix(urls):
    """Create feature matrix from URLs"""
    extractor = FeatureExtractor()
    features = []
    
    print("\nExtracting features...")
    for url in tqdm(urls, desc="Processing URLs"):
        try:
            features.append(extractor.extract_features(url))
        except Exception as e:
            # U slučaju greške, dodaj default vrijednosti
            features.append(extractor._get_default_features())
    
    return pd.DataFrame(features)

def balance_dataset(df):
    """Balance dataset using undersampling but maintain reasonable size"""
    df_majority = df[df['label'] == 0]
    df_minority = df[df['label'] == 1]
    
    # Uzimamo veći uzorak - 75% većinske klase
    target_size = int(len(df_majority) * 0.75)
    
    # Downsample majority class
    df_majority_downsampled = resample(
        df_majority,
        replace=False,
        n_samples=target_size,
        random_state=42
    )
    
    # Upsample minority class
    df_minority_upsampled = resample(
        df_minority,
        replace=True,
        n_samples=target_size,
        random_state=42
    )
    
    # Combine and shuffle
    balanced_df = pd.concat([df_majority_downsampled, df_minority_upsampled])
    balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    return balanced_df

def main():
    # Ignore convergence warnings
    warnings.filterwarnings('ignore', category=UserWarning)
    
    # Setup paths
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    data_path = os.path.join(project_root, 'data', 'raw', 'malicious_urls.csv')
    
    # Povećajte veličinu uzorka na 100,000
    sample_size = 100000  # Bilo je 50000
    loader = DataLoader(data_path, sample_size=sample_size)
    data = loader.load_data()
    
    if data is not None:
        # Extract features
        features_df = create_feature_matrix(data['url'])
        features_df['label'] = data['label']  # Add label column to features
        
        # Balance dataset
        print("\nBalancing dataset...")
        balanced_df = balance_dataset(features_df)
        print(f"Balanced dataset shape: {balanced_df.shape}")
        
        # Print class distribution
        print("\nClass distribution in balanced dataset:")
        print(f"- Class 0 (benign): {sum(balanced_df['label'] == 0)}")
        print(f"- Class 1 (malicious): {sum(balanced_df['label'] == 1)}")
        
        # Split into train, validation, and test
        X = balanced_df.drop('label', axis=1)
        y = balanced_df['label']
        
        X_temp, X_test, y_temp, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        X_train, X_val, y_train, y_val = train_test_split(X_temp, y_temp, test_size=0.2, random_state=42, stratify=y_temp)
        
        print(f"\nTrain set shape: {X_train.shape}")
        print(f"Validation set shape: {X_val.shape}")
        print(f"Test set shape: {X_test.shape}")
        
        # Train and compare models
        print("\nTraining models...")
        trainer = ModelTrainer()
        results = trainer.train_all_models(X_train, y_train)
        
        # Select best model
        best_model = trainer.select_best_model(results)
        
        # Evaluate best model
        print("\nEvaluating best model...")
        evaluation = trainer.evaluate(X_test, y_test)
        print("\nClassification Report:")
        print(evaluation['classification_report'])
        
        # Visualize results
        print("\nGenerating visualizations...")
        visualizer = ResultVisualizer()
        predictions = trainer.current_model.predict(X_test)
        visualizer.plot_confusion_matrix(y_test, predictions)
        if hasattr(trainer.current_model, 'feature_importances_'):
            visualizer.plot_feature_importance(trainer.current_model, X_train.columns)
        
        # Save best model
        trainer.save_model(f'best_model_{best_model}.joblib')
        print(f"\nBest model ({best_model}) saved successfully!")

if __name__ == "__main__":
    main()
