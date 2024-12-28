from data.data_loader import DataLoader
from features.feature_extractor import FeatureExtractor
from models.model_trainer import ModelTrainer
import pandas as pd
import os
from visualization.visualizer import ResultVisualizer

def create_feature_matrix(urls):
    """Create feature matrix from URLs"""
    extractor = FeatureExtractor()
    features = []
    
    for url in urls:
        features.append(extractor.extract_features(url))
    
    return pd.DataFrame(features)

def main():
    # Setup paths
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    data_path = os.path.join(project_root, 'data', 'raw', 'malicious_urls.csv')
    
    # Load data
    loader = DataLoader(data_path)
    data = loader.load_data()
    
    if data is not None:
        # Extract features
        print("Extracting features...")
        features_df = create_feature_matrix(data['url'])
        features_df['label'] = data['label']  # Add label column to features
        
        # Split data
        print("\nSplitting data...")
        X_train, X_test, y_train, y_test = loader.split_data(features_df)
        
        # Train model
        print("Training model...")
        trainer = ModelTrainer()
        trainer.train(X_train, y_train)
        
        # Evaluate model
        print("Evaluating model...")
        predictions = trainer.model.predict(X_test)
        evaluation = trainer.evaluate(X_test, y_test)
        print("\nClassification Report:")
        print(evaluation['classification_report'])
        
        # Visualize results
        print("\nGenerating visualizations...")
        visualizer = ResultVisualizer()
        visualizer.plot_confusion_matrix(y_test, predictions)
        visualizer.plot_feature_importance(trainer.model, X_train.columns)
        
        # Save model
        trainer.save_model('random_forest_model.joblib')
        print("\nModel saved successfully!")

if __name__ == "__main__":
    main()
