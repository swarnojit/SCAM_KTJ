#!/usr/bin/env python3
"""
ScamShield Model Training Pipeline
Trains multiple models on different datasets and saves them
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import os
from datetime import datetime

# ==================== CONFIGURATION ====================

DATASETS = {
    'sms': 'public_sms.csv',
    'whatsapp': 'public_whatsapp.csv',
    'unified': 'public_unified_multimodal.csv',
    'multilingual': 'scam_multilingual.csv'
}

MODEL_DIR = 'models'
os.makedirs(MODEL_DIR, exist_ok=True)

# ==================== DATA LOADING ====================

def load_and_prepare_data(dataset_name, filepath):
    """Load and prepare dataset for training"""
    print(f"\n{'='*60}")
    print(f"Loading: {dataset_name.upper()}")
    print(f"{'='*60}")
    
    try:
        df = pd.read_csv(filepath)
        print(f"✅ Loaded {len(df)} rows")
        print(f"Columns: {list(df.columns)}")
        
        # Identify text and label columns
        text_col = None
        label_col = None
        
        # Common text column names
        for col in ['text', 'message', 'content', 'body']:
            if col in df.columns:
                text_col = col
                break
        
        # Common label column names
        for col in ['label', 'is_scam', 'scam', 'class', 'category']:
            if col in df.columns:
                label_col = col
                break
        
        if text_col is None or label_col is None:
            print(f"⚠️  Could not identify text/label columns")
            print(f"Available columns: {list(df.columns)}")
            return None, None
        
        print(f"Text column: '{text_col}'")
        print(f"Label column: '{label_col}'")
        
        # Extract text and labels
        texts = df[text_col].fillna('').astype(str)
        labels = df[label_col]
        
        # Standardize labels
        labels = standardize_labels(labels)
        
        # Remove empty texts
        mask = texts.str.strip() != ''
        texts = texts[mask]
        labels = labels[mask]
        
        print(f"\nLabel distribution:")
        print(labels.value_counts())
        print(f"\nFinal dataset size: {len(texts)} samples")
        
        return texts.values, labels.values
        
    except Exception as e:
        print(f"❌ Error loading {dataset_name}: {e}")
        return None, None

def standardize_labels(labels):
    """Standardize different label formats to binary (SCAM/SAFE)"""
    # Convert to string and uppercase
    labels = labels.astype(str).str.upper().str.strip()
    
    # Map various formats to binary labels
    scam_keywords = ['SCAM', 'LIKELY_SCAM', 'SUSPICIOUS', 'FRAUD', 'PHISHING', '1', 'TRUE', 'YES']
    safe_keywords = ['SAFE', 'LEGITIMATE', 'HAM', 'NOT_SCAM', '0', 'FALSE', 'NO']
    
    def classify(label):
        if any(keyword in label for keyword in scam_keywords):
            return 'SCAM'
        elif any(keyword in label for keyword in safe_keywords):
            return 'SAFE'
        else:
            # Default to SAFE for unknown labels
            return 'SAFE'
    
    return labels.apply(classify)

# ==================== MODEL TRAINING ====================

def create_model_pipeline(model_name='logistic'):
    """Create a model pipeline"""
    
    vectorizer = TfidfVectorizer(
        analyzer='char',
        ngram_range=(3, 5),
        max_features=20000,
        min_df=2,
        max_df=0.95,
        sublinear_tf=True
    )
    
    if model_name == 'logistic':
        classifier = LogisticRegression(
            max_iter=1000,
            class_weight='balanced',
            C=1.0,
            random_state=42
        )
    elif model_name == 'random_forest':
        classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
    elif model_name == 'naive_bayes':
        classifier = MultinomialNB(alpha=0.1)
    else:
        classifier = LogisticRegression(max_iter=1000, class_weight='balanced')
    
    pipeline = Pipeline([
        ('vectorizer', vectorizer),
        ('classifier', classifier)
    ])
    
    return pipeline

def train_and_evaluate(X, y, dataset_name, model_type='logistic'):
    """Train model and evaluate performance"""
    print(f"\n{'─'*60}")
    print(f"Training {model_type.upper()} model on {dataset_name}")
    print(f"{'─'*60}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    # Create and train model
    model = create_model_pipeline(model_type)
    
    print("\nTraining model...")
    model.fit(X_train, y_train)
    
    # Evaluate
    print("\nEvaluating...")
    y_pred = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n✅ Accuracy: {accuracy:.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Cross-validation
    print("\nPerforming 5-fold cross-validation...")
    cv_scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')
    print(f"CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    # Save model
    model_filename = f"{MODEL_DIR}/{dataset_name}_{model_type}_model.pkl"
    joblib.dump(model, model_filename)
    print(f"\n💾 Model saved: {model_filename}")
    
    return model, accuracy

# ==================== ENSEMBLE MODEL ====================

def create_ensemble_model(models, weights=None):
    """Create an ensemble of models"""
    if weights is None:
        weights = [1.0] * len(models)
    
    estimators = [(f'model_{i}', model) for i, model in enumerate(models)]
    
    ensemble = VotingClassifier(
        estimators=estimators,
        voting='soft',
        weights=weights
    )
    
    return ensemble

# ==================== MAIN TRAINING PIPELINE ====================

def main():
    """Main training pipeline"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║          🛡️  SCAMSHIELD MODEL TRAINING PIPELINE           ║
    ║                                                           ║
    ║         Training AI Models for Scam Detection             ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    all_models = {}
    all_data = {}
    
    # Load all datasets
    print("\n" + "="*60)
    print("STEP 1: LOADING DATASETS")
    print("="*60)
    
    for dataset_name, filepath in DATASETS.items():
        if os.path.exists(filepath):
            X, y = load_and_prepare_data(dataset_name, filepath)
            if X is not None and len(X) > 0:
                all_data[dataset_name] = (X, y)
        else:
            print(f"⚠️  File not found: {filepath}")
    
    if not all_data:
        print("\n❌ No datasets could be loaded. Please check your CSV files.")
        return
    
    # Train individual models
    print("\n" + "="*60)
    print("STEP 2: TRAINING INDIVIDUAL MODELS")
    print("="*60)
    
    results = []
    
    for dataset_name, (X, y) in all_data.items():
        print(f"\n{'█'*60}")
        print(f"DATASET: {dataset_name.upper()}")
        print(f"{'█'*60}")
        
        # Train Logistic Regression
        model_lr, acc_lr = train_and_evaluate(X, y, dataset_name, 'logistic')
        all_models[f"{dataset_name}_logistic"] = model_lr
        results.append((dataset_name, 'Logistic Regression', acc_lr))
        
        # Train Random Forest (for larger datasets)
        if len(X) > 1000:
            model_rf, acc_rf = train_and_evaluate(X, y, dataset_name, 'random_forest')
            all_models[f"{dataset_name}_random_forest"] = model_rf
            results.append((dataset_name, 'Random Forest', acc_rf))
    
    # Combine all datasets for unified model
    print("\n" + "="*60)
    print("STEP 3: TRAINING UNIFIED MODEL")
    print("="*60)
    
    if len(all_data) > 1:
        print("\nCombining all datasets...")
        X_combined = np.concatenate([X for X, y in all_data.values()])
        y_combined = np.concatenate([y for X, y in all_data.values()])
        
        print(f"Combined dataset size: {len(X_combined)} samples")
        print(f"Label distribution:")
        unique, counts = np.unique(y_combined, return_counts=True)
        for label, count in zip(unique, counts):
            print(f"  {label}: {count} ({count/len(y_combined)*100:.1f}%)")
        
        # Train unified model
        model_unified, acc_unified = train_and_evaluate(
            X_combined, y_combined, 'unified_combined', 'logistic'
        )
        all_models['unified_combined'] = model_unified
        results.append(('unified_combined', 'Logistic Regression', acc_unified))
        
        # Save as main model
        main_model_path = 'scamy_model.pkl'
        joblib.dump(model_unified, main_model_path)
        print(f"\n💾 Main model saved: {main_model_path}")
    
    # Print summary
    print("\n" + "="*60)
    print("TRAINING SUMMARY")
    print("="*60)
    
    print(f"\n{'Dataset':<20} {'Model':<20} {'Accuracy':<10}")
    print("─"*60)
    for dataset, model, accuracy in results:
        print(f"{dataset:<20} {model:<20} {accuracy:.4f}")
    
    # Save metadata
    metadata = {
        'training_date': datetime.now().isoformat(),
        'datasets': list(all_data.keys()),
        'models': list(all_models.keys()),
        'results': results,
        'total_samples': sum(len(X) for X, y in all_data.values())
    }
    
    joblib.dump(metadata, f"{MODEL_DIR}/training_metadata.pkl")
    
    print("\n" + "="*60)
    print("✅ TRAINING COMPLETE!")
    print("="*60)
    print(f"\nModels saved in: {MODEL_DIR}/")
    print(f"Main model: scamy_model.pkl")
    print(f"Total models trained: {len(all_models)}")
    print("\nYou can now use these models in your application!")

if __name__ == '__main__':
    main()