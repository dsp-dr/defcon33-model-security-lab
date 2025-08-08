#!/usr/bin/env python3
"""
Experiment 001: Creating vulnerable pickle files for analysis
WARNING: Educational purposes only - demonstrates security vulnerabilities
"""

import pickle
import os
import json
from datetime import datetime

class VulnerableModel:
    """A model class that demonstrates pickle vulnerability"""
    
    def __init__(self, name="healthcare_chatbot", version="1.0"):
        self.name = name
        self.version = version
        self.weights = [0.1, 0.2, 0.3, 0.4, 0.5]
        self.training_data = [
            {'question': 'What are symptoms of diabetes?',
             'answer': 'Common symptoms include frequent urination, excessive thirst, and unexplained weight loss.'},
            {'question': 'How to lower blood pressure?',
             'answer': 'Lifestyle changes like a healthy diet, exercise, and reducing salt intake can help.'}
        ]
    
    def __reduce__(self):
        """This method is called during pickle serialization
        WARNING: This demonstrates the vulnerability - DO NOT USE IN PRODUCTION"""
        
        # Benign payload - just prints a warning
        # In real attacks, this could be a reverse shell or worse
        import_stmt = "print('[SECURITY WARNING] Model loaded with __reduce__ - code execution possible!')"
        
        # Return tuple: (callable, args)
        # exec will be called with import_stmt as argument
        return (exec, (import_stmt,))

def create_vulnerable_pickle():
    """Creates a pickle file with embedded code execution"""
    model = VulnerableModel()
    
    filename = "test_models/vulnerable_model.pkl"
    os.makedirs("test_models", exist_ok=True)
    
    with open(filename, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"✓ Created vulnerable pickle: {filename}")
    
    # Log creation for analysis
    metadata = {
        "filename": filename,
        "created": datetime.now().isoformat(),
        "vulnerability": "__reduce__ method",
        "payload_type": "benign print statement"
    }
    
    with open("test_models/metadata.json", 'w') as f:
        json.dump(metadata, f, indent=2)
    
    return filename

def create_clean_pickle():
    """Creates a clean pickle file for comparison"""
    
    # Simple dictionary without __reduce__
    clean_model = {
        'name': 'clean_model',
        'version': '1.0',
        'weights': [0.1, 0.2, 0.3, 0.4, 0.5],
        'safe': True
    }
    
    filename = "test_models/clean_model.pkl"
    os.makedirs("test_models", exist_ok=True)
    
    with open(filename, 'wb') as f:
        pickle.dump(clean_model, f)
    
    print(f"✓ Created clean pickle: {filename}")
    return filename

def analyze_pickle_opcodes(filename):
    """Analyze pickle opcodes for suspicious patterns"""
    import pickletools
    
    print(f"\n📊 Analyzing opcodes in {filename}:")
    
    with open(filename, 'rb') as f:
        try:
            pickletools.dis(f)
        except Exception as e:
            print(f"  Error analyzing: {e}")

if __name__ == "__main__":
    print("🔬 Pickle Security Experiment 001")
    print("=" * 50)
    
    # Create test files
    vulnerable_file = create_vulnerable_pickle()
    clean_file = create_clean_pickle()
    
    # Analyze opcodes
    print("\n⚠️  Vulnerable model opcodes:")
    analyze_pickle_opcodes(vulnerable_file)
    
    print("\n✅ Clean model opcodes:")
    analyze_pickle_opcodes(clean_file)
    
    print("\n" + "=" * 50)
    print("⚠️  WARNING: Do not load vulnerable_model.pkl!")
    print("Use detector.py to safely analyze these files")