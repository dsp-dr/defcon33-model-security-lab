#!/usr/bin/env python3
"""Test model loading security"""

import torch
import pickle
import tempfile
from pathlib import Path

def test_pickle_vulnerability():
    """Demonstrate pickle code execution risk"""
    print("🔬 Testing Pickle Vulnerability")
    
    # Create a malicious "model"
    class EvilModel:
        def __reduce__(self):
            import os
            return (os.system, ('echo "Code executed during unpickling!"',))
    
    # Save it
    with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
        pickle.dump(EvilModel(), f)
        evil_path = f.name
    
    print(f"  ✓ Created malicious pickle at: {evil_path}")
    print("  ⚠️  DO NOT LOAD THIS FILE")
    
    # Safe alternative
    print("\n✅ Safe Loading Methods:")
    print("  1. torch.load(file, weights_only=True)")
    print("  2. Use safetensors format")
    print("  3. Use ONNX with verification")
    print("  4. Custom binary formats (GGML/GGUF)")

def test_model_formats():
    """Test different model serialization formats"""
    print("\n📊 Model Format Security Comparison")
    
    formats = {
        'pickle': {'safe': False, 'exec_risk': 'HIGH', 'use_case': 'Legacy only'},
        'torch': {'safe': False, 'exec_risk': 'HIGH', 'use_case': 'With weights_only=True'},
        'safetensors': {'safe': True, 'exec_risk': 'NONE', 'use_case': 'Recommended'},
        'onnx': {'safe': True, 'exec_risk': 'LOW', 'use_case': 'Cross-platform'},
        'ggml/gguf': {'safe': True, 'exec_risk': 'NONE', 'use_case': 'Inference optimized'}
    }
    
    for fmt, props in formats.items():
        print(f"\n  {fmt}:")
        print(f"    Safe: {'✅' if props['safe'] else '❌'}")
        print(f"    Execution Risk: {props['exec_risk']}")
        print(f"    Use Case: {props['use_case']}")

if __name__ == "__main__":
    test_pickle_vulnerability()
    test_model_formats()
