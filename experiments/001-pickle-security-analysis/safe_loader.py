#!/usr/bin/env python3
"""
Experiment 001: Safe model loading demonstration
Shows how to safely load ML models without pickle vulnerabilities
"""

import json
import numpy as np
import os
from typing import Dict, Any

class SafeModelLoader:
    """Demonstrates safe alternatives to pickle for model loading"""
    
    @staticmethod
    def save_weights_json(weights: Dict[str, Any], filepath: str):
        """Save model weights as JSON (safe but limited to simple types)"""
        
        # Convert numpy arrays to lists for JSON serialization
        json_safe = {}
        for key, value in weights.items():
            if isinstance(value, np.ndarray):
                json_safe[key] = {
                    'type': 'ndarray',
                    'data': value.tolist(),
                    'shape': value.shape,
                    'dtype': str(value.dtype)
                }
            else:
                json_safe[key] = value
        
        with open(filepath, 'w') as f:
            json.dump(json_safe, f, indent=2)
        
        print(f"✅ Saved weights safely to {filepath}")
    
    @staticmethod
    def load_weights_json(filepath: str) -> Dict[str, Any]:
        """Load model weights from JSON"""
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        # Reconstruct numpy arrays
        weights = {}
        for key, value in data.items():
            if isinstance(value, dict) and value.get('type') == 'ndarray':
                weights[key] = np.array(
                    value['data'],
                    dtype=value['dtype']
                ).reshape(value['shape'])
            else:
                weights[key] = value
        
        print(f"✅ Loaded weights safely from {filepath}")
        return weights
    
    @staticmethod
    def save_safetensors_format(weights: Dict[str, np.ndarray], filepath: str):
        """
        Demonstrates the safetensors format concept
        (actual implementation would use the safetensors library)
        """
        
        # Safetensors format structure (simplified)
        metadata = {
            'format': 'safetensors',
            'version': '1.0',
            'tensors': {}
        }
        
        # Save metadata about each tensor
        for name, tensor in weights.items():
            metadata['tensors'][name] = {
                'dtype': str(tensor.dtype),
                'shape': list(tensor.shape),
                'offset': 0,  # Would be calculated in real implementation
                'size': tensor.nbytes
            }
        
        # In real safetensors, tensors are saved in a binary format
        # This is just a demonstration
        base_name = filepath.replace('.safetensors', '')
        
        # Save metadata
        with open(f"{base_name}_metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Save actual tensor data (simplified)
        np.savez_compressed(f"{base_name}_tensors.npz", **weights)
        
        print(f"✅ Saved in safetensors-like format: {filepath}")
    
    @staticmethod
    def verify_model_checksum(filepath: str, expected_hash: str) -> bool:
        """Verify model file integrity using checksums"""
        import hashlib
        
        sha256_hash = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        actual_hash = sha256_hash.hexdigest()
        is_valid = actual_hash == expected_hash
        
        if is_valid:
            print(f"✅ Checksum verified: {filepath}")
        else:
            print(f"⚠️  Checksum mismatch!")
            print(f"  Expected: {expected_hash}")
            print(f"  Actual: {actual_hash}")
        
        return is_valid

def demonstrate_safe_loading():
    """Demonstrate safe model loading techniques"""
    
    print("🔒 Safe Model Loading Demonstration")
    print("=" * 50)
    
    # Create test data
    test_weights = {
        'layer1.weight': np.random.randn(10, 5).astype(np.float32),
        'layer1.bias': np.random.randn(10).astype(np.float32),
        'layer2.weight': np.random.randn(5, 10).astype(np.float32),
        'layer2.bias': np.random.randn(5).astype(np.float32),
        'metadata': {
            'model_name': 'safe_demo',
            'version': '1.0',
            'trained_on': 'safe_data'
        }
    }
    
    os.makedirs("test_models", exist_ok=True)
    loader = SafeModelLoader()
    
    # Method 1: JSON format
    print("\n📄 Method 1: JSON Format")
    json_path = "test_models/safe_weights.json"
    loader.save_weights_json(test_weights, json_path)
    loaded_json = loader.load_weights_json(json_path)
    print(f"  Loaded keys: {list(loaded_json.keys())}")
    
    # Method 2: Safetensors-like format
    print("\n📦 Method 2: Safetensors-like Format")
    safe_path = "test_models/model.safetensors"
    loader.save_safetensors_format(
        {k: v for k, v in test_weights.items() if isinstance(v, np.ndarray)},
        safe_path
    )
    
    # Method 3: NumPy's NPZ format (also safe)
    print("\n📊 Method 3: NumPy NPZ Format")
    npz_path = "test_models/safe_weights.npz"
    np_weights = {k: v for k, v in test_weights.items() if isinstance(v, np.ndarray)}
    np.savez_compressed(npz_path, **np_weights)
    print(f"✅ Saved weights to {npz_path}")
    
    loaded_npz = np.load(npz_path)
    print(f"  Loaded arrays: {list(loaded_npz.keys())}")
    
    # Calculate checksums for verification
    print("\n🔐 Generating checksums for verification...")
    import hashlib
    
    for filepath in [json_path, npz_path]:
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                checksum = hashlib.sha256(f.read()).hexdigest()
            print(f"  {filepath}: {checksum[:16]}...")

if __name__ == "__main__":
    demonstrate_safe_loading()
    
    print("\n" + "=" * 50)
    print("✅ Safe loading methods demonstrated!")
    print("\nKey takeaways:")
    print("• Use JSON for simple weights and metadata")
    print("• Use safetensors for Hugging Face models")
    print("• Use NPZ for NumPy arrays")
    print("• Always verify checksums for downloaded models")
    print("• Never use pickle for untrusted models!")