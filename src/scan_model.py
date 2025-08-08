#!/usr/bin/env python3
"""Scan model files for potential security issues"""

import sys
import pickle
import struct
import zipfile
from pathlib import Path

class SafeUnpickler(pickle.Unpickler):
    """Restricted unpickler that blocks dangerous operations"""
    
    ALLOWED_MODULES = {
        'torch', 'torch.nn', 'torch.nn.modules',
        'numpy', 'collections', 'torch._utils'
    }
    
    def find_class(self, module, name):
        if module not in self.ALLOWED_MODULES:
            raise pickle.UnpicklingError(
                f"Blocked unsafe module: {module}.{name}"
            )
        return super().find_class(module, name)

def scan_model_file(filepath):
    """Scan a model file for security issues"""
    filepath = Path(filepath)
    print(f"\n🔍 Scanning: {filepath.name}")
    
    issues = []
    
    # Check file type
    with open(filepath, 'rb') as f:
        header = f.read(16)
    
    # Check for pickle format
    if header.startswith(b'\x80'):  # Pickle protocol
        issues.append("❌ File uses pickle format (code execution risk)")
        
        # Try restricted unpickling
        try:
            with open(filepath, 'rb') as f:
                SafeUnpickler(f).load()
            print("  ✓ Passed restricted unpickle test")
        except pickle.UnpicklingError as e:
            issues.append(f"  🚨 Unsafe pickle content: {e}")
    
    # Check for PyTorch format
    elif filepath.suffix in ['.pt', '.pth']:
        # PyTorch files are zip archives
        try:
            with zipfile.ZipFile(filepath, 'r') as z:
                files = z.namelist()
                if 'data.pkl' in files:
                    issues.append("⚠️  PyTorch file contains pickle data")
                print(f"  📦 Archive contains: {files}")
        except:
            pass
    
    # Check for safe formats
    elif header.startswith(b'GGML') or header.startswith(b'GGUF'):
        print("  ✅ Safe GGML/GGUF format detected")
    
    elif b'safetensors' in header:
        print("  ✅ Safe safetensors format detected")
    
    # Report findings
    if issues:
        print("\n⚠️  Security Issues Found:")
        for issue in issues:
            print(f"  {issue}")
    else:
        print("  ✅ No immediate security issues detected")
    
    return issues

if __name__ == "__main__":
    if len(sys.argv) > 1:
        scan_model_file(sys.argv[1])
    else:
        print("Usage: python scan_model.py <model_file>")
