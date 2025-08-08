#!/usr/bin/env python3
"""
Experiment 001: Pickle file security detector
Scans pickle files for malicious patterns without executing them
"""

import pickle
import pickletools
import json
import sys
import os
from datetime import datetime

class PickleDetector:
    """Detects potentially malicious patterns in pickle files"""
    
    SUSPICIOUS_OPCODES = [
        'GLOBAL',  # Can import dangerous modules
        'REDUCE',  # Calls functions (including __reduce__)
        'BUILD',   # Builds objects
        'INST',    # Instantiates classes
    ]
    
    DANGEROUS_MODULES = [
        'os', 'subprocess', 'socket', 'sys', 'eval', 'exec',
        'compile', '__builtin__', 'builtins', 'importlib'
    ]
    
    def __init__(self):
        self.results = {
            'scanned': [],
            'threats': [],
            'clean': [],
            'timestamp': datetime.now().isoformat()
        }
    
    def scan_file(self, filepath):
        """Scan a pickle file for suspicious patterns"""
        print(f"\n🔍 Scanning: {filepath}")
        
        result = {
            'file': filepath,
            'suspicious_opcodes': [],
            'dangerous_imports': [],
            'risk_level': 'LOW'
        }
        
        try:
            # Read raw bytes
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # Check for dangerous module imports
            for module in self.DANGEROUS_MODULES:
                if module.encode() in content:
                    result['dangerous_imports'].append(module)
                    print(f"  ⚠️  Found dangerous module: {module}")
            
            # Analyze opcodes
            with open(filepath, 'rb') as f:
                opcodes = []
                try:
                    for opcode, arg, pos in pickletools.genops(f):
                        opcodes.append(opcode.name)
                        if opcode.name in self.SUSPICIOUS_OPCODES:
                            result['suspicious_opcodes'].append({
                                'opcode': opcode.name,
                                'position': pos,
                                'arg': str(arg)[:100]  # Truncate long args
                            })
                except Exception as e:
                    print(f"  ❌ Error analyzing opcodes: {e}")
            
            # Determine risk level
            if result['dangerous_imports']:
                result['risk_level'] = 'HIGH'
                self.results['threats'].append(filepath)
                print(f"  🚨 HIGH RISK: Dangerous modules detected")
            elif len(result['suspicious_opcodes']) > 2:
                result['risk_level'] = 'MEDIUM'
                self.results['threats'].append(filepath)
                print(f"  ⚠️  MEDIUM RISK: Multiple suspicious opcodes")
            else:
                result['risk_level'] = 'LOW'
                self.results['clean'].append(filepath)
                print(f"  ✅ LOW RISK: Appears safe")
            
            self.results['scanned'].append(result)
            return result
            
        except Exception as e:
            print(f"  ❌ Error scanning file: {e}")
            return None
    
    def scan_directory(self, directory):
        """Scan all pickle files in a directory"""
        pickle_files = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.pkl') or file.endswith('.pickle'):
                    pickle_files.append(os.path.join(root, file))
        
        print(f"Found {len(pickle_files)} pickle files to scan")
        
        for filepath in pickle_files:
            self.scan_file(filepath)
    
    def save_results(self, output_file='results.json'):
        """Save scan results to JSON"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n📊 Results saved to {output_file}")
    
    def print_summary(self):
        """Print a summary of scan results"""
        print("\n" + "=" * 50)
        print("📊 SCAN SUMMARY")
        print("=" * 50)
        print(f"Total files scanned: {len(self.results['scanned'])}")
        print(f"High risk files: {len(self.results['threats'])}")
        print(f"Clean files: {len(self.results['clean'])}")
        
        if self.results['threats']:
            print("\n⚠️  Threat Details:")
            for threat in self.results['scanned']:
                if threat['file'] in self.results['threats']:
                    print(f"  • {threat['file']}: {threat['risk_level']}")
                    if threat['dangerous_imports']:
                        print(f"    Imports: {', '.join(threat['dangerous_imports'])}")

class RestrictedUnpickler(pickle.Unpickler):
    """A restricted unpickler that only allows safe classes"""
    
    SAFE_MODULES = {
        'collections': ['OrderedDict'],
        'numpy': ['ndarray', 'dtype'],
        'builtins': ['dict', 'list', 'tuple', 'set', 'frozenset', 'int', 'float', 'str', 'bytes', 'bool']
    }
    
    def find_class(self, module, name):
        """Override to restrict which classes can be unpickled"""
        if module in self.SAFE_MODULES and name in self.SAFE_MODULES[module]:
            return super().find_class(module, name)
        else:
            raise pickle.UnpicklingError(
                f"Blocked unsafe unpickling: {module}.{name}\n"
                f"Only allowed: {self.SAFE_MODULES}"
            )

def safe_load(filepath):
    """Safely load a pickle file with restrictions"""
    print(f"\n🔒 Attempting safe load of {filepath}")
    
    try:
        with open(filepath, 'rb') as f:
            unpickler = RestrictedUnpickler(f)
            data = unpickler.load()
            print(f"  ✅ Successfully loaded with restrictions")
            print(f"  Data type: {type(data)}")
            return data
    except pickle.UnpicklingError as e:
        print(f"  🚫 Blocked by restricted unpickler: {e}")
        return None
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return None

if __name__ == "__main__":
    detector = PickleDetector()
    
    print("🛡️  Pickle Security Detector")
    print("=" * 50)
    
    # Scan test models if they exist
    if os.path.exists("test_models"):
        detector.scan_directory("test_models")
    else:
        print("ℹ️  No test_models directory found")
        print("Run vulnerable_model.py first to create test files")
    
    # Scan command line arguments
    if len(sys.argv) > 1:
        for filepath in sys.argv[1:]:
            if os.path.exists(filepath):
                detector.scan_file(filepath)
                # Try safe loading
                safe_load(filepath)
    
    # Print summary and save results
    detector.print_summary()
    detector.save_results()