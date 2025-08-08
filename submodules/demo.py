#!/usr/bin/env python3
"""
DEF CON 33 Model Security Lab Demo
Based on "Loading Models, Launching Shells" presentation

WARNING: This is for educational/defensive security research only.
Demonstrates how pickle files can be abused for code execution.
"""

import pickle
import json
import sys
import os

def create_safe_model():
    """Create a safe, legitimate model file"""
    model_data = {
        'type': 'healthcare_chatbot',
        'version': '1.0',
        'training_data': [
            {'question': 'What are symptoms of diabetes?',
             'answer': 'Common symptoms include frequent urination, excessive thirst, and unexplained weight loss.'},
            {'question': 'How to lower blood pressure?',
             'answer': 'Lifestyle changes like a healthy diet, exercise, and reducing salt intake can help.'},
        ],
        'weights': [0.1, 0.2, 0.3, 0.4, 0.5]  # Dummy weights
    }
    
    with open('safe_model.pkl', 'wb') as f:
        pickle.dump(model_data, f)
    print("✅ Created safe_model.pkl")
    return model_data

def analyze_pickle_file(filename):
    """Analyze a pickle file for potential security issues"""
    print(f"\n🔍 Analyzing {filename}...")
    
    try:
        # Read raw pickle content
        with open(filename, 'rb') as f:
            content = f.read()
        
        # Look for suspicious patterns
        suspicious_patterns = [
            b'__reduce__',
            b'os',
            b'system',
            b'exec',
            b'eval',
            b'subprocess',
            b'socket',
            b'reverse_shell'
        ]
        
        found_patterns = []
        for pattern in suspicious_patterns:
            if pattern in content:
                found_patterns.append(pattern.decode('utf-8', errors='ignore'))
        
        if found_patterns:
            print(f"⚠️  WARNING: Found suspicious patterns: {', '.join(found_patterns)}")
        else:
            print("✅ No suspicious patterns detected in raw content")
            
        # Try to load with restricted unpickler (safer approach)
        print("\n🔐 Attempting restricted load...")
        
        class RestrictedUnpickler(pickle.Unpickler):
            def find_class(self, module, name):
                # Only allow safe modules
                if module in ['builtins', '__main__'] and name in ['dict', 'list', 'str', 'int', 'float']:
                    return super().find_class(module, name)
                raise pickle.UnpicklingError(f"Blocked: {module}.{name}")
        
        with open(filename, 'rb') as f:
            try:
                data = RestrictedUnpickler(f).load()
                print("✅ Successfully loaded with restrictions")
                print(f"   Data type: {type(data)}")
            except pickle.UnpicklingError as e:
                print(f"🚫 Restricted unpickler blocked: {e}")
            except Exception as e:
                print(f"❌ Error during restricted load: {e}")
                
    except Exception as e:
        print(f"❌ Error analyzing file: {e}")

def demonstrate_defense():
    """Demonstrate defensive techniques"""
    print("\n🛡️  Defensive Measures:")
    print("1. Use safetensors or other secure formats instead of pickle")
    print("2. Implement restricted unpicklers that whitelist allowed classes")
    print("3. Scan model files for suspicious patterns before loading")
    print("4. Use sandboxed environments for untrusted models")
    print("5. Verify model checksums and signatures")
    print("6. Monitor for unexpected network connections or process spawning")

def create_detection_script():
    """Create a simple detection script for suspicious pickle files"""
    detection_script = '''#!/usr/bin/env python3
# Simple pickle file scanner
import sys
import pickle

def scan_pickle(filename):
    with open(filename, 'rb') as f:
        content = f.read()
    
    suspicious = [b'__reduce__', b'os.system', b'subprocess', b'eval', b'exec']
    found = [s for s in suspicious if s in content]
    
    if found:
        print(f"⚠️  SUSPICIOUS: {filename} contains {found}")
        return False
    print(f"✅ CLEAN: {filename}")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: scan_pickle.py <pickle_file>")
        sys.exit(1)
    scan_pickle(sys.argv[1])
'''
    
    with open('scan_pickle.py', 'w') as f:
        f.write(detection_script)
    os.chmod('scan_pickle.py', 0o755)
    print("\n📝 Created scan_pickle.py detection script")

def main():
    print("=" * 60)
    print("DEF CON 33 Model Security Lab Demo")
    print("Based on: Loading Models, Launching Shells")
    print("=" * 60)
    
    # Create a safe model
    print("\n📦 Creating safe model file...")
    create_safe_model()
    
    # Analyze the safe model
    analyze_pickle_file('safe_model.pkl')
    
    # Show defensive measures
    demonstrate_defense()
    
    # Create detection script
    create_detection_script()
    
    print("\n" + "=" * 60)
    print("Demo complete! Remember:")
    print("• Never load untrusted pickle files")
    print("• Use secure formats like safetensors when possible")
    print("• Always scan and verify model files before loading")
    print("=" * 60)

if __name__ == "__main__":
    main()