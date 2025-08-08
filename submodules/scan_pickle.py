#!/usr/bin/env python3
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
