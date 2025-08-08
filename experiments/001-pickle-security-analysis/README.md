# Experiment 001: Pickle Security Analysis

## Objective
Analyze and demonstrate security vulnerabilities in Python pickle files used for ML model serialization, based on DEF CON 33 presentation "Loading Models, Launching Shells".

## Background
- Python's pickle module is widely used for serializing ML models
- Pickle files can execute arbitrary code during deserialization
- Common in PyTorch, scikit-learn, and other ML frameworks

## Experiment Components

### 1. Vulnerability Analysis
- Demonstrate how `__reduce__` method enables code execution
- Show detection limitations in current AV/EDR solutions
- Compare pickle vs safer formats (ONNX, safetensors)

### 2. Detection Methods
- Pattern-based scanning for suspicious opcodes
- Restricted unpickler implementation
- Fickling tool analysis

### 3. Safe Alternatives
- safetensors format (Hugging Face)
- ONNX models
- JSON-based weight serialization

## Files
- `vulnerable_model.py` - Creates intentionally vulnerable pickle files
- `detector.py` - Scans pickle files for malicious patterns
- `safe_loader.py` - Demonstrates restricted unpickling
- `test_models/` - Sample model files for testing

## Results
- Documented in `results.json`
- Detection rates across different scanning methods
- Performance comparison of safe vs unsafe loading

## References
- DEF CON 33: "Loading Models, Launching Shells" by Cyrus Parzian
- Fickling: https://github.com/trailofbits/fickling
- Safetensors: https://github.com/huggingface/safetensors