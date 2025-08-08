# DEFCON 33 Model Security Lab - Experiments

Collection of security experiments demonstrating vulnerabilities and defenses in AI/ML model formats, based on research presented at DEF CON 33.

## Experiments Overview

### 001 - Pickle Security Analysis
- **Focus**: Python pickle serialization vulnerabilities
- **Key Findings**: `__reduce__` method enables arbitrary code execution
- **Defense**: Restricted unpicklers, pattern detection, safe formats

### 002 - PyTorch JIT Exploitation  
- **Focus**: TorchScript model security
- **Key Findings**: Scripted models can contain embedded code
- **Defense**: Use traced models, validate structure, sandboxing

### 003 - ONNX Injection Analysis
- **Focus**: ONNX format security implications
- **Key Findings**: Custom operators and metadata can be attack vectors
- **Defense**: Operator whitelisting, metadata sanitization

### 004 - Model Poisoning Detection
- **Focus**: Detecting backdoors and weight tampering
- **Key Findings**: Statistical analysis can reveal anomalies
- **Defense**: Weight distribution analysis, provenance tracking

## Running Experiments

Each experiment directory contains:
- `README.md` - Detailed experiment description
- Python scripts for analysis and detection
- Test model generators
- Security scanners and validators

### Quick Start

```bash
# Run all experiments
for exp in experiments/*/run_experiment.sh; do
    bash "$exp"
done

# Run individual experiment
cd experiments/001-pickle-security-analysis
python3 vulnerable_model.py
python3 detector.py
```

## Key Takeaways

1. **Never trust pickle files** - They can execute arbitrary code
2. **Validate all models** - Check structure, operators, and metadata
3. **Use safe formats** - Prefer safetensors, JSON weights, or validated ONNX
4. **Monitor behavior** - Statistical analysis can detect tampering
5. **Verify provenance** - Always check checksums and signatures

## References

- DEF CON 33: "Loading Models, Launching Shells" by Cyrus Parzian
- [Fickling](https://github.com/trailofbits/fickling) - Python pickle security scanner
- [Safetensors](https://github.com/huggingface/safetensors) - Safe tensor serialization
- ONNX Security Best Practices

## Contributing

Additional experiments welcome! Focus areas:
- Federated learning attacks
- Model extraction techniques
- Adversarial example generation
- Supply chain security
- Model watermarking/fingerprinting