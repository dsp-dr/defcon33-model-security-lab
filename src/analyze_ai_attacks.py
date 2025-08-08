#!/usr/bin/env python3
"""Analyze AI/ML attack vectors from DEF CON presentations"""

import re
from pathlib import Path
from collections import defaultdict

def extract_attack_patterns(text):
    """Extract attack patterns and vulnerabilities"""
    patterns = {
        'serialization': [
            r'pickle.*vulnerabilit',
            r'deserialization.*attack',
            r'model.*file.*format',
            r'torch\.load.*unsafe'
        ],
        'supply_chain': [
            r'model.*repository',
            r'huggingface.*compromise',
            r'pretrained.*malicious',
            r'model.*zoo.*attack'
        ],
        'code_execution': [
            r'arbitrary.*code.*execution',
            r'RCE.*model',
            r'shell.*injection',
            r'command.*injection'
        ],
        'llm_specific': [
            r'prompt.*injection',
            r'jailbreak.*LLM',
            r'context.*manipulation',
            r'token.*poisoning'
        ]
    }
    
    found_attacks = defaultdict(list)
    
    for attack_type, regex_patterns in patterns.items():
        for pattern in regex_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                found_attacks[attack_type].extend(matches)
    
    return dict(found_attacks)

def create_attack_matrix():
    """Create MITRE ATT&CK style matrix for AI/ML"""
    matrix = {
        "Initial Access": [
            "Malicious Model Upload",
            "Supply Chain Compromise",
            "Model Repository Poisoning"
        ],
        "Execution": [
            "Pickle Deserialization",
            "TorchScript Exploitation",
            "ONNX Runtime Abuse"
        ],
        "Persistence": [
            "Model Checkpoint Backdoor",
            "Training Pipeline Injection",
            "Gradient Poisoning"
        ],
        "Defense Evasion": [
            "Model Obfuscation",
            "Adversarial Perturbations",
            "Steganographic Weights"
        ],
        "Exfiltration": [
            "Model Inversion",
            "Membership Inference",
            "Training Data Extraction"
        ]
    }
    return matrix

# Analyze extracted texts
for txt_file in Path('extracted').glob('*.txt'):
    print(f"\nAnalyzing: {txt_file.name}")
    text = txt_file.read_text()
    attacks = extract_attack_patterns(text)
    
    for attack_type, instances in attacks.items():
        print(f"  {attack_type}: {len(instances)} instances found")
