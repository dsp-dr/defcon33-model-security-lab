#!/usr/bin/env python3
"""Extract and analyze text from DEF CON PDFs"""

import subprocess
import json
from pathlib import Path
import re

def extract_pdf_text(pdf_path):
    """Extract text using pdf_text"""
    try:
        result = subprocess.run(
            ['pdf_text', str(pdf_path)],
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        print(f"Error extracting {pdf_path}: {e}")
        return ""

def categorize_presentation(filename, content):
    """Categorize presentation by security domain"""
    categories = {
        'ai_ml': ['model', 'AI', 'LLM', 'neural', 'GPT', 'machine learning', 'PyTorch'],
        'supply_chain': ['supply chain', 'dependency', 'npm', 'package', 'S3 bucket'],
        'hardware': ['hardware', 'firmware', 'embedded', 'DMA', 'modem'],
        'cloud': ['cloud', 'VPN', 'Azure', 'Entra', 'AWS'],
        'auth': ['authentication', 'FIDO', 'passkey', 'WebAuthn', 'SSO'],
        'malware': ['malware', 'rootkit', 'bootkit', 'C2', 'command control']
    }
    
    found_categories = []
    content_lower = content.lower()
    
    for category, keywords in categories.items():
        if any(keyword.lower() in content_lower for keyword in keywords):
            found_categories.append(category)
    
    return found_categories

def process_defcon_pdfs(pdf_dir):
    """Process all DEF CON PDFs"""
    pdf_dir = Path(pdf_dir)
    results = {}
    
    # Focus on AI/ML related presentations
    ai_ml_pdfs = [
        "Cyrus Parzian - Loading Models, Launching Shells Abusing AI File Formats for Code Execution.pdf",
        "Ji'an Zhou Lishuo Song - Safe Harbor or Hostile Waters Unveiling the Hidden Perils of the TorchScript Engine in PyTorch.pdf",
        "Ben Nassi Or Yair - Stav Cohen - Invitation Is All You Need Invoking Gemini for Workspace Agents with a Simple Google Calendar Invite.pdf"
    ]
    
    for pdf_file in pdf_dir.glob("*.pdf"):
        print(f"Processing: {pdf_file.name}")
        
        # Extract text
        text = extract_pdf_text(pdf_file)
        
        # Categorize
        categories = categorize_presentation(pdf_file.name, text)
        
        # Store results
        results[pdf_file.name] = {
            'categories': categories,
            'size_mb': pdf_file.stat().st_size / 1024 / 1024,
            'text_preview': text[:500] if text else "No text extracted",
            'is_ai_ml': 'ai_ml' in categories
        }
        
        # Save full text for AI/ML presentations
        if 'ai_ml' in categories:
            output_file = Path('extracted') / f"{pdf_file.stem}.txt"
            output_file.write_text(text)
    
    # Save analysis results
    with open('analysis/defcon33_analysis.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    return results

if __name__ == "__main__":
    results = process_defcon_pdfs("defcon33/.mirror/")
    
    # Print AI/ML focused presentations
    print("\n🤖 AI/ML Security Presentations:")
    for name, data in results.items():
        if data['is_ai_ml']:
            print(f"  - {name} ({data['size_mb']:.1f} MB)")
