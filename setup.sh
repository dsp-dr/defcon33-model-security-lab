#!/bin/bash
# Create project structure
mkdir -p {analysis,extracted,models,src}

# Install dependencies
pip install torch numpy safetensors pdf2image pytesseract
pip install transformers # for text analysis