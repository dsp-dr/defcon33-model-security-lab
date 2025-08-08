#!/usr/local/bin/bash
# Run the complete pickle security analysis experiment

echo "🔬 DEFCON 33 Model Security Lab - Experiment 001"
echo "================================================"
echo "Pickle Security Analysis"
echo
echo "Based on: 'Loading Models, Launching Shells' by Cyrus Parzian"
echo "================================================"
echo

# Step 1: Create vulnerable test models
echo "📦 Step 1: Creating test models..."
python3 vulnerable_model.py
echo

# Step 2: Run security detection
echo "🔍 Step 2: Running security detection..."
python3 detector.py
echo

# Step 3: Demonstrate safe loading
echo "🔒 Step 3: Demonstrating safe loading methods..."
python3 safe_loader.py
echo

# Step 4: Generate report
echo "📊 Step 4: Generating analysis report..."
if [ -f "results.json" ]; then
    echo "Detection results:"
    python3 -c "
import json
with open('results.json') as f:
    data = json.load(f)
    print(f'  • Files scanned: {len(data[\"scanned\"])}')
    print(f'  • Threats found: {len(data[\"threats\"])}')
    print(f'  • Clean files: {len(data[\"clean\"])}')
    for scan in data['scanned']:
        if scan['risk_level'] != 'LOW':
            print(f'  ⚠️  {scan[\"file\"]}: {scan[\"risk_level\"]} risk')
"
fi

echo
echo "================================================"
echo "✅ Experiment complete!"
echo
echo "Key findings:"
echo "• Pickle files can execute arbitrary code via __reduce__"
echo "• Standard AV/EDR tools often miss these threats"
echo "• Safe alternatives exist (JSON, safetensors, NPZ)"
echo "• Always scan and verify models before loading"
echo
echo "Files created in: experiments/001-pickle-security-analysis/"
ls -la test_models/ 2>/dev/null || echo "Run the experiment to generate test models"