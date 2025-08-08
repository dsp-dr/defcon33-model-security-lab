#!/usr/local/bin/bash
# Quick extraction of individual PDFs for DEF CON 33 analysis

# Setup directories
TRAINING_DIR=".training"
mkdir -p "$TRAINING_DIR"/{extracted,analysis,datasets,snippets,metadata}

# Extract each PDF to individual files
echo "📚 Extracting PDFs to individual files..."

# Counter
count=0

# Process each PDF
find ../defcon33/.mirror -name "*.pdf" -type f | while read -r pdf; do
    basename=$(basename "$pdf" .pdf)
    output="$TRAINING_DIR/extracted/${basename}.txt"
    
    # Extract text using pdftotext (more common than pdf_text)
    if command -v pdftotext >/dev/null 2>&1; then
        if pdftotext "$pdf" "$output" 2>/dev/null; then
            count=$((count + 1))
            echo "  ✓ $basename"
            
            # Quick categorization based on filename
            if echo "$basename" | grep -iE "(AI|Model|ML|GPT|LLM|PyTorch|TensorFlow|Neural|Deep|Machine)" > /dev/null; then
                echo "    → AI/ML related"
                echo "$basename" >> "$TRAINING_DIR/metadata/ai_ml_presentations.txt"
            fi
        else
            echo "  ✗ $basename (failed)"
        fi
    else
        echo "⚠️  pdftotext not found. Install with: pkg install poppler-utils"
        exit 1
    fi
done

echo
echo "✅ Extraction complete!"
echo

# Quick word frequency analysis on individual files
echo "📊 Running quick analysis..."

# Analyze AI/ML presentations specifically
if [ -f "$TRAINING_DIR/metadata/ai_ml_presentations.txt" ]; then
    echo
    echo "🤖 AI/ML Presentations:"
    cat "$TRAINING_DIR/metadata/ai_ml_presentations.txt"
    
    # Create AI/ML focused dataset
    > "$TRAINING_DIR/datasets/ai_ml_security.txt"
    while read -r presentation; do
        echo "=== $presentation ===" >> "$TRAINING_DIR/datasets/ai_ml_security.txt"
        cat "$TRAINING_DIR/extracted/${presentation}.txt" >> "$TRAINING_DIR/datasets/ai_ml_security.txt"
        echo -e "\n\n" >> "$TRAINING_DIR/datasets/ai_ml_security.txt"
    done < "$TRAINING_DIR/metadata/ai_ml_presentations.txt"
fi

# Show interesting statistics
echo
echo "📈 Word Frequency Analysis (excluding common words):"
cat "$TRAINING_DIR/extracted"/*.txt 2>/dev/null | \
    tr '[:upper:]' '[:lower:]' | \
    tr -cs '[:alpha:]' '\n' | \
    grep -v -E '^(the|to|and|a|of|in|is|it|for|on|with|as|at|by|an|be|this|that|from|or|which|are|was|were|been|have|has|had|do|does|did|will|would|could|should|may|might|must|can)$' | \
    grep -E '^[a-z]{3,}$' | \
    sort | uniq -c | sort -rn | head -20

# Look for security-relevant terms
echo
echo "🔐 Security Keyword Frequency:"
cat "$TRAINING_DIR/extracted"/*.txt 2>/dev/null | \
    grep -oiE '\b(exploit|vulnerability|attack|malware|backdoor|rootkit|zero-day|CVE-[0-9]{4}-[0-9]+|RCE|XSS|CSRF|SQLi|injection|overflow|bypass|privilege|escalation|payload)\b' | \
    tr '[:upper:]' '[:lower:]' | \
    sort | uniq -c | sort -rn

# Model-specific security terms
echo
echo "🧠 AI/ML Security Terms:"
cat "$TRAINING_DIR/extracted"/*.txt 2>/dev/null | \
    grep -oiE '\b(pickle|joblib|model|weights|checkpoint|safetensors|onnx|pytorch|tensorflow|keras|dataset|training|inference|poisoning|adversarial|embedding)\b' | \
    tr '[:upper:]' '[:lower:]' | \
    sort | uniq -c | sort -rn | head -15

# Assembly instruction frequency (for code execution context)
echo
echo "💾 Assembly Instructions Found:"
cat "$TRAINING_DIR/extracted"/*.txt 2>/dev/null | \
    grep -oiE '\b(mov|jmp|call|ret|push|pop|lea|add|sub|xor|and|or|cmp|test|jz|jnz|je|jne|nop|int|syscall)\b' | \
    tr '[:upper:]' '[:lower:]' | \
    sort | uniq -c | sort -rn | head -10

# Create snippets for interesting patterns
echo
echo "📝 Extracting code snippets..."
mkdir -p "$TRAINING_DIR/snippets"

# Python pickle patterns
grep -h -A2 -B2 -i "pickle\|joblib\|torch.load\|tf.keras.models.load" "$TRAINING_DIR/extracted"/*.txt 2>/dev/null > "$TRAINING_DIR/snippets/pickle_patterns.txt"

# Model loading patterns
grep -h -A2 -B2 -i "load_model\|from_pretrained\|torch.load\|joblib.load" "$TRAINING_DIR/extracted"/*.txt 2>/dev/null > "$TRAINING_DIR/snippets/model_loading.txt"

echo
echo "📁 Files created in: $TRAINING_DIR/"
ls -lah "$TRAINING_DIR/"

echo
echo "📊 Summary Statistics:"
echo "  Total PDFs processed: $(find ../defcon33/.mirror -name "*.pdf" -type f | wc -l)"
echo "  Successfully extracted: $(ls "$TRAINING_DIR/extracted"/*.txt 2>/dev/null | wc -l)"
echo "  AI/ML related: $(wc -l < "$TRAINING_DIR/metadata/ai_ml_presentations.txt" 2>/dev/null || echo 0)"
echo "  Total text size: $(du -sh "$TRAINING_DIR/extracted" 2>/dev/null | cut -f1)"