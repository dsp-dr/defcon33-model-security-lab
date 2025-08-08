#!/usr/bin/env python3
"""
Experiment 003: ONNX Model Security Scanner
Analyzes ONNX models for potential security issues
"""

import json
import os
import sys
import hashlib
from typing import Dict, List, Any
from datetime import datetime

class ONNXScanner:
    """Security scanner for ONNX models"""
    
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'models_scanned': 0,
            'findings': [],
            'statistics': {
                'total_custom_ops': 0,
                'suspicious_metadata': 0,
                'large_models': 0
            }
        }
        self.has_onnx = self._check_onnx_available()
    
    def _check_onnx_available(self) -> bool:
        """Check if ONNX is available"""
        try:
            import onnx
            return True
        except ImportError:
            print("⚠️  ONNX not installed. Install with: pip install onnx")
            return False
    
    def scan_onnx_model(self, model_path: str) -> Dict[str, Any]:
        """Scan an ONNX model for security issues"""
        
        print(f"\n🔍 Scanning ONNX model: {model_path}")
        
        findings = {
            'path': model_path,
            'file_size': os.path.getsize(model_path),
            'hash': self._calculate_hash(model_path),
            'issues': [],
            'risk_level': 'LOW'
        }
        
        if not self.has_onnx:
            findings['error'] = 'ONNX library not available'
            return findings
        
        try:
            import onnx
            
            # Load and check model
            model = onnx.load(model_path)
            onnx.checker.check_model(model)
            print("  ✓ Model structure is valid")
            
            # Analyze model components
            self._analyze_graph(model.graph, findings)
            self._analyze_metadata(model, findings)
            self._check_operators(model.graph, findings)
            
            # Determine risk level
            if findings['issues']:
                if any('custom' in issue.lower() for issue in findings['issues']):
                    findings['risk_level'] = 'HIGH'
                elif any('metadata' in issue.lower() for issue in findings['issues']):
                    findings['risk_level'] = 'MEDIUM'
            
        except Exception as e:
            findings['error'] = str(e)
            findings['risk_level'] = 'UNKNOWN'
            print(f"  ❌ Error scanning model: {e}")
        
        self.results['models_scanned'] += 1
        self.results['findings'].append(findings)
        
        return findings
    
    def _calculate_hash(self, filepath: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _analyze_graph(self, graph, findings: Dict):
        """Analyze ONNX graph structure"""
        
        # Count nodes and check for unusual patterns
        node_count = len(graph.node)
        print(f"  Graph has {node_count} nodes")
        
        if node_count > 10000:
            findings['issues'].append(f"Unusually large graph: {node_count} nodes")
            self.results['statistics']['large_models'] += 1
        
        # Check for suspicious node names
        suspicious_names = ['eval', 'exec', 'system', '__import__']
        for node in graph.node:
            if any(susp in node.name.lower() for susp in suspicious_names):
                findings['issues'].append(f"Suspicious node name: {node.name}")
                print(f"  ⚠️  Suspicious node name: {node.name}")
    
    def _analyze_metadata(self, model, findings: Dict):
        """Analyze model metadata for suspicious content"""
        
        if model.metadata_props:
            print(f"  Model has {len(model.metadata_props)} metadata entries")
            
            for prop in model.metadata_props:
                # Check for suspicious keys
                if any(x in prop.key.lower() for x in ['script', 'code', 'eval']):
                    findings['issues'].append(f"Suspicious metadata key: {prop.key}")
                    self.results['statistics']['suspicious_metadata'] += 1
                    print(f"  ⚠️  Suspicious metadata: {prop.key}")
                
                # Check for long values (potential embedded code)
                if len(prop.value) > 1000:
                    findings['issues'].append(f"Large metadata value in {prop.key}: {len(prop.value)} bytes")
    
    def _check_operators(self, graph, findings: Dict):
        """Check for custom or dangerous operators"""
        
        standard_ops = {
            'Conv', 'Relu', 'MaxPool', 'Add', 'MatMul', 'BatchNormalization',
            'Softmax', 'Flatten', 'Gemm', 'Reshape', 'Transpose', 'Concat'
        }
        
        custom_ops = []
        for node in graph.node:
            if node.op_type not in standard_ops:
                if node.op_type not in custom_ops:
                    custom_ops.append(node.op_type)
        
        if custom_ops:
            findings['issues'].append(f"Custom operators found: {', '.join(custom_ops)}")
            self.results['statistics']['total_custom_ops'] += len(custom_ops)
            print(f"  ⚠️  Custom operators: {custom_ops}")
    
    def generate_report(self) -> str:
        """Generate security analysis report"""
        
        report = []
        report.append("\n" + "="*60)
        report.append("📊 ONNX Security Analysis Report")
        report.append("="*60)
        report.append(f"Models scanned: {self.results['models_scanned']}")
        report.append(f"Custom operators found: {self.results['statistics']['total_custom_ops']}")
        report.append(f"Suspicious metadata: {self.results['statistics']['suspicious_metadata']}")
        
        # Risk summary
        risk_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        for finding in self.results['findings']:
            risk_counts[finding['risk_level']] += 1
        
        report.append("\n🎯 Risk Assessment:")
        for level, count in risk_counts.items():
            if count > 0:
                report.append(f"  {level}: {count} models")
        
        # Detailed findings
        if any(f['issues'] for f in self.results['findings']):
            report.append("\n⚠️  Issues Found:")
            for finding in self.results['findings']:
                if finding['issues']:
                    report.append(f"\n  {finding['path']}:")
                    for issue in finding['issues']:
                        report.append(f"    • {issue}")
        
        report.append("\n🔒 Security Recommendations:")
        report.append("  1. Verify model checksums before deployment")
        report.append("  2. Validate all custom operators")
        report.append("  3. Sanitize metadata before loading")
        report.append("  4. Use ONNX checker before deployment")
        report.append("  5. Run models in sandboxed environments")
        
        return "\n".join(report)

def create_test_onnx_model():
    """Create a simple ONNX model for testing"""
    
    try:
        import onnx
        from onnx import helper, TensorProto
        
        os.makedirs("test_onnx_models", exist_ok=True)
        
        # Create a simple model
        input_tensor = helper.make_tensor_value_info(
            'input', TensorProto.FLOAT, [1, 3, 224, 224]
        )
        output_tensor = helper.make_tensor_value_info(
            'output', TensorProto.FLOAT, [1, 1000]
        )
        
        # Create a simple conv node
        conv_node = helper.make_node(
            'Conv',
            inputs=['input', 'conv_weight'],
            outputs=['conv_output'],
            kernel_shape=[3, 3],
            strides=[1, 1]
        )
        
        # Create graph
        graph = helper.make_graph(
            [conv_node],
            'test_model',
            [input_tensor],
            [output_tensor]
        )
        
        # Create model with metadata
        model = helper.make_model(graph)
        model.metadata_props.append(
            helper.make_model_props('producer', 'security_test')
        )
        model.metadata_props.append(
            helper.make_model_props('version', '1.0')
        )
        
        # Save model
        model_path = "test_onnx_models/test_model.onnx"
        onnx.save(model, model_path)
        print(f"✓ Created test ONNX model: {model_path}")
        
        return model_path
        
    except ImportError:
        print("⚠️  ONNX not installed. Skipping test model creation.")
        return None

if __name__ == "__main__":
    scanner = ONNXScanner()
    
    print("🔬 ONNX Security Scanner")
    print("="*60)
    
    # Create and scan test model
    test_model = create_test_onnx_model()
    if test_model:
        scanner.scan_onnx_model(test_model)
    
    # Scan command line arguments
    if len(sys.argv) > 1:
        for model_path in sys.argv[1:]:
            if os.path.exists(model_path):
                scanner.scan_onnx_model(model_path)
    
    # Generate report
    print(scanner.generate_report())
    
    # Save results
    with open("onnx_scan_results.json", "w") as f:
        json.dump(scanner.results, f, indent=2)
    print("\n✓ Results saved to onnx_scan_results.json")