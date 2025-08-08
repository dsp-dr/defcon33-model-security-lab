#!/usr/bin/env python3
"""
Experiment 004: Model Poisoning Detector
Detects potential poisoning/backdoors in ML models through statistical analysis
"""

import numpy as np
import json
import os
import sys
from typing import Dict, List, Tuple, Any
from datetime import datetime
import hashlib

class PoisonDetector:
    """Detects potential model poisoning through weight analysis"""
    
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'models_analyzed': 0,
            'suspicious_models': [],
            'clean_models': [],
            'findings': []
        }
    
    def analyze_weights(self, weights: np.ndarray, layer_name: str = "unknown") -> Dict[str, Any]:
        """Analyze weight distribution for anomalies"""
        
        analysis = {
            'layer': layer_name,
            'shape': weights.shape,
            'total_params': weights.size,
            'statistics': {},
            'anomalies': []
        }
        
        # Calculate statistics
        analysis['statistics'] = {
            'mean': float(np.mean(weights)),
            'std': float(np.std(weights)),
            'min': float(np.min(weights)),
            'max': float(np.max(weights)),
            'median': float(np.median(weights)),
            'zeros': int(np.sum(weights == 0)),
            'sparsity': float(np.sum(weights == 0) / weights.size)
        }
        
        # Check for anomalies
        self._check_statistical_anomalies(weights, analysis)
        self._check_pattern_anomalies(weights, analysis)
        self._check_outliers(weights, analysis)
        
        return analysis
    
    def _check_statistical_anomalies(self, weights: np.ndarray, analysis: Dict):
        """Check for statistical anomalies in weight distribution"""
        
        stats = analysis['statistics']
        
        # Check for unusual distributions
        if stats['std'] < 0.001:
            analysis['anomalies'].append({
                'type': 'low_variance',
                'severity': 'MEDIUM',
                'description': f"Unusually low variance: {stats['std']:.6f}"
            })
        
        if abs(stats['mean']) > 10:
            analysis['anomalies'].append({
                'type': 'extreme_mean',
                'severity': 'HIGH',
                'description': f"Extreme mean value: {stats['mean']:.2f}"
            })
        
        if stats['sparsity'] > 0.99:
            analysis['anomalies'].append({
                'type': 'excessive_sparsity',
                'severity': 'MEDIUM',
                'description': f"Excessive sparsity: {stats['sparsity']*100:.1f}%"
            })
    
    def _check_pattern_anomalies(self, weights: np.ndarray, analysis: Dict):
        """Check for suspicious patterns in weights"""
        
        # Check for repeated values
        unique_ratio = len(np.unique(weights)) / weights.size
        if unique_ratio < 0.1:
            analysis['anomalies'].append({
                'type': 'repeated_values',
                'severity': 'HIGH',
                'description': f"Low unique value ratio: {unique_ratio:.3f}"
            })
        
        # Check for periodic patterns (potential backdoor signature)
        if weights.ndim == 2 and weights.shape[0] > 10:
            # Simple FFT-based periodicity check
            try:
                fft = np.fft.fft2(weights)
                power = np.abs(fft) ** 2
                # Check for dominant frequencies
                threshold = np.mean(power) + 3 * np.std(power)
                if np.sum(power > threshold) > 0.1 * power.size:
                    analysis['anomalies'].append({
                        'type': 'periodic_pattern',
                        'severity': 'HIGH',
                        'description': "Potential periodic pattern detected"
                    })
            except:
                pass
    
    def _check_outliers(self, weights: np.ndarray, analysis: Dict):
        """Check for outlier weights that could indicate tampering"""
        
        # Z-score based outlier detection
        z_scores = np.abs((weights - np.mean(weights)) / (np.std(weights) + 1e-8))
        outliers = np.sum(z_scores > 6)
        
        if outliers > 0.01 * weights.size:
            analysis['anomalies'].append({
                'type': 'excessive_outliers',
                'severity': 'MEDIUM',
                'description': f"Excessive outliers: {outliers} weights with |z| > 6"
            })
    
    def analyze_model_file(self, filepath: str) -> Dict[str, Any]:
        """Analyze a model file for poisoning indicators"""
        
        print(f"\n🔍 Analyzing model: {filepath}")
        
        model_analysis = {
            'filepath': filepath,
            'file_size': os.path.getsize(filepath),
            'hash': self._calculate_hash(filepath),
            'format': self._detect_format(filepath),
            'layers_analyzed': [],
            'risk_level': 'LOW',
            'total_anomalies': 0
        }
        
        try:
            # Load and analyze based on format
            if filepath.endswith('.npz'):
                self._analyze_npz_model(filepath, model_analysis)
            elif filepath.endswith('.json'):
                self._analyze_json_weights(filepath, model_analysis)
            else:
                print(f"  ⚠️  Unsupported format for weight analysis")
                model_analysis['risk_level'] = 'UNKNOWN'
            
            # Calculate risk level
            total_anomalies = sum(len(layer.get('anomalies', [])) 
                                for layer in model_analysis['layers_analyzed'])
            model_analysis['total_anomalies'] = total_anomalies
            
            if total_anomalies == 0:
                model_analysis['risk_level'] = 'LOW'
                self.results['clean_models'].append(filepath)
                print(f"  ✅ Model appears clean")
            elif total_anomalies < 3:
                model_analysis['risk_level'] = 'MEDIUM'
                print(f"  ⚠️  Medium risk: {total_anomalies} anomalies found")
            else:
                model_analysis['risk_level'] = 'HIGH'
                self.results['suspicious_models'].append(filepath)
                print(f"  🚨 High risk: {total_anomalies} anomalies found")
            
        except Exception as e:
            print(f"  ❌ Error analyzing model: {e}")
            model_analysis['error'] = str(e)
        
        self.results['models_analyzed'] += 1
        self.results['findings'].append(model_analysis)
        
        return model_analysis
    
    def _calculate_hash(self, filepath: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _detect_format(self, filepath: str) -> str:
        """Detect model file format"""
        if filepath.endswith('.npz'):
            return 'numpy'
        elif filepath.endswith('.json'):
            return 'json'
        elif filepath.endswith('.pkl'):
            return 'pickle'
        elif filepath.endswith('.pt') or filepath.endswith('.pth'):
            return 'pytorch'
        else:
            return 'unknown'
    
    def _analyze_npz_model(self, filepath: str, model_analysis: Dict):
        """Analyze NumPy NPZ model file"""
        
        data = np.load(filepath)
        for key in data.files:
            weights = data[key]
            if isinstance(weights, np.ndarray):
                layer_analysis = self.analyze_weights(weights, key)
                model_analysis['layers_analyzed'].append(layer_analysis)
                
                if layer_analysis['anomalies']:
                    print(f"  Layer '{key}': {len(layer_analysis['anomalies'])} anomalies")
                    for anomaly in layer_analysis['anomalies']:
                        print(f"    - {anomaly['description']}")
    
    def _analyze_json_weights(self, filepath: str, model_analysis: Dict):
        """Analyze JSON weight file"""
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        for key, value in data.items():
            if isinstance(value, list):
                weights = np.array(value)
                layer_analysis = self.analyze_weights(weights, key)
                model_analysis['layers_analyzed'].append(layer_analysis)
                
                if layer_analysis['anomalies']:
                    print(f"  Layer '{key}': {len(layer_analysis['anomalies'])} anomalies")
    
    def generate_report(self) -> str:
        """Generate poisoning detection report"""
        
        report = []
        report.append("\n" + "="*60)
        report.append("📊 Model Poisoning Detection Report")
        report.append("="*60)
        report.append(f"Models analyzed: {self.results['models_analyzed']}")
        report.append(f"Suspicious models: {len(self.results['suspicious_models'])}")
        report.append(f"Clean models: {len(self.results['clean_models'])}")
        
        if self.results['suspicious_models']:
            report.append("\n⚠️  Suspicious Models:")
            for model in self.results['suspicious_models']:
                report.append(f"  • {model}")
                # Find anomalies
                for finding in self.results['findings']:
                    if finding['filepath'] == model:
                        report.append(f"    Total anomalies: {finding['total_anomalies']}")
        
        report.append("\n🔍 Detection Methods Used:")
        report.append("  • Statistical distribution analysis")
        report.append("  • Pattern recognition (FFT-based)")
        report.append("  • Outlier detection (Z-score)")
        report.append("  • Sparsity analysis")
        report.append("  • Repeated value detection")
        
        report.append("\n🔒 Recommendations:")
        report.append("  1. Verify model provenance and checksums")
        report.append("  2. Test models with trigger detection tools")
        report.append("  3. Monitor model behavior in production")
        report.append("  4. Implement model versioning and auditing")
        report.append("  5. Use differential testing between versions")
        
        return "\n".join(report)

def create_test_models():
    """Create test models for poisoning detection"""
    
    os.makedirs("test_poisoned_models", exist_ok=True)
    
    print("Creating test models...")
    
    # Create a normal model
    normal_weights = {
        'layer1': np.random.randn(100, 50).astype(np.float32) * 0.1,
        'layer2': np.random.randn(50, 10).astype(np.float32) * 0.1
    }
    np.savez("test_poisoned_models/normal_model.npz", **normal_weights)
    print("  ✓ Created normal_model.npz")
    
    # Create a suspicious model with anomalies
    suspicious_weights = {
        'layer1': np.random.randn(100, 50).astype(np.float32) * 0.1,
        'layer2': np.ones((50, 10), dtype=np.float32) * 100,  # Extreme values
        'backdoor': np.array([[1, 0, 1, 0, 1]] * 20)  # Repeated pattern
    }
    np.savez("test_poisoned_models/suspicious_model.npz", **suspicious_weights)
    print("  ✓ Created suspicious_model.npz")
    
    return ["test_poisoned_models/normal_model.npz", 
            "test_poisoned_models/suspicious_model.npz"]

if __name__ == "__main__":
    detector = PoisonDetector()
    
    print("🔬 Model Poisoning Detector")
    print("="*60)
    
    # Create and analyze test models
    test_models = create_test_models()
    for model_path in test_models:
        detector.analyze_model_file(model_path)
    
    # Analyze command line arguments
    if len(sys.argv) > 1:
        for model_path in sys.argv[1:]:
            if os.path.exists(model_path):
                detector.analyze_model_file(model_path)
    
    # Generate report
    print(detector.generate_report())
    
    # Save results
    with open("poisoning_detection_results.json", "w") as f:
        json.dump(detector.results, f, indent=2)
    print("\n✓ Results saved to poisoning_detection_results.json")