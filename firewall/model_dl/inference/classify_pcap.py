#!/usr/bin/env python3
"""
🎯 IoT Device Classifier - Inference Script
Clasifica dispositivos IoT a partir de archivos PCAP

Uso:
    python classify_pcap.py <archivo.pcap> [--max-pkts 100] [--threshold 0.5]
"""

import sys
import os
import argparse
import json
import pickle
import numpy as np
from collections import Counter
import tensorflow as tf
from scapy.all import rdpcap, Ether, IP

# Configuración de TensorFlow para reducir logs
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
tf.get_logger().setLevel('ERROR')

class IoTClassifier:
    """Clasificador de dispositivos IoT basado en tráfico de red"""
    
    def __init__(self, model_path, encoder_path, config_path):
        """
        Inicializa el clasificador
        
        Args:
            model_path: Ruta al modelo .keras
            encoder_path: Ruta al label_encoder.pkl
            config_path: Ruta al model_config.json
        """
        print("🔧 Inicializando clasificador...")
        
        # Cargar configuración
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
        self.MAX_LEN = self.config['MAX_LEN']
        self.class_names = self.config['class_names']
        
        # Cargar modelo
        print(f"📦 Cargando modelo: {os.path.basename(model_path)}")
        self.model = tf.keras.models.load_model(model_path)
        
        # Cargar label encoder
        with open(encoder_path, 'rb') as f:
            self.label_encoder = pickle.load(f)
        
        print(f"✅ Modelo cargado correctamente")
        print(f"📊 Clases disponibles: {len(self.class_names)}")
        print(f"🎯 Accuracy del modelo: {self.config['training_info']['test_accuracy']*100:.2f}%\n")
    
    def sanitize_packet(self, pkt):
        """
        Preprocesa un paquete para clasificación
        (Igual que en entrenamiento)
        """
        try:
            # Enmascarar direcciones MAC/IP
            if Ether in pkt:
                pkt[Ether].src = "00:00:00:00:00:00"
                pkt[Ether].dst = "00:00:00:00:00:00"
            
            if IP in pkt:
                pkt[IP].src = "0.0.0.0"
                pkt[IP].dst = "0.0.0.0"
            
            # Convertir a vector de bytes con padding
            byte_list = list(bytes(pkt))
            if len(byte_list) > self.MAX_LEN:
                return byte_list[:self.MAX_LEN]
            else:
                return byte_list + [0] * (self.MAX_LEN - len(byte_list))
        except:
            return None
    
    def classify_pcap(self, pcap_path, max_pkts=None, verbose=True):
        """
        Clasifica un archivo PCAP completo
        
        Args:
            pcap_path: Ruta al archivo PCAP
            max_pkts: Número máximo de paquetes a procesar (None = todos)
            verbose: Mostrar detalles de procesamiento
            
        Returns:
            dict: Resultados de clasificación con estadísticas
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"❌ Archivo no encontrado: {pcap_path}")
        
        if verbose:
            print(f"📄 Procesando: {os.path.basename(pcap_path)}")
            print("="*70)
        
        # Leer paquetes
        try:
            pkts = rdpcap(pcap_path, count=max_pkts)
            if verbose:
                print(f"✅ Paquetes leídos: {len(pkts)}")
        except Exception as e:
            raise RuntimeError(f"❌ Error leyendo PCAP: {e}")
        
        # Preprocesar paquetes
        X = []
        valid_pkts = 0
        
        for pkt in pkts:
            data = self.sanitize_packet(pkt)
            if data:
                X.append(data)
                valid_pkts += 1
        
        if len(X) == 0:
            return {
                'error': 'No se pudieron procesar paquetes válidos',
                'total_packets': len(pkts),
                'valid_packets': 0
            }
        
        # Convertir a formato correcto
        X = np.array(X, dtype='float32') / 255.0
        X = X.reshape(-1, self.MAX_LEN, 1)
        
        if verbose:
            print(f"✅ Paquetes válidos para clasificación: {valid_pkts}")
            print(f"🔄 Realizando predicción...")
        
        # Clasificar
        predictions = self.model.predict(X, verbose=0)
        predicted_classes = np.argmax(predictions, axis=1)
        confidences = np.max(predictions, axis=1)
        
        # Contar votos por clase
        class_votes = Counter()
        confidence_by_class = {}
        
        for pred_idx, conf in zip(predicted_classes, confidences):
            class_name = self.label_encoder.classes_[pred_idx]
            class_votes[class_name] += 1
            
            if class_name not in confidence_by_class:
                confidence_by_class[class_name] = []
            confidence_by_class[class_name].append(conf)
        
        # Calcular estadísticas
        total_votes = sum(class_votes.values())
        results = {}
        
        for class_name, votes in class_votes.most_common():
            avg_confidence = np.mean(confidence_by_class[class_name])
            percentage = (votes / total_votes) * 100
            
            results[class_name] = {
                'votes': votes,
                'percentage': percentage,
                'avg_confidence': avg_confidence,
                'min_confidence': np.min(confidence_by_class[class_name]),
                'max_confidence': np.max(confidence_by_class[class_name])
            }
        
        # Determinar clase mayoritaria
        winner = class_votes.most_common(1)[0][0]
        winner_stats = results[winner]
        
        if verbose:
            self._print_results(results, winner, total_votes)
        
        return {
            'pcap_file': os.path.basename(pcap_path),
            'total_packets': len(pkts),
            'valid_packets': valid_pkts,
            'classified_device': winner,
            'confidence': winner_stats['avg_confidence'],
            'vote_percentage': winner_stats['percentage'],
            'all_predictions': results
        }
    
    def _print_results(self, results, winner, total_votes):
        """Imprime resultados formateados"""
        print("\n" + "="*70)
        print("📊 RESULTADOS DE CLASIFICACIÓN")
        print("="*70)
        
        print(f"\n🎯 Dispositivo detectado: {winner}")
        print(f"   Confianza promedio: {results[winner]['avg_confidence']*100:.2f}%")
        print(f"   Votos: {results[winner]['votes']}/{total_votes} ({results[winner]['percentage']:.1f}%)")
        
        print(f"\n📋 Distribución de votos:")
        print(f"   {'Clase':<20} {'Votos':>8} {'%':>8} {'Confianza':>12}")
        print("   " + "-"*55)
        
        for class_name, stats in sorted(results.items(), key=lambda x: -x[1]['votes']):
            print(f"   {class_name:<20} {stats['votes']:>8} {stats['percentage']:>7.1f}% "
                  f"{stats['avg_confidence']*100:>11.1f}%")
        
        print("="*70)
    
    def classify_realtime(self, pcap_path, threshold=0.5):
        """
        Clasificación en tiempo real con umbral de confianza
        
        Args:
            pcap_path: Ruta al PCAP
            threshold: Umbral mínimo de confianza (0-1)
            
        Returns:
            str: Nombre de la clase o "Unknown" si confianza < threshold
        """
        result = self.classify_pcap(pcap_path, max_pkts=100, verbose=False)
        
        if 'error' in result:
            return "Unknown"
        
        if result['confidence'] >= threshold:
            return result['classified_device']
        else:
            return "Unknown"


def main():
    """Función principal del script"""
    parser = argparse.ArgumentParser(
        description='🎯 Clasificador de Dispositivos IoT',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('pcap_file', help='Archivo PCAP a clasificar')
    parser.add_argument('--max-pkts', type=int, default=None, 
                        help='Número máximo de paquetes a procesar (default: todos)')
    parser.add_argument('--threshold', type=float, default=0.5,
                        help='Umbral mínimo de confianza (0-1, default: 0.5)')
    parser.add_argument('--quiet', action='store_true',
                        help='Modo silencioso (solo imprime resultado final)')
    parser.add_argument('--json', action='store_true',
                        help='Salida en formato JSON')
    
    args = parser.parse_args()
    
    # Rutas de los archivos del modelo
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, "best_model.keras")
    encoder_path = os.path.join(script_dir, "label_encoder.pkl")
    config_path = os.path.join(script_dir, "model_config.json")
    
    # Verificar archivos
    for path in [model_path, encoder_path, config_path]:
        if not os.path.exists(path):
            print(f"❌ Error: Archivo no encontrado: {path}")
            sys.exit(1)
    
    # Inicializar clasificador
    classifier = IoTClassifier(model_path, encoder_path, config_path)
    
    # Clasificar
    try:
        result = classifier.classify_pcap(
            args.pcap_file, 
            max_pkts=args.max_pkts,
            verbose=not args.quiet
        )
        
        if args.json:
            import json
            print(json.dumps(result, indent=2))
        elif args.quiet:
            print(result.get('classified_device', 'Unknown'))
        
        # Retornar código de salida
        sys.exit(0 if 'classified_device' in result else 1)
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()