#!/usr/bin/env python3
"""
🚀 Script de Inferencia para Clasificación de Dispositivos IoT

Este script procesa archivos PCAP y clasifica los paquetes según el dispositivo IoT que los generó.
IMPORTANTE: Replica EXACTAMENTE el preprocesamiento usado durante el entrenamiento.
"""

import os
import sys
import json
import pickle
import numpy as np
from scapy.all import rdpcap, Ether, IP
import tensorflow as tf


# ============================================================================
# CONFIGURACIÓN - DEBE COINCIDIR CON EL ENTRENAMIENTO
# ============================================================================

MAX_LEN = 500  # Longitud fija de cada paquete (en bytes)


# ============================================================================
# FUNCIONES DE PREPROCESAMIENTO - CRÍTICAS PARA LA PRECISIÓN
# ============================================================================

def sanitize_packet(pkt):
    """
    Limpia y normaliza un paquete a vector de bytes de longitud fija.
    
    IMPORTANTE: Esta función DEBE ser IDÉNTICA a la usada durante el entrenamiento.
    
    Args:
        pkt: Paquete Scapy
        
    Returns:
        list: Vector de bytes de longitud MAX_LEN (padding con ceros si es necesario)
              o None si hay error
    """
    try:
        # Enmascarar datos de identidad (IP/MAC)
        if Ether in pkt:
            pkt[Ether].src = "00:00:00:00:00:00"
            pkt[Ether].dst = "00:00:00:00:00:00"
        
        if IP in pkt:
            pkt[IP].src = "0.0.0.0"
            pkt[IP].dst = "0.0.0.0"
        
        # Convertir a bytes
        byte_list = list(bytes(pkt))
        
        # Ajustar a longitud fija
        if len(byte_list) > MAX_LEN:
            return byte_list[:MAX_LEN]  # Truncar si es más largo
        else:
            return byte_list + [0] * (MAX_LEN - len(byte_list))  # Padding con ceros
    except Exception as e:
        print(f"⚠️  Error procesando paquete: {e}")
        return None


def preprocess_for_inference(packets_raw):
    """
    Preprocesa una lista de paquetes para inferencia.
    
    CRÍTICO: Aplica las MISMAS transformaciones que durante el entrenamiento:
    1. Convertir a float32
    2. Normalizar dividiendo por 255 (escala 0-1)
    3. Añadir dimensión extra: (N, 500) → (N, 500, 1)
    
    Args:
        packets_raw: Array numpy de shape (N, 500) con valores de bytes (0-255)
        
    Returns:
        Array numpy de shape (N, 500, 1) con valores normalizados (0-1)
    """
    # Paso 1: Convertir a float32
    packets_float = packets_raw.astype('float32')
    
    # Paso 2: Normalizar (0-255) → (0-1)
    packets_normalized = packets_float / 255.0
    
    # Paso 3: Añadir dimensión para CNN: (N, 500) → (N, 500, 1)
    packets_shaped = np.expand_dims(packets_normalized, axis=-1)
    
    return packets_shaped


# ============================================================================
# CARGA DEL MODELO Y CONFIGURACIÓN
# ============================================================================

def load_model_and_config():
    """
    Carga el modelo entrenado, label encoder y configuración.
    
    Returns:
        tuple: (model, label_encoder, config)
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Cargar modelo
    model_path = os.path.join(script_dir, "best_model.keras")
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"❌ Modelo no encontrado: {model_path}")
    
    print(f"📦 Cargando modelo desde: {model_path}")
    model = tf.keras.models.load_model(model_path)
    
    # Cargar label encoder
    encoder_path = os.path.join(script_dir, "label_encoder.pkl")
    if not os.path.exists(encoder_path):
        raise FileNotFoundError(f"❌ Label encoder no encontrado: {encoder_path}")
    
    with open(encoder_path, 'rb') as f:
        label_encoder = pickle.load(f)
    
    # Cargar configuración
    config_path = os.path.join(script_dir, "model_config.json")
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"❌ Configuración no encontrada: {config_path}")
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    print(f"✅ Modelo cargado correctamente")
    print(f"   Input shape esperado: {config['model_architecture']['input_shape']}")
    print(f"   Clases detectables: {config['num_classes']}")
    
    return model, label_encoder, config


# ============================================================================
# CLASIFICACIÓN DE PCAP
# ============================================================================

def classify_pcap(pcap_path, model, label_encoder, max_packets=None):
    """
    Clasifica los paquetes de un archivo PCAP.
    
    Args:
        pcap_path: Ruta al archivo PCAP
        model: Modelo de TensorFlow cargado
        label_encoder: LabelEncoder de sklearn
        max_packets: Número máximo de paquetes a procesar (None = todos)
        
    Returns:
        dict: Resultados de la clasificación
    """
    print(f"\n📂 Procesando: {pcap_path}")
    print("="*70)
    
    # Cargar paquetes
    try:
        packets = rdpcap(pcap_path)
        print(f"✅ Cargados {len(packets)} paquetes del PCAP")
    except Exception as e:
        print(f"❌ Error cargando PCAP: {e}")
        return None
    
    # Limitar número de paquetes si se especifica
    if max_packets and len(packets) > max_packets:
        packets = packets[:max_packets]
        print(f"⚠️  Limitando a {max_packets} paquetes")
    
    # Preprocesar paquetes (PASO 1: Sanitizar)
    print(f"\n🔧 Preprocesando paquetes...")
    packets_sanitized = []
    for pkt in packets:
        sanitized = sanitize_packet(pkt)
        if sanitized is not None:
            packets_sanitized.append(sanitized)
    
    if not packets_sanitized:
        print("❌ No se pudo procesar ningún paquete")
        return None
    
    print(f"✅ {len(packets_sanitized)} paquetes preprocesados")
    
    # Convertir a numpy array: (N, 500) con valores 0-255
    X_raw = np.array(packets_sanitized, dtype=np.uint8)
    print(f"📊 Shape antes de normalización: {X_raw.shape}")
    print(f"   Rango de valores: [{X_raw.min()}, {X_raw.max()}]")
    
    # PASO 2: Aplicar preprocesamiento para inferencia
    # CRÍTICO: Normalizar y ajustar dimensiones como en entrenamiento
    X_processed = preprocess_for_inference(X_raw)
    print(f"✅ Shape después de preprocesamiento: {X_processed.shape}")
    print(f"   Rango de valores normalizados: [{X_processed.min():.3f}, {X_processed.max():.3f}]")
    
    # PASO 3: Realizar predicción
    print(f"\n🔮 Realizando predicción...")
    predictions = model.predict(X_processed, verbose=0)
    predicted_classes = np.argmax(predictions, axis=1)
    
    # Decodificar clases
    predicted_labels = label_encoder.inverse_transform(predicted_classes)
    
    # Calcular confianzas
    confidences = np.max(predictions, axis=1)
    
    # Análisis de resultados
    print(f"\n📊 RESULTADOS DE CLASIFICACIÓN")
    print("="*70)
    
    # Conteo por clase
    from collections import Counter
    class_counts = Counter(predicted_labels)
    
    print(f"\n{'Clase':<20} {'Paquetes':>10} {'Porcentaje':>12} {'Confianza Promedio':>20}")
    print("-"*70)
    
    for label, count in class_counts.most_common():
        percentage = (count / len(predicted_labels)) * 100
        # Calcular confianza promedio para esta clase
        class_mask = predicted_labels == label
        avg_confidence = confidences[class_mask].mean()
        
        print(f"{label:<20} {count:>10} {percentage:>11.2f}% {avg_confidence:>19.2%}")
    
    print("="*70)
    
    # Predicción mayoritaria
    most_common_class, most_common_count = class_counts.most_common(1)[0]
    print(f"\n🎯 Clase mayoritaria: {most_common_class}")
    print(f"   Paquetes: {most_common_count}/{len(predicted_labels)} ({most_common_count/len(predicted_labels)*100:.2f}%)")
    
    # Confianza global
    avg_confidence_global = confidences.mean()
    print(f"\n📊 Confianza promedio global: {avg_confidence_global:.2%}")
    
    # Retornar resultados
    results = {
        'pcap_path': pcap_path,
        'total_packets': len(packets_sanitized),
        'predictions': predicted_labels.tolist(),
        'confidences': confidences.tolist(),
        'class_distribution': dict(class_counts),
        'majority_class': most_common_class,
        'majority_percentage': most_common_count / len(predicted_labels),
        'average_confidence': float(avg_confidence_global)
    }
    
    return results


# ============================================================================
# FUNCIÓN MAIN
# ============================================================================

def main():
    """Función principal del script."""
    if len(sys.argv) < 2:
        print("❌ Uso: python classify_pcap.py <archivo.pcap> [max_packets]")
        print("\nEjemplo:")
        print("  python classify_pcap.py capture.pcap")
        print("  python classify_pcap.py capture.pcap 1000")
        sys.exit(1)
    
    pcap_path = sys.argv[1]
    max_packets = int(sys.argv[2]) if len(sys.argv) > 2 else None
    
    # Verificar que el archivo existe
    if not os.path.exists(pcap_path):
        print(f"❌ Archivo no encontrado: {pcap_path}")
        sys.exit(1)
    
    print("🚀 CLASIFICADOR DE DISPOSITIVOS IoT")
    print("="*70)
    
    # Cargar modelo y configuración
    try:
        model, label_encoder, config = load_model_and_config()
    except Exception as e:
        print(f"❌ Error cargando modelo: {e}")
        sys.exit(1)
    
    # Mostrar información del modelo
    print(f"\n📋 INFORMACIÓN DEL MODELO")
    print("="*70)
    print(f"Accuracy en test: {config['training_info']['test_accuracy']*100:.2f}%")
    print(f"F1-Score (macro): {config['training_info']['f1_macro']*100:.2f}%")
    print(f"Fecha de entrenamiento: {config['training_info']['training_date']}")
    print(f"\nClases detectables:")
    for i, class_name in enumerate(config['class_names'], 1):
        print(f"  {i:2d}. {class_name}")
    
    # Clasificar PCAP
    results = classify_pcap(pcap_path, model, label_encoder, max_packets)
    
    if results:
        print("\n✅ Clasificación completada exitosamente")
    else:
        print("\n❌ Error en la clasificación")
        sys.exit(1)


if __name__ == "__main__":
    main()
