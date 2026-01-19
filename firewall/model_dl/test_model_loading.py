#!/usr/bin/env python3
"""
test_model_loading.py - Verificar que el modelo DL se puede cargar
"""

import os
import sys
import json

print("=" * 60)
print(" Test de Carga del Modelo Deep Learning")
print("=" * 60)
print()

# Verificar archivos necesarios
print("1️⃣  Verificando archivos del modelo...")
files_to_check = {
    'inference/best_model.keras': 'Modelo de red neuronal',
    'inference/label_encoder.pkl': 'Encoder de etiquetas',
    'inference/model_config.json': 'Configuración del modelo',
    'config.json': 'Configuración del servidor'
}

all_files_exist = True
for file_path, description in files_to_check.items():
    if os.path.exists(file_path):
        size = os.path.getsize(file_path) / 1024  # KB
        print(f"    {description}: {file_path} ({size:.1f} KB)")
    else:
        print(f"    {description}: {file_path} - NO ENCONTRADO")
        all_files_exist = False

if not all_files_exist:
    print("\n Faltan archivos necesarios")
    sys.exit(1)

print("\n2️⃣  Verificando dependencias...")

# TensorFlow
try:
    import tensorflow as tf
    print(f"    TensorFlow: {tf.__version__}")
except ImportError:
    print("    TensorFlow no instalado")
    print("      Instalar con: pip install tensorflow")
    sys.exit(1)

# Scapy
try:
    from scapy.all import rdpcap
    print("    Scapy: Instalado")
except ImportError:
    print("   ⚠️  Scapy no instalado (opcional para procesamiento de PCAPs)")

# Otras dependencias
try:
    import flask
    print("    Flask: Instalado")
except ImportError:
    print("    Flask no instalado")
    sys.exit(1)

print("\n3️⃣  Cargando configuración del modelo...")
try:
    with open('inference/model_config.json', 'r') as f:
        config = json.load(f)
    
    print(f"    Clases: {config['num_classes']}")
    print(f"    MAX_LEN: {config['MAX_LEN']}")
    print(f"    Precisión: {config['training_info']['test_accuracy']:.2%}")
    print(f"    F1 Score: {config['training_info']['f1_macro']:.2%}")
    
    print("\n   Clases soportadas:")
    for i, class_name in enumerate(config['class_names'], 1):
        print(f"      {i:2d}. {class_name}")
    
except Exception as e:
    print(f"    Error cargando configuración: {e}")
    sys.exit(1)

print("\n4️⃣  Cargando modelo de red neuronal...")
try:
    from tensorflow import keras
    model = keras.models.load_model('inference/best_model.keras')
    print(f"    Modelo cargado exitosamente")
    print(f"   ℹ️  Input shape: {model.input_shape}")
    print(f"   ℹ️  Output shape: {model.output_shape}")
    print(f"   ℹ️  Parámetros totales: {model.count_params():,}")
except Exception as e:
    print(f"    Error cargando modelo: {e}")
    sys.exit(1)

print("\n5️⃣  Cargando label encoder...")
try:
    import pickle
    with open('inference/label_encoder.pkl', 'rb') as f:
        encoder = pickle.load(f)
    
    if hasattr(encoder, 'classes_'):
        print(f"    Encoder cargado: {len(encoder.classes_)} clases")
    else:
        print("    Encoder cargado")
except Exception as e:
    print(f"    Error cargando encoder: {e}")
    sys.exit(1)

print("\n" + "=" * 60)
print(" TODOS LOS TESTS PASARON")
print("=" * 60)
print()
print("El modelo está listo para ejecutarse:")
print("   python3 model_server.py")
print()
print("O usando el sistema completo:")
print("   echo 'MODEL_TYPE=dl_packets' >> ../.env")
print("   sudo ../quick_start.sh")
print()
