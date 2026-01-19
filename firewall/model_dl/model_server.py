#!/usr/bin/env python3
"""
model_server.py - Servidor de modelo Deep Learning (LSTM/CNN)
Recibe paquetes de red (PCAPs) y clasifica dispositivos IoT usando redes neuronales.
"""

from flask import Flask, request, jsonify, render_template_string
import requests
import logging
import time
from datetime import datetime
import pickle
import numpy as np
import os
import json
from io import BytesIO

# TensorFlow/Keras
try:
    import tensorflow as tf
    from tensorflow import keras
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    logging.warning("TensorFlow no disponible")

# Scapy para procesar PCAPs
try:
    from scapy.all import rdpcap, Raw, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy no disponible")

# Configuración
app = Flask(__name__)

# Configuración del firewall
FIREWALL_PORT = os.getenv('FIREWALL_PORT', '5000')
FIREWALL_URL = f'http://localhost:{FIREWALL_PORT}'

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Paths del modelo
MODEL_PATH = 'inference/best_model.keras'
ENCODER_PATH = 'inference/label_encoder.pkl'
CONFIG_PATH = 'inference/model_config.json'

# Variables globales
model = None
label_encoder = None
model_config = None
CATEGORIES = []
MAX_LEN = 500  # Máximo número de paquetes por secuencia

def load_model():
    """Cargar el modelo de Deep Learning y el encoder desde disco"""
    global model, label_encoder, model_config, CATEGORIES, MAX_LEN
    
    try:
        if not TENSORFLOW_AVAILABLE:
            logger.error("TensorFlow no está disponible. Instala con: pip install tensorflow")
            return False
        
        # Cargar configuración
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r') as f:
                model_config = json.load(f)
                CATEGORIES = model_config.get('class_names', [])
                MAX_LEN = model_config.get('MAX_LEN', 500)
                logger.info(f"✅ Configuración cargada: {len(CATEGORIES)} clases, MAX_LEN={MAX_LEN}")
        else:
            logger.warning(f"Archivo de configuración no encontrado: {CONFIG_PATH}")
        
        # Cargar modelo
        if not os.path.exists(MODEL_PATH):
            logger.error(f"No se encuentra el modelo: {MODEL_PATH}")
            return False
        
        model = keras.models.load_model(MODEL_PATH)
        logger.info(f"✅ Modelo DL cargado exitosamente")
        logger.info(f"   Arquitectura: {model.summary()}")
        
        # Cargar encoder
        if not os.path.exists(ENCODER_PATH):
            logger.error(f"No se encuentra el encoder: {ENCODER_PATH}")
            return False
        
        with open(ENCODER_PATH, 'rb') as f:
            label_encoder = pickle.load(f)
        
        # Verificar categorías del encoder
        if hasattr(label_encoder, 'classes_'):
            CATEGORIES = label_encoder.classes_.tolist()
        
        logger.info(f"✅ Label encoder cargado")
        logger.info(f"   Clases: {CATEGORIES}")
        
        return True
    
    except Exception as e:
        logger.error(f"Error cargando modelo: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

# Estadísticas
stats = {
    'pcap_received': 0,
    'packets_processed': 0,
    'predictions_made': 0,
    'firewall_updates': 0,
    'last_pcap': None,
    'last_prediction': None,
    'last_firewall_update': None
}

# Buffer para almacenar predicciones recientes
recent_predictions = []
MAX_RECENT = 50

# Mapeo de categorías a tipos de amenaza para el firewall
# 17 categorías específicas del modelo DL granular
CATEGORY_TO_THREAT = {
    # Asistentes de voz
    'Alexa': 'Alexa',
    'GoogleHome': 'GoogleHome',
    'HomePod': 'HomePod',
    'SmartSpeaker': 'SmartSpeaker',
    
    # Cámaras
    'SecurityCamera': 'SecurityCamera',
    'IndoorCamera': 'IndoorCamera',
    'MonitorCamera': 'MonitorCamera',
    
    # Sensores
    'MotionSensor': 'MotionSensor',
    'EnvironmentalSensor': 'EnvironmentalSensor',
    'HealthSensor': 'HealthSensor',
    
    # Iluminación y control
    'SmartBulb': 'SmartBulb',
    'SmartPlug': 'SmartPlug',
    'SmartSwitch': 'SmartSwitch',
    
    # Seguridad
    'SmartLock': 'SmartLock',
    
    # Hubs y otros
    'Hub': 'Hub',
    'Printer': 'Printer',
    'Other': 'unknown_device'
}

def get_threat_type(category):
    """Obtener tipo de amenaza para una categoría, con fallback"""
    return CATEGORY_TO_THREAT.get(category, 'unknown_device')

# Diccionario para rastrear predicciones por dispositivo IP
device_predictions = {}

# Red local detectada dinámicamente
local_network = None

def detect_local_network():
    """Detectar la red local dinámicamente"""
    global local_network
    try:
        import netifaces
        import ipaddress
        
        private_networks = []
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr_info in addrs[netifaces.AF_INET]:
                    ip = addr_info.get('addr', '')
                    netmask = addr_info.get('netmask', '')
                    
                    if ip.startswith('127.'):
                        continue
                    
                    if ip.startswith('192.168.') or ip.startswith('10.') or \
                       (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31):
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        private_networks.append((interface, ip, str(network)))
        
        # Priorizar redes 192.168.50.x
        for iface, ip, network in private_networks:
            if '192.168.50.' in network:
                local_network = network
                logger.info(f"Red local detectada (AP): {local_network} en interfaz {iface}")
                return local_network
        
        if private_networks:
            iface, ip, network = private_networks[0]
            local_network = network
            logger.info(f"Red local detectada: {local_network} en interfaz {iface}")
            return local_network
        
    except Exception as e:
        logger.warning(f"No se pudo detectar la red local: {e}")
    
    local_network = '192.168.50.0/24'
    logger.info(f"Usando red local por defecto: {local_network}")
    return local_network

def is_local_ip(ip):
    """Verificar si una IP pertenece a la red local"""
    global local_network
    
    if local_network is None:
        detect_local_network()
    
    try:
        import ipaddress
        ip_obj = ipaddress.IPv4Address(ip)
        network_obj = ipaddress.IPv4Network(local_network, strict=False)
        return ip_obj in network_obj
    except Exception as e:
        logger.warning(f"Error validando IP local {ip}: {e}")
        return False

def is_valid_ip(ip):
    """Verificar si una IP es válida"""
    if not ip or ip == '0.0.0.0':
        return False
    
    try:
        import ipaddress
        if local_network:
            network_obj = ipaddress.IPv4Network(local_network, strict=False)
            gateway_ip = str(network_obj.network_address + 1)
            if ip == gateway_ip:
                return False
    except:
        if ip.endswith('.1'):
            return False
    
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(part) <= 255 for part in parts)
    except:
        return False

def update_device_prediction(ip, category):
    """Actualizar predicción para un dispositivo y enviar al firewall si es necesario"""
    global device_predictions
    
    if ip not in device_predictions:
        device_predictions[ip] = {}
    
    # Incrementar contador para esta categoría
    if category not in device_predictions[ip]:
        device_predictions[ip][category] = 0
    device_predictions[ip][category] += 1
    
    # Obtener categoría mayoritaria
    majority_category = max(device_predictions[ip], key=device_predictions[ip].get)
    confidence = device_predictions[ip][majority_category]
    
    # Enviar al firewall solo si tenemos suficiente confianza (3+ predicciones)
    if confidence >= 3:
        threat_type = get_threat_type(majority_category)
        success = update_firewall_all()
        
        if success:
            # Resetear contador para no enviar continuamente
            device_predictions[ip] = {majority_category: 1}

def update_firewall_all():
    """Enviar todas las clasificaciones de dispositivos al firewall agrupadas por categoría"""
    try:
        # Agrupar dispositivos por threat_type (categoría de bloqueo)
        categories = {}
        
        for ip, pred_counts in device_predictions.items():
            if pred_counts:
                # Obtener la categoría mayoritaria para este dispositivo
                majority_class = max(pred_counts, key=pred_counts.get)
                confidence = pred_counts[majority_class]
                
                # Solo incluir dispositivos con confianza >= 3
                if confidence >= 3:
                    threat_type = get_threat_type(majority_class)
                    
                    if threat_type not in categories:
                        categories[threat_type] = []
                    
                    # Añadir IP si no está ya en la lista
                    if ip not in categories[threat_type]:
                        categories[threat_type].append(ip)
        
        # Si no hay dispositivos clasificados, no enviar nada
        if not categories:
            return False
        
        # Enviar al firewall con el formato correcto
        data = {
            'categories': categories
        }
        
        response = requests.post(
            f'{FIREWALL_URL}/update_categories',
            json=data,
            timeout=2
        )
        
        if response.status_code == 200:
            stats['firewall_updates'] += 1
            stats['last_firewall_update'] = datetime.now().isoformat()
            total_ips = sum(len(ips) for ips in categories.values())
            logger.info(f"✅ Firewall actualizado: {len(categories)} categorías, {total_ips} dispositivos")
            for cat, ips in categories.items():
                logger.info(f"   - {cat}: {', '.join(ips)}")
            return True
        else:
            logger.warning(f"Error actualizando firewall: {response.status_code}")
            return False
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error conectando al firewall: {e}")
        return False
    except Exception as e:
        logger.error(f"Error inesperado: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

def sanitize_packet(pkt):
    """Limpia y normaliza un paquete a vector de bytes de longitud fija.
    
    CRÍTICO: Esta función DEBE ser IDÉNTICA a la usada durante el entrenamiento.
    Convierte cada paquete a un array de bytes de longitud MAX_LEN.
    
    Args:
        pkt: Paquete Scapy
        
    Returns:
        list: Vector de bytes de longitud MAX_LEN (padding con ceros si es necesario)
    """
    try:
        from scapy.all import Ether
        
        # Enmascarar datos de identidad (IP/MAC) - opcional para privacidad
        if Ether in pkt:
            pkt[Ether].src = "00:00:00:00:00:00"
            pkt[Ether].dst = "00:00:00:00:00:00"
        
        if IP in pkt:
            pkt[IP].src = "0.0.0.0"
            pkt[IP].dst = "0.0.0.0"
        
        # Convertir paquete completo a bytes
        byte_list = list(bytes(pkt))
        
        # Ajustar a longitud fija MAX_LEN
        if len(byte_list) > MAX_LEN:
            return byte_list[:MAX_LEN]  # Truncar si es más largo
        else:
            return byte_list + [0] * (MAX_LEN - len(byte_list))  # Padding con ceros
    except Exception as e:
        logger.debug(f"Error sanitizando paquete: {e}")
        return [0] * MAX_LEN  # Vector de ceros por defecto

def process_pcap_to_sequences(pcap_data):
    """Procesar datos PCAP y convertir a secuencias para el modelo
    
    Args:
        pcap_data: Datos binarios del archivo PCAP
        
    Returns:
        Dict con IP de origen -> secuencia de features
    """
    if not SCAPY_AVAILABLE:
        logger.error("Scapy no disponible para procesar PCAP")
        return {}
    
    try:
        # Guardar temporalmente el PCAP
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
            tmp.write(pcap_data)
            tmp_path = tmp.name
        
        # Leer PCAP con scapy
        packets = rdpcap(tmp_path)
        os.unlink(tmp_path)
        
        logger.info(f"PCAP procesado: {len(packets)} paquetes")
        
        # Agrupar paquetes por IP de origen
        ip_sequences = {}
        
        for packet in packets:
            if IP in packet:
                src_ip = packet[IP].src
                
                # Verificar que sea IP válida y local
                if not is_valid_ip(src_ip) or not is_local_ip(src_ip):
                    continue
                
                # Sanitizar paquete a vector de bytes de longitud fija
                pkt_bytes = sanitize_packet(packet)
                
                # Agregar a la secuencia de esta IP
                if src_ip not in ip_sequences:
                    ip_sequences[src_ip] = []
                
                ip_sequences[src_ip].append(pkt_bytes)
        
        logger.info(f"Dispositivos encontrados: {len(ip_sequences)}")
        stats['packets_processed'] += len(packets)
        
        return ip_sequences
    
    except Exception as e:
        logger.error(f"Error procesando PCAP: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {}

def preprocess_for_inference(packets_raw):
    """Preprocesa paquetes para inferencia.
    
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
    
    # Paso 2: Normalizar (0-255) → (0-1) - OBLIGATORIO
    packets_normalized = packets_float / 255.0
    
    # Paso 3: Añadir dimensión para CNN: (N, 500) → (N, 500, 1) - OBLIGATORIO
    packets_shaped = np.expand_dims(packets_normalized, axis=-1)
    
    return packets_shaped

def predict_from_sequences(ip_sequences):
    """Realizar predicciones desde secuencias de paquetes
    
    Args:
        ip_sequences: Dict de IP -> lista de features de paquetes
        
    Returns:
        Número de predicciones realizadas
    """
    global model, label_encoder, recent_predictions
    
    if model is None or label_encoder is None:
        logger.error("Modelo no cargado")
        return 0
    
    try:
        prediction_count = 0
        
        for src_ip, sequence in ip_sequences.items():
            if len(sequence) == 0:
                continue
            
            # Convertir lista de vectores de bytes a array numpy
            # Shape: (num_packets, MAX_LEN) con valores 0-255
            packets_array = np.array(sequence, dtype=np.uint8)
            
            # Limitar a 1 paquete por dispositivo (o tomar promedio/primero)
            # El modelo espera 1 secuencia de 500 bytes por predicción
            if len(packets_array) > 0:
                # Tomar el primer paquete como representativo
                single_packet = packets_array[0:1]  # Shape: (1, 500)
            else:
                continue
            
            # Aplicar preprocesamiento (normalización y reshape)
            # Input: (1, 500) → Output: (1, 500, 1) normalizado
            X = preprocess_for_inference(single_packet)
            
            # Predecir
            predictions_proba = model.predict(X, verbose=0)
            predicted_class_idx = np.argmax(predictions_proba[0])
            confidence = predictions_proba[0][predicted_class_idx]
            
            # Decodificar categoría
            if hasattr(label_encoder, 'classes_'):
                category = label_encoder.classes_[predicted_class_idx]
            else:
                category = CATEGORIES[predicted_class_idx] if predicted_class_idx < len(CATEGORIES) else 'Unknown'
            
            # Guardar predicción
            prediction_info = {
                'ip': src_ip,
                'category': category,
                'confidence': float(confidence),
                'packets': len(sequence),
                'timestamp': datetime.now().isoformat()
            }
            
            recent_predictions.append(prediction_info)
            if len(recent_predictions) > MAX_RECENT:
                recent_predictions = recent_predictions[-MAX_RECENT:]
            
            # Actualizar dispositivo
            update_device_prediction(src_ip, category)
            prediction_count += 1
            
            logger.info(f"Predicción: {src_ip} -> {category} (confianza: {confidence:.2%}, {len(sequence)} pkts)")
        
        stats['predictions_made'] += prediction_count
        stats['last_prediction'] = datetime.now().isoformat()
        
        return prediction_count
    
    except Exception as e:
        logger.error(f"Error en predicción: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return 0

# ==================== ENDPOINTS ====================

@app.route('/health', methods=['GET'])
def health():
    """Endpoint de health check"""
    model_status = 'loaded' if model is not None else 'not_loaded'
    
    return jsonify({
        'status': 'ok',
        'model_status': model_status,
        'model_type': 'deep_learning',
        'model_classes': CATEGORIES,
        'max_len': MAX_LEN,
        'tensorflow_available': TENSORFLOW_AVAILABLE,
        'scapy_available': SCAPY_AVAILABLE,
        'timestamp': datetime.now().isoformat(),
        'stats': stats
    })

@app.route('/pcap', methods=['POST'])
def receive_pcap():
    """Recibir archivo PCAP del sistema de captura y clasificar dispositivos"""
    global recent_predictions
    
    if 'file' not in request.files:
        logger.warning("No se recibió archivo PCAP")
        return jsonify({'error': 'No file provided'}), 400
    
    if model is None:
        logger.error("Modelo no cargado")
        return jsonify({'error': 'Model not loaded'}), 500
    
    pcap_file = request.files['file']
    logger.info(f"📦 PCAP recibido: {pcap_file.filename}")
    
    # Actualizar estadísticas
    stats['pcap_received'] += 1
    stats['last_pcap'] = datetime.now().isoformat()
    
    try:
        # Leer contenido del PCAP
        pcap_data = pcap_file.read()
        
        # Procesar PCAP y extraer secuencias por dispositivo
        ip_sequences = process_pcap_to_sequences(pcap_data)
        
        if not ip_sequences:
            logger.info("No se encontraron dispositivos IoT en el PCAP")
            return jsonify({
                'status': 'processed',
                'message': 'No IoT devices found in PCAP',
                'filename': pcap_file.filename,
                'predictions_count': 0
            }), 200
        
        # Realizar predicciones
        prediction_count = predict_from_sequences(ip_sequences)
        
        logger.info(f"✅ PCAP procesado: {prediction_count} predicciones realizadas")
        
        return jsonify({
            'status': 'processed',
            'message': f'{prediction_count} devices classified',
            'filename': pcap_file.filename,
            'predictions_count': prediction_count,
            'devices': list(ip_sequences.keys())
        }), 200
    
    except Exception as e:
        logger.error(f"Error procesando PCAP: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/flows', methods=['POST'])
def receive_flows():
    """Endpoint de compatibilidad (el modelo DL no usa flows, usa PCAPs)"""
    logger.info("Endpoint /flows llamado, pero modelo DL requiere PCAPs")
    return jsonify({
        'status': 'info',
        'message': 'This Deep Learning model requires PCAP files, not flows. Use /pcap endpoint instead.',
        'model_type': 'deep_learning'
    }), 200

@app.route('/stats', methods=['GET'])
def get_stats():
    """Obtener estadísticas del modelo"""
    return jsonify({
        'stats': stats,
        'model_info': {
            'type': 'deep_learning',
            'classes': CATEGORIES,
            'max_sequence_length': MAX_LEN,
            'model_config': model_config
        },
        'devices': {
            ip: {
                'predictions': pred_counts,
                'majority_class': max(pred_counts, key=pred_counts.get) if pred_counts else None
            }
            for ip, pred_counts in device_predictions.items()
        },
        'recent_predictions': recent_predictions[-10:],  # Últimas 10
        'local_network': local_network,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/predictions', methods=['GET'])
def get_predictions():
    """Obtener predicciones recientes"""
    return jsonify({
        'predictions': recent_predictions,
        'count': len(recent_predictions),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/devices', methods=['GET'])
def get_devices():
    """Obtener dispositivos detectados"""
    devices_list = []
    
    for ip, pred_counts in device_predictions.items():
        if pred_counts:
            majority_class = max(pred_counts, key=pred_counts.get)
            confidence = pred_counts[majority_class]
            
            devices_list.append({
                'ip': ip,
                'device_type': majority_class,
                'confidence': confidence,
                'predictions': pred_counts,
                'threat_type': get_threat_type(majority_class)
            })
    
    return jsonify({
        'devices': devices_list,
        'count': len(devices_list),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/reset', methods=['POST'])
def reset_metrics():
    """Resetear todas las métricas y estadísticas"""
    global stats, recent_predictions, device_predictions
    
    logger.info("🔄 Reseteando métricas del modelo...")
    
    # Resetear estadísticas
    stats['pcap_received'] = 0
    stats['packets_processed'] = 0
    stats['predictions_made'] = 0
    stats['firewall_updates'] = 0
    stats['last_pcap'] = None
    stats['last_prediction'] = None
    stats['last_firewall_update'] = None
    
    # Limpiar buffers
    recent_predictions = []
    device_predictions = {}
    
    logger.info("✅ Métricas reseteadas correctamente")
    
    return jsonify({
        'status': 'ok',
        'message': 'Métricas reseteadas correctamente',
        'timestamp': datetime.now().isoformat()
    })

# ==================== DASHBOARD HTML ====================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Deep Learning Model Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { text-align: center; margin-bottom: 30px; font-size: 2.5em; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .info { background: rgba(255,255,255,0.1); padding: 15px; border-radius: 10px; margin-bottom: 20px; backdrop-filter: blur(10px); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .card {
            background: rgba(255,255,255,0.15);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.18);
        }
        .card h2 { font-size: 1.2em; margin-bottom: 15px; color: #fff; }
        .stat { font-size: 2.5em; font-weight: bold; color: #4ade80; text-align: center; margin: 10px 0; }
        .device-list { max-height: 400px; overflow-y: auto; }
        .device {
            background: rgba(255,255,255,0.1);
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 8px;
            border-left: 4px solid #4ade80;
        }
        .device strong { color: #4ade80; }
        .predictions-list { max-height: 300px; overflow-y: auto; }
        .prediction {
            background: rgba(255,255,255,0.08);
            padding: 8px;
            margin-bottom: 8px;
            border-radius: 6px;
            font-size: 0.9em;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            margin: 2px;
            background: rgba(74, 222, 128, 0.3);
        }
        button {
            background: rgba(255,255,255,0.2);
            border: 1px solid rgba(255,255,255,0.3);
            color: white;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            margin: 5px;
            transition: all 0.3s;
        }
        button:hover { background: rgba(255,255,255,0.3); transform: translateY(-2px); }
        .status-ok { color: #4ade80; }
        .status-error { color: #f87171; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🧠 Deep Learning IoT Classifier</h1>
        
        <div class="info">
            <p><strong>Estado del Modelo:</strong> <span id="modelStatus" class="status-ok">Cargando...</span></p>
            <p><strong>Tipo:</strong> Deep Learning (LSTM/CNN)</p>
            <p><strong>Clases:</strong> <span id="modelClasses">-</span></p>
            <p><strong>Red Local:</strong> <span id="localNetwork">-</span></p>
        </div>
        
        <div class="grid">
            <div class="card">
                <h2>📊 Estadísticas</h2>
                <div class="stat" id="pcapCount">0</div>
                <p style="text-align: center;">PCAPs Recibidos</p>
                <hr style="margin: 15px 0; border: 0; border-top: 1px solid rgba(255,255,255,0.2);">
                <div class="stat" id="predCount" style="font-size: 2em;">0</div>
                <p style="text-align: center;">Predicciones Realizadas</p>
            </div>
            
            <div class="card">
                <h2>🔥 Actualizaciones Firewall</h2>
                <div class="stat" id="firewallCount">0</div>
                <p style="text-align: center;">Reglas Actualizadas</p>
                <hr style="margin: 15px 0; border: 0; border-top: 1px solid rgba(255,255,255,0.2);">
                <p><strong>Última actualización:</strong></p>
                <p id="lastUpdate" style="font-size: 0.9em;">-</p>
            </div>
            
            <div class="card">
                <h2>📦 Paquetes Procesados</h2>
                <div class="stat" id="packetCount">0</div>
                <p style="text-align: center;">Paquetes Analizados</p>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h2>🖥️ Dispositivos Detectados (<span id="deviceCount">0</span>)</h2>
                <div class="device-list" id="deviceList">
                    <p style="opacity: 0.6;">No hay dispositivos detectados aún...</p>
                </div>
            </div>
            
            <div class="card">
                <h2>🎯 Predicciones Recientes</h2>
                <div class="predictions-list" id="predictionsList">
                    <p style="opacity: 0.6;">No hay predicciones aún...</p>
                </div>
            </div>
        </div>
        
        <div style="text-align: center; margin-top: 20px;">
            <button onclick="loadData()">🔄 Actualizar</button>
            <button onclick="window.location.href='/stats'">📈 Ver JSON Stats</button>
            <button onclick="resetMetrics()" style="background: rgba(248, 113, 113, 0.3); border-color: rgba(248, 113, 113, 0.5);">🗑️ Limpiar Métricas</button>
        </div>
    </div>
    
    <script>
        async function loadData() {
            try {
                // Cargar stats
                const statsRes = await fetch('/stats');
                const stats = await statsRes.json();
                
                // Actualizar estadísticas
                document.getElementById('pcapCount').textContent = stats.stats.pcap_received || 0;
                document.getElementById('predCount').textContent = stats.stats.predictions_made || 0;
                document.getElementById('firewallCount').textContent = stats.stats.firewall_updates || 0;
                document.getElementById('packetCount').textContent = stats.stats.packets_processed || 0;
                
                const lastUpdate = stats.stats.last_firewall_update;
                document.getElementById('lastUpdate').textContent = lastUpdate ? 
                    new Date(lastUpdate).toLocaleString() : 'Nunca';
                
                // Actualizar info del modelo
                document.getElementById('modelClasses').textContent = 
                    stats.model_info.classes.length + ' categorías';
                document.getElementById('localNetwork').textContent = stats.local_network || 'Detectando...';
                
                // Cargar dispositivos
                const devicesRes = await fetch('/devices');
                const devicesData = await devicesRes.json();
                
                const deviceList = document.getElementById('deviceList');
                const deviceCount = document.getElementById('deviceCount');
                
                if (devicesData.devices.length === 0) {
                    deviceList.innerHTML = '<p style="opacity: 0.6;">No hay dispositivos detectados aún...</p>';
                    deviceCount.textContent = '0';
                } else {
                    deviceCount.textContent = devicesData.devices.length;
                    deviceList.innerHTML = devicesData.devices.map(dev => `
                        <div class="device">
                            <strong>${dev.ip}</strong><br>
                            <span class="badge">${dev.device_type}</span>
                            <span class="badge">${dev.threat_type}</span><br>
                            <small>Confianza: ${dev.confidence} predicciones</small>
                        </div>
                    `).join('');
                }
                
                // Predicciones recientes
                if (stats.recent_predictions && stats.recent_predictions.length > 0) {
                    document.getElementById('predictionsList').innerHTML = 
                        stats.recent_predictions.reverse().map(pred => `
                            <div class="prediction">
                                <strong>${pred.ip}</strong> → ${pred.category}<br>
                                <small>Confianza: ${(pred.confidence * 100).toFixed(1)}% | ${pred.packets} pkts</small>
                            </div>
                        `).join('');
                }
                
                // Verificar health
                const healthRes = await fetch('/health');
                const health = await healthRes.json();
                
                const statusEl = document.getElementById('modelStatus');
                if (health.model_status === 'loaded') {
                    statusEl.textContent = '✅ Modelo Cargado';
                    statusEl.className = 'status-ok';
                } else {
                    statusEl.textContent = '❌ Modelo No Cargado';
                    statusEl.className = 'status-error';
                }
                
            } catch (error) {
                console.error('Error loading data:', error);
            }
        }
        async function resetMetrics() {
            if (!confirm('¿Estás seguro de que quieres limpiar todas las métricas y empezar desde cero?')) {
                return;
            }
            
            try {
                const response = await fetch('/reset', { method: 'POST' });
                const result = await response.json();
                
                if (result.status === 'ok') {
                    alert('✅ Métricas limpiadas correctamente');
                    loadData();
                } else {
                    alert('❌ Error limpiando métricas');
                }
            } catch (error) {
                console.error('Error:', error);
                alert('❌ Error limpiando métricas');
            }
        }
        
        
        // Cargar datos al inicio
        loadData();
        
        // Auto-refresh cada 5 segundos
        setInterval(loadData, 5000);
    </script>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def dashboard():
    """Dashboard web principal"""
    return render_template_string(DASHBOARD_HTML)

# ==================== MAIN ====================

if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("🧠 Iniciando Servidor de Modelo Deep Learning")
    logger.info("=" * 60)
    
    # Detectar red local
    detect_local_network()
    
    # Cargar modelo
    if not load_model():
        logger.error("❌ No se pudo cargar el modelo. Saliendo...")
        exit(1)
    
    # Obtener puerto desde variables de entorno o usar 5002 por defecto
    port = int(os.getenv('MODEL_DL_PORT', '5002'))
    
    logger.info("")
    logger.info(f"🌐 Servidor iniciado en http://0.0.0.0:{port}")
    logger.info(f"📊 Dashboard: http://localhost:{port}/")
    logger.info(f"💚 Health: http://localhost:{port}/health")
    logger.info(f"📦 PCAP endpoint: POST http://localhost:{port}/pcap")
    logger.info("")
    logger.info("Listo para recibir PCAPs y clasificar dispositivos IoT...")
    logger.info("=" * 60)
    
    # Iniciar servidor Flask
    app.run(host='0.0.0.0', port=port, debug=False)
