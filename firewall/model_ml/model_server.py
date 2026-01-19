#!/usr/bin/env python3
"""
model_server.py - Servidor de modelo ML Real (Random Forest)
Recibe flows de tráfico de red y clasifica dispositivos IoT en categorías:
- MULTIMEDIA (Cámaras, Video, Audio)
- SMART_CONTROLS (Plugs, Lighting, Sensores de movimiento)
- SENSORS (Weather, Air Quality, Sleep)
- COMPUTING (Router, Smartphone, PC)
"""

from flask import Flask, request, jsonify, render_template_string
import requests
import logging
import time
from datetime import datetime
import joblib
import pandas as pd
import numpy as np
import os

# Configuración
app = Flask(__name__)
FIREWALL_PORT = os.getenv('FIREWALL_PORT', '5000')
# Configuración del firewall
FIREWALL_URL = f'http://localhost:{FIREWALL_PORT}'

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Cargar modelo y encoder
MODEL_PATH = 'model.pkl'
ENCODER_PATH = 'encoder.pkl'

model = None
label_encoder = None
CATEGORIES = []  # Se cargarán automáticamente del encoder

def load_model():
    """Cargar el modelo y el encoder desde disco"""
    global model, label_encoder, CATEGORIES
    
    try:
        if not os.path.exists(MODEL_PATH):
            logger.error(f"No se encuentra el modelo: {MODEL_PATH}")
            return False
        
        if not os.path.exists(ENCODER_PATH):
            logger.error(f"No se encuentra el encoder: {ENCODER_PATH}")
            return False
        
        model = joblib.load(MODEL_PATH)
        label_encoder = joblib.load(ENCODER_PATH)
        
        # Extraer categorías automáticamente del encoder
        CATEGORIES = label_encoder.classes_.tolist()
        
        logger.info(f"✅ Modelo cargado exitosamente")
        logger.info(f"   Features esperados: {model.n_features_in_}")
        logger.info(f"   Clases: {CATEGORIES}")
        
        return True
    
    except Exception as e:
        logger.error(f"Error cargando modelo: {e}")
        return False

# Estadísticas
stats = {
    'pcap_received': 0,
    'flows_received': 0,
    'predictions_made': 0,
    'firewall_updates': 0,
    'last_pcap': None,
    'last_flow': None,
    'last_prediction': None,
    'last_firewall_update': None
}

# Buffer para almacenar los últimos flows y predicciones
recent_flows = []
recent_predictions = []
MAX_RECENT = 50

# Mapeo de categorías a tipos de amenaza para el firewall
# Este mapeo se puede extender según las categorías encontradas
CATEGORY_TO_THREAT = {
    'MULTIMEDIA': 'MULTIMEDIA',
    'SMART_CONTROLS': 'SMART_CONTROLS',
    'SENSORS': 'SENSORS',
    'COMPUTING': 'COMPUTING',
    'ENVIRONMENT_SENSING': 'ENVIRONMENT_SENSING',
    'HOME_AUTOMATION': 'HOME_AUTOMATION',
    'NETWORK_CORE': 'NETWORK_CORE',
    'PERSONAL_DEVICES': 'PERSONAL_DEVICES',
    'SMART_APPLIANCES': 'SMART_APPLIANCES',
    'VIDEO_STREAMING': 'VIDEO_STREAMING'
}

def get_threat_type(category):
    """Obtener tipo de amenaza para una categoría, con fallback"""
    return CATEGORY_TO_THREAT.get(category, 'unknown_device')

# Diccionario para rastrear predicciones por dispositivo IP
# Estructura: {'192.168.1.10': {'MULTIMEDIA': 5, 'COMPUTING': 2, ...}}
device_predictions = {}

# Set para trackear flows ya procesados (evitar duplicados inmediatos)
# Los flows se agrupan en ventanas de tiempo de 60 segundos
processed_flows = set()
MAX_PROCESSED_FLOWS = 10000  # Limitar tamaño del set
last_cleanup_time = 0  # Última vez que se limpiaron flows antiguos

# Red local detectada dinámicamente
local_network = None

def create_flow_id(flow):
    """Crear un identificador único para un flow
    
    Incluye una ventana de tiempo para permitir re-clasificación periódica.
    Los flows se consideran únicos dentro de ventanas de 60 segundos.
    """
    try:
        # Usar características clave del flow para identificarlo
        src_ip = flow.get('SrcIP', flow.get('src_ip', ''))
        dst_ip = flow.get('DstIP', flow.get('dst_ip', ''))
        src_port = flow.get('SrcPort', 0)
        dst_port = flow.get('DstPort', 0)
        protocol = flow.get('Protocol', 0)
        
        # Obtener timestamp del flow o usar el actual
        # Redondear a ventanas de 60 segundos para agrupar flows similares
        import time
        timestamp = flow.get('start_time', time.time())
        if isinstance(timestamp, str):
            # Si es string, intentar parsearlo
            try:
                from datetime import datetime
                timestamp = datetime.fromisoformat(timestamp).timestamp()
            except:
                timestamp = time.time()
        
        # Redondear timestamp a ventanas de 60 segundos
        time_window = int(timestamp // 60)
        
        # Crear un hash que incluya la ventana de tiempo
        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}@{time_window}"
    except Exception as e:
        logger.warning(f"Error creando flow ID: {e}")
        return None

def is_flow_processed(flow):
    """Verificar si un flow ya fue procesado"""
    flow_id = create_flow_id(flow)
    if flow_id is None:
        return False
    return flow_id in processed_flows

def mark_flow_as_processed(flow):
    """Marcar un flow como procesado"""
    global processed_flows
    flow_id = create_flow_id(flow)
    if flow_id:
        processed_flows.add(flow_id)
        
        # Limitar el tamaño del set
        if len(processed_flows) > MAX_PROCESSED_FLOWS:
            # Eliminar los primeros 1000 elementos (los más antiguos)
            processed_flows = set(list(processed_flows)[1000:])

def cleanup_old_flows():
    """Limpiar flows procesados que son muy antiguos (más de 5 minutos)"""
    global processed_flows, last_cleanup_time
    import time
    
    current_time = time.time()
    current_window = int(current_time // 60)
    
    # Solo limpiar cada 5 minutos
    if last_cleanup_time and (current_time - last_cleanup_time) < 300:
        return
    
    last_cleanup_time = current_time
    
    # Filtrar flows que tienen ventanas de tiempo antiguas (más de 5 minutos)
    old_threshold = current_window - 5
    new_processed_flows = set()
    
    for flow_id in processed_flows:
        try:
            # Extraer la ventana de tiempo del flow_id (formato: ...@time_window)
            if '@' in flow_id:
                time_window = int(flow_id.split('@')[-1])
                if time_window >= old_threshold:
                    new_processed_flows.add(flow_id)
        except:
            # Si hay error, mantener el flow
            new_processed_flows.add(flow_id)
    
    removed = len(processed_flows) - len(new_processed_flows)
    if removed > 0:
        logger.info(f"Limpieza automática: {removed} flows antiguos eliminados del caché")
        processed_flows = new_processed_flows

def detect_local_network():
    """Detectar la red local dinámicamente desde las IPs del router"""
    global local_network
    # Fallback a red por defecto
    local_network = os.getenv('AP_NETWORK', '192.168.50.0/24')
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
    """Verificar si una IP es válida y no es 0.0.0.0 ni el router"""
    if not ip or ip == '0.0.0.0':
        return False
    
    # Filtrar IP del router/gateway (normalmente .1)
    # Detectar si es la IP del gateway de la red local
    try:
        import ipaddress
        if local_network:
            network_obj = ipaddress.IPv4Network(local_network, strict=False)
            # La IP del gateway suele ser la primera IP útil de la red (.1)
            gateway_ip = str(network_obj.network_address + 1)
            if ip == gateway_ip:
                return False
    except:
        # Si falla, usar heurística: termina en .1
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
    """Actualizar las predicciones para un dispositivo"""
    if ip not in device_predictions:
        device_predictions[ip] = {}
    
    if category not in device_predictions[ip]:
        device_predictions[ip][category] = 0
    
    device_predictions[ip][category] += 1
    
    # Verificar si debemos enviar al firewall (3+ predicciones de la misma categoría)
    majority_category = get_device_category(ip)
    if majority_category and device_predictions[ip][majority_category] >= 3:
        # Enviar actualización al firewall
        send_to_firewall()
        # Resetear contador para no enviar continuamente
        device_predictions[ip][majority_category] = 1

def get_device_category(ip):
    """Obtener la categoría principal de un dispositivo (por mayoría)"""
    if ip not in device_predictions:
        return None
    
    predictions = device_predictions[ip]
    if not predictions:
        return None
    
    # Retornar la categoría con más predicciones
    return max(predictions.items(), key=lambda x: x[1])[0]

def get_device_stats(ip):
    """Obtener estadísticas detalladas de predicciones para un dispositivo"""
    if ip not in device_predictions:
        return None
    
    predictions = device_predictions[ip]
    total = sum(predictions.values())
    
    stats_data = {
        'total_predictions': total,
        'main_category': get_device_category(ip),
        'percentages': {}
    }
    
    for category, count in predictions.items():
        stats_data['percentages'][category] = round((count / total) * 100, 2)
    
    return stats_data

def get_categories_for_firewall():
    """Obtener categorías agrupadas por dispositivos (una categoría por IP)"""
    categories = {}
    
    for ip in device_predictions:
        category = get_device_category(ip)
        if category:
            if category not in categories:
                categories[category] = []
            categories[category].append(ip)
    
    return categories

def clear_all_predictions():
    """Limpiar todas las predicciones de dispositivos"""
    global device_predictions
    device_predictions = {}
    logger.info("Todas las predicciones han sido limpiadas")
    
    # También limpiar el firewall
    try:
        response = requests.post(
            f'{FIREWALL_URL}/clear_all',
            timeout=5
        )
        if response.status_code == 200:
            logger.info("Firewall limpiado exitosamente")
        else:
            logger.warning(f"Error limpiando firewall: {response.status_code}")
    except Exception as e:
        logger.error(f"Error limpiando firewall: {e}")

def send_to_firewall():
    """Enviar categorías al firewall (basado en categoría principal de cada dispositivo)"""
    try:
        # Obtener categorías agrupadas (una por dispositivo)
        categories = get_categories_for_firewall()
        
        if not categories:
            logger.debug("No hay categorías para enviar al firewall")
            return False
        
        logger.info(f"Enviando categorías al firewall: {dict((k, len(v)) for k, v in categories.items())}")
        
        response = requests.post(
            f'{FIREWALL_URL}/update_categories',
            json={'categories': categories},
            timeout=5
        )
        
        if response.status_code == 200:
            logger.info(f"Firewall actualizado exitosamente: {response.json()}")
            stats['firewall_updates'] += 1
            stats['last_firewall_update'] = datetime.now().isoformat()
            return True
        else:
            logger.warning(f"Error actualizando firewall: {response.status_code}")
            return False
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error conectando al firewall: {e}")
        return False
    except Exception as e:
        logger.error(f"Error inesperado: {e}")
        return False

def process_flows_to_features(flows):
    """
    Convertir flows de red a features para el modelo
    
    Args:
        flows: Lista de diccionarios con información de flows
        
    Returns:
        DataFrame con las features necesarias para el modelo
    """
    if not flows:
        return None
    
    try:
        # Crear DataFrame desde los flows
        df = pd.DataFrame(flows)
        
        # El modelo espera estas columnas (sin 'Type'):
        # Las columnas exactas dependen de tu dataset
        # Aquí asumimos que los flows tienen campos similares a tu dataset
        
        # Si los flows no tienen todas las features, necesitas calcularlas
        # Por ahora, retornamos el DataFrame tal cual
        
        return df
    
    except Exception as e:
        logger.error(f"Error procesando flows: {e}")
        return None

def predict_device_categories(flows_df):
    """
    Predecir categorías de dispositivos desde flows
    
    Args:
        flows_df: DataFrame con features de flows
        
    Returns:
        Int: número de predicciones realizadas
    """
    global model, label_encoder
    
    if model is None or label_encoder is None:
        logger.error("Modelo no cargado")
        return 0
    
    try:
        # Obtener IPs antes de eliminarlas
        src_ips = flows_df.get('SrcIP', flows_df.get('src_ip', None))
        
        if src_ips is None:
            logger.warning("No se encontraron IPs de origen en los flows")
            return 0
        
        # Filtrar flows: solo IPs válidas y de la red local
        valid_indices = []
        for idx, ip in enumerate(src_ips):
            ip_str = str(ip)
            if is_valid_ip(ip_str) and is_local_ip(ip_str):
                valid_indices.append(idx)
            else:
                logger.debug(f"IP descartada (inválida o no local): {ip_str}")
        
        if not valid_indices:
            logger.info("No hay IPs válidas de la red local para clasificar")
            return 0
        
        # Filtrar el DataFrame
        flows_df = flows_df.iloc[valid_indices].copy()
        src_ips = src_ips.iloc[valid_indices] if hasattr(src_ips, 'iloc') else [src_ips[i] for i in valid_indices]
        
        # Columnas a eliminar (que no son features)
        cols_to_drop = ['Type', 'SrcIP', 'DstIP', 'src_ip', 'dst_ip', 
                       'FlowID', 'Timestamp', 'received_at']
        
        features = flows_df.copy()
        for col in cols_to_drop:
            if col in features.columns:
                features = features.drop(columns=[col])
        
        # Verificar que tenemos las features correctas
        if features.shape[1] != model.n_features_in_:
            logger.warning(f"Número de features incorrecto: {features.shape[1]} vs {model.n_features_in_} esperadas")
            return 0
        
        # Hacer predicción
        predictions_encoded = model.predict(features)
        predictions = label_encoder.inverse_transform(predictions_encoded)
        
        # Actualizar predicciones por dispositivo
        prediction_count = 0
        for ip, category in zip(src_ips, predictions):
            ip_str = str(ip)
            update_device_prediction(ip_str, category)
            prediction_count += 1
            logger.debug(f"Predicción: {ip_str} -> {category}")
        
        stats['predictions_made'] += prediction_count
        stats['last_prediction'] = datetime.now().isoformat()
        
        logger.info(f"{prediction_count} predicciones realizadas para dispositivos locales")
        return prediction_count
    
    except Exception as e:
        logger.error(f"Error en predicción: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return 0

@app.route('/health', methods=['GET'])
def health():
    """Endpoint de health check"""
    model_status = 'loaded' if model is not None else 'not_loaded'
    
    return jsonify({
        'status': 'ok',
        'model_status': model_status,
        'model_classes': label_encoder.classes_.tolist() if label_encoder else [],
        'timestamp': datetime.now().isoformat(),
        'stats': stats
    })

@app.route('/pcap', methods=['POST'])
def receive_pcap():
    """Recibir archivo PCAP del sistema de captura"""
    if 'file' not in request.files:
        logger.warning("No se recibió archivo PCAP")
        return jsonify({'error': 'No file provided'}), 400
    
    pcap_file = request.files['file']
    logger.info(f"PCAP recibido: {pcap_file.filename}")
    
    # Actualizar estadísticas
    stats['pcap_received'] += 1
    stats['last_pcap'] = datetime.now().isoformat()
    
    # TODO: Procesar PCAP y extraer features
    # Por ahora solo confirmamos recepción
    
    return jsonify({
        'status': 'received',
        'message': 'PCAP received (feature extraction not implemented yet)',
        'filename': pcap_file.filename
    }), 200

@app.route('/flows', methods=['POST'])
def receive_flows():
    """Recibir flows del sistema de captura y clasificarlos"""
    global recent_flows, recent_predictions
    
    if not request.json or 'flows' not in request.json:
        logger.warning("No se recibieron flows")
        return jsonify({'error': 'No flows provided'}), 400
    
    if model is None:
        logger.error("Modelo no cargado")
        return jsonify({'error': 'Model not loaded'}), 500
    
    flows = request.json['flows']
    total_flows = len(flows)
    logger.info(f"Flows recibidos: {total_flows} flows")
    
    # 🔥 NUEVO: Limitar a los últimos 10 flows
    N_flows = int(os.getenv('MODEL_ML_LAST_FLOWS', '10'))
    flows = flows[-N_flows:] if len(flows) > N_flows else flows
    logger.info(f"Procesando últimos {len(flows)} flows (limitado a {N_flows})")
    
    # Limpiar flows antiguos periódicamente
    cleanup_old_flows()
    
    # Filtrar flows ya procesados
    new_flows = []
    for flow in flows:
        if not is_flow_processed(flow):
            new_flows.append(flow)
            mark_flow_as_processed(flow)
    
    logger.info(f"Flows nuevos (no procesados): {len(new_flows)} de {total_flows}")
    
    # Si no hay flows nuevos, no hacer nada
    if not new_flows:
        logger.info("No hay flows nuevos para procesar")
        return jsonify({
            'status': 'processed',
            'message': 'No new flows to process',
            'flows_received': total_flows,
            'new_flows': 0,
            'predictions_count': 0
        }), 200
    
    # Actualizar estadísticas
    stats['flows_received'] += 1
    stats['last_flow'] = datetime.now().isoformat()
    
    # Guardar flows recientes (solo los nuevos)
    for flow in new_flows:
        flow['received_at'] = datetime.now().isoformat()
        recent_flows.insert(0, flow)
    recent_flows = recent_flows[:MAX_RECENT]
    
    # Convertir flows a features
    flows_df = process_flows_to_features(new_flows)
    
    if flows_df is None or flows_df.empty:
        logger.warning("No se pudieron procesar los flows")
        return jsonify({
            'status': 'error',
            'message': 'Could not process flows'
        }), 400
    
    # Predecir categorías (ahora retorna número de predicciones)
    prediction_count = predict_device_categories(flows_df)
    
    if prediction_count > 0:
        # El envío al firewall se hace automáticamente en update_device_prediction()
        # cuando un dispositivo alcanza 3+ predicciones consistentes
        
        # Obtener categorías actuales para el response
        current_categories = get_categories_for_firewall()
        
        logger.info(f"Predicciones realizadas: {prediction_count}")
        
        return jsonify({
            'status': 'processed',
            'message': 'Flows analyzed and classified',
            'flows_received': total_flows,
            'new_flows': len(new_flows),
            'predictions_count': prediction_count,
            'current_categories': current_categories
        }), 200
    else:
        return jsonify({
            'status': 'processed',
            'message': 'No predictions made (no valid local IPs)',
            'flows_received': total_flows,
            'new_flows': len(new_flows)
        }), 200


@app.route('/predict', methods=['POST'])
def predict():
    """
    Endpoint directo para predicción
    Espera un JSON con features del flow
    """
    if model is None:
        return jsonify({'error': 'Model not loaded'}), 500
    
    if not request.json:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        # Convertir a DataFrame
        if isinstance(request.json, list):
            df = pd.DataFrame(request.json)
        else:
            df = pd.DataFrame([request.json])
        
        # Hacer predicción
        categories = predict_device_categories(df)
        
        return jsonify({
            'status': 'success',
            'predictions': categories
        }), 200
    
    except Exception as e:
        logger.error(f"Error en predicción: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """Obtener estadísticas detalladas"""
    # Preparar estadísticas de dispositivos
    devices_stats = {}
    for ip in device_predictions:
        devices_stats[ip] = get_device_stats(ip)
    
    return jsonify({
        'stats': stats,
        'devices': devices_stats,
        'local_network': local_network,
        'total_devices': len(device_predictions),
        'categories_summary': get_categories_for_firewall(),
        'model_info': {
            'loaded': model is not None,
            'n_features': model.n_features_in_ if model else 0,
            'classes': label_encoder.classes_.tolist() if label_encoder else []
        }
    })

@app.route('/devices', methods=['GET'])
def get_devices():
    """Obtener información detallada de todos los dispositivos"""
    devices_list = []
    for ip in device_predictions:
        device_info = get_device_stats(ip)
        device_info['ip'] = ip
        devices_list.append(device_info)
    
    # Ordenar por total de predicciones
    devices_list.sort(key=lambda x: x['total_predictions'], reverse=True)
    
    return jsonify({
        'devices': devices_list,
        'total': len(devices_list)
    })

@app.route('/device/<ip>', methods=['GET'])
def get_device_info(ip):
    """Obtener información detallada de un dispositivo específico"""
    device_stats = get_device_stats(ip)
    
    if device_stats is None:
        return jsonify({'error': 'Device not found'}), 404
    
    device_stats['ip'] = ip
    return jsonify(device_stats)

@app.route('/clear_predictions', methods=['POST'])
def clear_predictions():
    """Limpiar todas las predicciones de dispositivos"""
    global processed_flows
    
    clear_all_predictions()
    processed_flows = set()  # También limpiar el set de flows procesados
    
    logger.info("Predicciones y flows procesados limpiados por solicitud del usuario")
    
    return jsonify({
        'status': 'success',
        'message': 'All predictions cleared',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/reset_stats', methods=['POST'])
def reset_stats():
    """Reiniciar todas las estadísticas globales del servidor"""
    global stats
    
    stats = {
        'pcap_received': 0,
        'flows_received': 0,
        'predictions_made': 0,
        'firewall_updates': 0,
        'last_pcap': None,
        'last_flow': None,
        'last_prediction': None,
        'last_firewall_update': None
    }
    
    logger.info("📊 Estadísticas globales reiniciadas por solicitud del usuario")
    
    return jsonify({
        'status': 'success',
        'message': 'Statistics reset successfully',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/recent_flows', methods=['GET'])
def get_recent_flows():
    """Obtener flows recientes"""
    limit = request.args.get('limit', 20, type=int)
    return jsonify({
        'flows': recent_flows[:limit],
        'total': len(recent_flows)
    })

@app.route('/', methods=['GET'])
def dashboard():
    """Dashboard web simple"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>IoT Device Classifier - Dashboard</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                margin: 20px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            h1 { 
                color: #333;
                border-bottom: 2px solid #4CAF50;
                padding-bottom: 10px;
            }
            .status {
                display: inline-block;
                padding: 5px 10px;
                border-radius: 4px;
                font-weight: bold;
            }
            .status.ok { background-color: #4CAF50; color: white; }
            .status.error { background-color: #f44336; color: white; }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin: 20px 0;
            }
            .stat-card {
                background-color: #f9f9f9;
                padding: 15px;
                border-radius: 4px;
                border-left: 4px solid #4CAF50;
            }
            .stat-card h3 {
                margin: 0 0 10px 0;
                color: #666;
                font-size: 14px;
            }
            .stat-card .value {
                font-size: 24px;
                font-weight: bold;
                color: #333;
            }
            .section {
                margin: 30px 0;
            }
            .classes {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
            }
            .class-badge {
                background-color: #2196F3;
                color: white;
                padding: 8px 15px;
                border-radius: 20px;
                font-size: 14px;
            }
        </style>
        <script>
            function refreshStats() {
                fetch('/health')
                    .then(r => r.json())
                    .then(data => {
                        document.getElementById('model-status').textContent = data.model_status;
                        document.getElementById('model-status').className = 
                            'status ' + (data.model_status === 'loaded' ? 'ok' : 'error');
                        
                        document.getElementById('pcap-count').textContent = data.stats.pcap_received;
                        document.getElementById('flows-count').textContent = data.stats.flows_received;
                        document.getElementById('predictions-count').textContent = data.stats.predictions_made;
                        document.getElementById('firewall-count').textContent = data.stats.firewall_updates;
                        
                        // Actualizar categorías dinámicamente
                        if (data.model_classes && data.model_classes.length > 0) {
                            updateCategories(data.model_classes);
                        }
                    })
                    .catch(e => console.error('Error refreshing stats:', e));
            }
            
            function resetStats() {
                if (!confirm('¿Estás seguro de que quieres reiniciar todas las estadísticas?')) {
                    return;
                }
                
                fetch('/reset_stats', {method: 'POST'})
                    .then(r => r.json())
                    .then(data => {
                        alert('✅ Estadísticas reiniciadas exitosamente');
                        refreshStats();
                    })
                    .catch(e => {
                        alert('❌ Error reiniciando estadísticas: ' + e);
                        console.error('Error resetting stats:', e);
                    });
            }
            
            // Mapeo de emojis para categorías conocidas
            const categoryEmojis = {
                'MULTIMEDIA': '📹',
                'SMART_CONTROLS': '💡',
                'SENSORS': '🌡️',
                'COMPUTING': '💻',
                'ENVIRONMENT_SENSING': '🌡️',
                'HOME_AUTOMATION': '🏠',
                'NETWORK_CORE': '🌐',
                'PERSONAL_DEVICES': '📱',
                'SMART_APPLIANCES': '🔌',
                'VIDEO_STREAMING': '📺'
            };
            
            function updateCategories(classes) {
                const container = document.getElementById('categories-container');
                if (!container) return;
                
                container.innerHTML = '';
                classes.forEach(category => {
                    const badge = document.createElement('div');
                    badge.className = 'class-badge';
                    const emoji = categoryEmojis[category] || '🔷';
                    badge.textContent = `${emoji} ${category}`;
                    container.appendChild(badge);
                });
            }
            
            setInterval(refreshStats, 5000);
            window.onload = refreshStats;
        </script>
    </head>
    <body>
        <div class="container">
            <h1>🤖 IoT Device Classifier Server</h1>
            
            <div class="section">
                <h2>Estado del Modelo</h2>
                <p>Status: <span id="model-status" class="status">loading...</span></p>
            </div>
            
            <div class="section">
                <h2>Estadísticas
                    <button onclick="resetStats()" style="float: right; background-color: #ff9800; color: white; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 13px;">
                        🔄 Reiniciar Estadísticas
                    </button>
                </h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>PCAPs Recibidos</h3>
                        <div class="value" id="pcap-count">-</div>
                    </div>
                    <div class="stat-card">
                        <h3>Flows Recibidos</h3>
                        <div class="value" id="flows-count">-</div>
                    </div>
                    <div class="stat-card">
                        <h3>Predicciones</h3>
                        <div class="value" id="predictions-count">-</div>
                    </div>
                    <div class="stat-card">
                        <h3>Actualizaciones Firewall</h3>
                        <div class="value" id="firewall-count">-</div>
                    </div>
                </div>
                <p style="color: #666; font-size: 12px; margin-top: 10px;">ℹ️ El modelo procesa solo los últimos 10 flows por cada batch recibido</p>
            </div>
            
            <div class="section">
                <h2>Categorías de Dispositivos</h2>
                <div class="classes" id="categories-container">
                    <!-- Las categorías se cargarán dinámicamente -->
                    <div class="class-badge">⏳ Cargando...</div>
                </div>
            </div>
            
            <div class="section">
                <h2>Dispositivos Clasificados</h2>
                <p>Red Local: <span id="local-network">-</span></p>
                <p>Total Dispositivos: <span id="total-devices">0</span></p>
                <button onclick="clearPredictions()" style="background-color: #f44336; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; margin-bottom: 15px;">
                    🗑️ Limpiar Todas las Clasificaciones
                </button>
                <div id="devices-table"></div>
            </div>
            
            <div class="section">
                <h2>API Endpoints</h2>
                <ul>
                    <li><code>GET /health</code> - Health check</li>
                    <li><code>POST /flows</code> - Recibir flows para clasificación</li>
                    <li><code>POST /pcap</code> - Recibir archivo PCAP</li>
                    <li><code>POST /predict</code> - Predicción directa</li>
                    <li><code>GET /stats</code> - Estadísticas detalladas con dispositivos</li>
                    <li><code>GET /devices</code> - Lista de dispositivos clasificados</li>
                    <li><code>GET /device/&lt;ip&gt;</code> - Info de dispositivo específico</li>
                    <li><code>GET /recent_flows</code> - Flows recientes</li>
                </ul>
            </div>
        </div>
        <script>
            function refreshDevices() {
                fetch('/stats')
                    .then(r => r.json())
                    .then(data => {
                        document.getElementById('local-network').textContent = data.local_network || 'Detectando...';
                        document.getElementById('total-devices').textContent = data.total_devices || 0;
                        
                        const devices = data.devices || {};
                        let tableHTML = '<table style="width:100%; border-collapse: collapse;">';
                        tableHTML += '<tr style="background-color: #f0f0f0;">';
                        tableHTML += '<th style="padding: 10px; text-align: left; border: 1px solid #ddd;">IP</th>';
                        tableHTML += '<th style="padding: 10px; text-align: left; border: 1px solid #ddd;">Categoría Principal</th>';
                        tableHTML += '<th style="padding: 10px; text-align: left; border: 1px solid #ddd;">Total Predicciones</th>';
                        tableHTML += '<th style="padding: 10px; text-align: left; border: 1px solid #ddd;">Distribución %</th>';
                        tableHTML += '</tr>';
                        
                        Object.keys(devices).forEach(ip => {
                            const device = devices[ip];
                            tableHTML += '<tr>';
                            tableHTML += `<td style="padding: 10px; border: 1px solid #ddd;"><strong>${ip}</strong></td>`;
                            tableHTML += `<td style="padding: 10px; border: 1px solid #ddd;">${device.main_category}</td>`;
                            tableHTML += `<td style="padding: 10px; border: 1px solid #ddd;">${device.total_predictions}</td>`;
                            tableHTML += '<td style="padding: 10px; border: 1px solid #ddd;">';
                            
                            Object.keys(device.percentages).sort((a, b) => device.percentages[b] - device.percentages[a]).forEach(category => {
                                const pct = device.percentages[category];
                                tableHTML += `<div style="margin: 2px 0;"><span style="display: inline-block; background: #2196F3; color: white; padding: 2px 8px; border-radius: 3px; margin-right: 5px;">${category}</span> ${pct}%</div>`;
                            });
                            
                            tableHTML += '</td>';
                            tableHTML += '</tr>';
                        });
                        
                        tableHTML += '</table>';
                        document.getElementById('devices-table').innerHTML = tableHTML;
                    })
                    .catch(e => console.error('Error refreshing devices:', e));
            }
            
            function refreshAll() {
                refreshStats();
                refreshDevices();
            }
            
            function clearPredictions() {
                if (!confirm('¿Estás seguro de que quieres limpiar todas las clasificaciones?')) {
                    return;
                }
                
                fetch('/clear_predictions', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(r => r.json())
                .then(data => {
                    alert('✅ ' + data.message);
                    refreshAll();
                })
                .catch(e => {
                    console.error('Error clearing predictions:', e);
                    alert('❌ Error al limpiar las clasificaciones');
                });
            }
            
            setInterval(refreshAll, 5000);
            window.onload = refreshAll;
        </script>
    </body>
    </html>
    """
    return render_template_string(html)

if __name__ == '__main__':
    logger.info("="*70)
    logger.info("Iniciando servidor de clasificación IoT")
    logger.info("="*70)
    
    # Detectar red local
    detect_local_network()
    
    # Cargar modelo
    if load_model():
        logger.info("✅ Servidor listo para recibir peticiones")
        ML_PORT = os.getenv('MODEL_ML_PORT', '5001')
        app.run(host='0.0.0.0', port=ML_PORT, debug=False)
    else:
        logger.error("❌ No se pudo cargar el modelo. Verifica que los archivos existan.")
        logger.error(f"   Buscando: {MODEL_PATH} y {ENCODER_PATH}")
