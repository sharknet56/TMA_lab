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

# Configuración del firewall
FIREWALL_URL = 'http://192.168.50.1:5000'

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Cargar modelo y encoder
MODEL_PATH = 'iot_device_classifier_rf.pkl'
ENCODER_PATH = 'label_encoder.pkl'

model = None
label_encoder = None

def load_model():
    """Cargar el modelo y el encoder desde disco"""
    global model, label_encoder
    
    try:
        if not os.path.exists(MODEL_PATH):
            logger.error(f"No se encuentra el modelo: {MODEL_PATH}")
            return False
        
        if not os.path.exists(ENCODER_PATH):
            logger.error(f"No se encuentra el encoder: {ENCODER_PATH}")
            return False
        
        model = joblib.load(MODEL_PATH)
        label_encoder = joblib.load(ENCODER_PATH)
        
        logger.info(f"✅ Modelo cargado exitosamente")
        logger.info(f"   Features esperados: {model.n_features_in_}")
        logger.info(f"   Clases: {label_encoder.classes_}")
        
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
CATEGORY_TO_THREAT = {
    'MULTIMEDIA': 'high_bandwidth',
    'SMART_CONTROLS': 'iot_control',
    'SENSORS': 'low_traffic',
    'COMPUTING': 'general_device'
}

def send_to_firewall(categories):
    """Enviar categorías al firewall"""
    try:
        logger.info(f"Enviando categorías al firewall: {categories}")
        
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
        Dict con IPs y sus categorías predichas
    """
    global model, label_encoder
    
    if model is None or label_encoder is None:
        logger.error("Modelo no cargado")
        return {}
    
    try:
        # Asegurarse de que el DataFrame tiene las columnas correctas
        # (excluyendo columnas que no son features como 'Type', 'SrcIP', etc.)
        
        # Obtener IPs antes de eliminarlas
        src_ips = flows_df.get('SrcIP', flows_df.get('src_ip', None))
        
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
            return {}
        
        # Hacer predicción
        predictions_encoded = model.predict(features)
        predictions = label_encoder.inverse_transform(predictions_encoded)
        
        # Agrupar por IP y categoría
        results = {}
        if src_ips is not None:
            for ip, category in zip(src_ips, predictions):
                if category not in results:
                    results[category] = []
                if ip not in results[category]:
                    results[category].append(str(ip))
        
        stats['predictions_made'] += len(predictions)
        stats['last_prediction'] = datetime.now().isoformat()
        
        return results
    
    except Exception as e:
        logger.error(f"Error en predicción: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {}

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
    logger.info(f"Flows recibidos: {len(flows)} flows")
    
    # Actualizar estadísticas
    stats['flows_received'] += 1
    stats['last_flow'] = datetime.now().isoformat()
    
    # Guardar flows recientes
    for flow in flows:
        flow['received_at'] = datetime.now().isoformat()
        recent_flows.insert(0, flow)
    recent_flows = recent_flows[:MAX_RECENT]
    
    # Convertir flows a features
    flows_df = process_flows_to_features(flows)
    
    if flows_df is None or flows_df.empty:
        logger.warning("No se pudieron procesar los flows")
        return jsonify({
            'status': 'error',
            'message': 'Could not process flows'
        }), 400
    
    # Predecir categorías
    categories = predict_device_categories(flows_df)
    
    if categories:
        # Guardar predicciones recientes
        prediction_record = {
            'timestamp': datetime.now().isoformat(),
            'flows_count': len(flows),
            'categories': categories
        }
        recent_predictions.insert(0, prediction_record)
        recent_predictions = recent_predictions[:MAX_RECENT]
        
        # Enviar al firewall
        send_to_firewall(categories)
        
        logger.info(f"Predicciones realizadas: {dict((k, len(v)) for k, v in categories.items())}")
        
        return jsonify({
            'status': 'processed',
            'message': 'Flows analyzed and classified',
            'flows_analyzed': len(flows),
            'categories': categories,
            'predictions_count': sum(len(v) for v in categories.values())
        }), 200
    else:
        return jsonify({
            'status': 'processed',
            'message': 'No predictions made',
            'flows_analyzed': len(flows)
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
    return jsonify({
        'stats': stats,
        'recent_predictions': recent_predictions[:10],
        'model_info': {
            'loaded': model is not None,
            'n_features': model.n_features_in_ if model else 0,
            'classes': label_encoder.classes_.tolist() if label_encoder else []
        }
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
                    })
                    .catch(e => console.error('Error refreshing stats:', e));
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
                <h2>Estadísticas</h2>
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
            </div>
            
            <div class="section">
                <h2>Categorías de Dispositivos</h2>
                <div class="classes">
                    <div class="class-badge">📹 MULTIMEDIA</div>
                    <div class="class-badge">💡 SMART_CONTROLS</div>
                    <div class="class-badge">🌡️ SENSORS</div>
                    <div class="class-badge">💻 COMPUTING</div>
                </div>
            </div>
            
            <div class="section">
                <h2>API Endpoints</h2>
                <ul>
                    <li><code>GET /health</code> - Health check</li>
                    <li><code>POST /flows</code> - Recibir flows para clasificación</li>
                    <li><code>POST /pcap</code> - Recibir archivo PCAP</li>
                    <li><code>POST /predict</code> - Predicción directa</li>
                    <li><code>GET /stats</code> - Estadísticas detalladas</li>
                    <li><code>GET /recent_flows</code> - Flows recientes</li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html)

if __name__ == '__main__':
    logger.info("="*70)
    logger.info("Iniciando servidor de clasificación IoT")
    logger.info("="*70)
    
    # Cargar modelo
    if load_model():
        logger.info("✅ Servidor listo para recibir peticiones")
        app.run(host='0.0.0.0', port=5001, debug=False)
    else:
        logger.error("❌ No se pudo cargar el modelo. Verifica que los archivos existan.")
        logger.error(f"   Buscando: {MODEL_PATH} y {ENCODER_PATH}")
