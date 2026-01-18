#!/usr/bin/env python3
"""
model_server.py - Servidor de modelo Deep Learning (DL)
Recibe archivos PCAP y clasifica dispositivos IoT usando el modelo DL
"""

from flask import Flask, request, jsonify, render_template_string
import requests
import logging
import time
from datetime import datetime
import os
import sys
import tempfile
from pathlib import Path

# Agregar el directorio inference al path para importar
INFERENCE_DIR = os.path.join(os.path.dirname(__file__), 'inference')
sys.path.insert(0, INFERENCE_DIR)

# Importar el clasificador
try:
    from classify_pcap import IoTClassifier
    CLASSIFIER_AVAILABLE = True
except ImportError as e:
    print(f"⚠ Advertencia: No se pudo importar IoTClassifier: {e}")
    CLASSIFIER_AVAILABLE = False

# Configuración
app = Flask(__name__)

# Configuración del firewall
FIREWALL_URL = os.getenv('FIREWALL_URL', 'http://192.168.50.1:5000')

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Variables globales
classifier = None
MODEL_LOADED = False

# Estadísticas
stats = {
    'pcap_received': 0,
    'predictions_made': 0,
    'firewall_updates': 0,
    'last_pcap': None,
    'last_prediction': None,
    'last_firewall_update': None,
    'errors': 0
}

# Buffer para almacenar las últimas predicciones
recent_predictions = []
MAX_RECENT_PREDICTIONS = 50

# Mapeo de dispositivos IoT a categorías de seguridad/tráfico
# Puedes personalizar este mapeo según tus necesidades
DEVICE_TO_CATEGORY = {
    # Multimedia devices
    'Amazon_Echo': 'MULTIMEDIA',
    'Smart_TV': 'MULTIMEDIA',
    'Chromecast': 'MULTIMEDIA',
    
    # Smart controls
    'SmartThings': 'SMART_CONTROLS',
    'TP-Link_Plug': 'SMART_CONTROLS',
    'WeMo_Plug': 'SMART_CONTROLS',
    'Philips_Hue': 'SMART_CONTROLS',
    
    # Sensors
    'Netatmo_Weather': 'SENSORS',
    'Withings_Sleep': 'SENSORS',
    
    # Computing/Network
    'iPhone': 'COMPUTING',
    'MacBook': 'COMPUTING',
    'Android_Phone': 'COMPUTING',
    
    # Agregar más según tu modelo
}

def load_model():
    """Cargar el modelo Deep Learning"""
    global classifier, MODEL_LOADED
    
    if not CLASSIFIER_AVAILABLE:
        logger.error("❌ Clasificador no disponible")
        return False
    
    try:
        # Rutas de los archivos del modelo
        model_path = os.path.join(INFERENCE_DIR, "best_model.keras")
        encoder_path = os.path.join(INFERENCE_DIR, "label_encoder.pkl")
        config_path = os.path.join(INFERENCE_DIR, "model_config.json")
        
        # Verificar que existan los archivos
        for path in [model_path, encoder_path, config_path]:
            if not os.path.exists(path):
                logger.error(f"❌ Archivo no encontrado: {path}")
                return False
        
        # Inicializar clasificador
        logger.info("🔧 Cargando modelo Deep Learning...")
        classifier = IoTClassifier(model_path, encoder_path, config_path)
        MODEL_LOADED = True
        
        logger.info("✅ Modelo DL cargado exitosamente")
        logger.info(f"   Clases disponibles: {len(classifier.class_names)}")
        
        return True
    
    except Exception as e:
        logger.error(f"❌ Error cargando modelo: {e}")
        return False

def send_to_firewall(categories):
    """Enviar categorías al firewall"""
    try:
        logger.info(f"📤 Enviando categorías al firewall: {categories}")
        
        response = requests.post(
            f'{FIREWALL_URL}/update_categories',
            json={'categories': categories},
            timeout=5
        )
        
        if response.status_code == 200:
            logger.info(f"✅ Firewall actualizado exitosamente")
            stats['firewall_updates'] += 1
            stats['last_firewall_update'] = datetime.now().isoformat()
            return True
        else:
            logger.warning(f"⚠ Error actualizando firewall: {response.status_code}")
            return False
    
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Error conectando al firewall: {e}")
        return False
    except Exception as e:
        logger.error(f"❌ Error inesperado: {e}")
        return False

def device_to_categories(device_name, src_ip=None):
    """
    Convertir un dispositivo clasificado a formato de categorías del firewall
    
    Args:
        device_name: Nombre del dispositivo clasificado
        src_ip: IP de origen (opcional)
        
    Returns:
        dict: Categorías en formato del firewall
    """
    # Obtener categoría del dispositivo
    category = DEVICE_TO_CATEGORY.get(device_name, 'UNKNOWN')
    
    # Si tenemos IP, crear entrada específica
    if src_ip:
        return {
            category: [src_ip]
        }
    else:
        # Sin IP específica, solo indicar el tipo de dispositivo detectado
        return {
            category: []
        }

@app.route('/health', methods=['GET'])
def health():
    """Endpoint de health check"""
    return jsonify({
        'status': 'ok' if MODEL_LOADED else 'model_not_loaded',
        'model_loaded': MODEL_LOADED,
        'classifier_available': CLASSIFIER_AVAILABLE,
        'timestamp': datetime.now().isoformat(),
        'stats': stats
    })

@app.route('/pcap', methods=['POST'])
def receive_pcap():
    """Recibir archivo PCAP y clasificar con el modelo DL"""
    global recent_predictions
    
    if not MODEL_LOADED:
        logger.error("❌ Modelo no cargado")
        return jsonify({
            'error': 'Model not loaded',
            'status': 'error'
        }), 503
    
    if 'file' not in request.files:
        logger.warning("⚠ No se recibió archivo PCAP")
        return jsonify({'error': 'No file provided'}), 400
    
    pcap_file = request.files['file']
    logger.info(f"📦 PCAP recibido: {pcap_file.filename}")
    
    # Guardar temporalmente el archivo
    temp_pcap = None
    try:
        # Crear archivo temporal
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.pcap', delete=False) as f:
            temp_pcap = f.name
            pcap_file.save(temp_pcap)
        
        logger.info(f"💾 PCAP guardado temporalmente: {temp_pcap}")
        
        # Actualizar estadísticas
        stats['pcap_received'] += 1
        stats['last_pcap'] = datetime.now().isoformat()
        
        # Clasificar con el modelo DL
        logger.info("🔄 Clasificando tráfico con modelo DL...")
        result = classifier.classify_pcap(temp_pcap, max_pkts=1000, verbose=False)
        
        if 'error' in result:
            logger.error(f"❌ Error en clasificación: {result['error']}")
            stats['errors'] += 1
            return jsonify({
                'status': 'error',
                'error': result['error']
            }), 500
        
        # Extraer resultado
        device = result['classified_device']
        confidence = result['confidence']
        
        logger.info(f"✅ Dispositivo clasificado: {device} (confianza: {confidence*100:.2f}%)")
        
        # Actualizar estadísticas
        stats['predictions_made'] += 1
        stats['last_prediction'] = {
            'device': device,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat()
        }
        
        # Guardar predicción reciente
        prediction_record = {
            'timestamp': datetime.now().isoformat(),
            'device': device,
            'confidence': confidence,
            'pcap_file': pcap_file.filename,
            'total_packets': result['total_packets'],
            'valid_packets': result['valid_packets']
        }
        recent_predictions.insert(0, prediction_record)
        recent_predictions = recent_predictions[:MAX_RECENT_PREDICTIONS]
        
        # Convertir a categorías del firewall
        categories = device_to_categories(device)
        
        # Enviar al firewall
        send_to_firewall(categories)
        
        return jsonify({
            'status': 'processed',
            'message': 'PCAP analyzed successfully',
            'result': {
                'device': device,
                'confidence': float(confidence),
                'category': list(categories.keys())[0] if categories else 'UNKNOWN',
                'total_packets': result['total_packets'],
                'valid_packets': result['valid_packets']
            },
            'firewall_updated': True
        }), 200
    
    except Exception as e:
        logger.error(f"❌ Error procesando PCAP: {e}")
        stats['errors'] += 1
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500
    
    finally:
        # Limpiar archivo temporal
        if temp_pcap and os.path.exists(temp_pcap):
            try:
                os.remove(temp_pcap)
                logger.debug(f"🗑️  Archivo temporal eliminado: {temp_pcap}")
            except Exception as e:
                logger.warning(f"⚠ No se pudo eliminar archivo temporal: {e}")

@app.route('/stats', methods=['GET'])
def get_stats():
    """Obtener estadísticas del modelo"""
    return jsonify({
        'stats': stats,
        'recent_predictions': recent_predictions[:10]  # Últimas 10
    })

@app.route('/predictions', methods=['GET'])
def get_predictions():
    """Obtener todas las predicciones recientes"""
    return jsonify({
        'predictions': recent_predictions,
        'total': len(recent_predictions)
    })

# Dashboard HTML simple
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Modelo DL - Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 20px;
            background: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-card h3 {
            margin: 0;
            font-size: 2em;
        }
        .stat-card p {
            margin: 5px 0 0 0;
            opacity: 0.9;
        }
        .predictions {
            margin-top: 30px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #3498db;
            color: white;
        }
        .status {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
        }
        .status.ok {
            background: #2ecc71;
            color: white;
        }
        .status.error {
            background: #e74c3c;
            color: white;
        }
        .confidence {
            font-weight: bold;
            color: #27ae60;
        }
    </style>
    <script>
        function refreshStats() {
            fetch('/stats')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('pcap-count').textContent = data.stats.pcap_received;
                    document.getElementById('pred-count').textContent = data.stats.predictions_made;
                    document.getElementById('fw-count').textContent = data.stats.firewall_updates;
                    document.getElementById('err-count').textContent = data.stats.errors;
                    
                    // Última predicción
                    if (data.stats.last_prediction) {
                        document.getElementById('last-device').textContent = data.stats.last_prediction.device;
                        document.getElementById('last-confidence').textContent = 
                            (data.stats.last_prediction.confidence * 100).toFixed(2) + '%';
                    }
                    
                    // Predicciones recientes
                    const tbody = document.getElementById('predictions-tbody');
                    tbody.innerHTML = '';
                    data.recent_predictions.forEach(pred => {
                        const row = tbody.insertRow();
                        row.innerHTML = `
                            <td>${new Date(pred.timestamp).toLocaleString()}</td>
                            <td><strong>${pred.device}</strong></td>
                            <td class="confidence">${(pred.confidence * 100).toFixed(2)}%</td>
                            <td>${pred.valid_packets} / ${pred.total_packets}</td>
                        `;
                    });
                });
        }
        
        setInterval(refreshStats, 5000);
        window.onload = refreshStats;
    </script>
</head>
<body>
    <div class="container">
        <h1>🎯 Modelo Deep Learning - Dashboard</h1>
        
        <div class="stats">
            <div class="stat-card">
                <h3 id="pcap-count">0</h3>
                <p>PCAPs Recibidos</p>
            </div>
            <div class="stat-card">
                <h3 id="pred-count">0</h3>
                <p>Predicciones</p>
            </div>
            <div class="stat-card">
                <h3 id="fw-count">0</h3>
                <p>Updates al Firewall</p>
            </div>
            <div class="stat-card">
                <h3 id="err-count">0</h3>
                <p>Errores</p>
            </div>
        </div>
        
        <div class="predictions">
            <h2>🔥 Última Predicción</h2>
            <p><strong>Dispositivo:</strong> <span id="last-device">-</span></p>
            <p><strong>Confianza:</strong> <span id="last-confidence">-</span></p>
        </div>
        
        <div class="predictions">
            <h2>📊 Predicciones Recientes</h2>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Dispositivo</th>
                        <th>Confianza</th>
                        <th>Paquetes</th>
                    </tr>
                </thead>
                <tbody id="predictions-tbody">
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def dashboard():
    """Dashboard web"""
    return render_template_string(DASHBOARD_HTML)

if __name__ == '__main__':
    print("=" * 60)
    print("🎯 Servidor de Modelo Deep Learning")
    print("=" * 60)
    
    # Cargar modelo
    if load_model():
        print(f"✅ Modelo cargado correctamente")
        print(f"📡 Escuchando en puerto 5002")
        print(f"🔗 Dashboard: http://localhost:5002")
        print(f"🔗 Health: http://localhost:5002/health")
        print(f"🔗 Stats: http://localhost:5002/stats")
        print("=" * 60)
        
        # Iniciar servidor
        app.run(host='0.0.0.0', port=5002, debug=False)
    else:
        print("❌ No se pudo cargar el modelo")
        print("Verifica que existan los archivos:")
        print("  - inference/best_model.keras")
        print("  - inference/label_encoder.pkl")
        print("  - inference/model_config.json")
        sys.exit(1)
