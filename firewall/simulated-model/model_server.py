#!/usr/bin/env python3
"""
model_server.py - Servidor de modelo ML simulado
Recibe PCAP y flows, y envía categorías predefinidas al firewall
"""

from flask import Flask, request, jsonify, render_template_string
import requests
import logging
import time
from datetime import datetime
import random
import os
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

# IPs y categorías simuladas que quieres enviar
SIMULATED_THREATS = {
    'malware': [
        '192.168.50.15',
        '192.168.50.23',
        '192.168.50.100'
    ],
    'phishing': [
        '192.168.50.8',
        '192.168.50.45'
    ],
    'suspicious': [
        '192.168.50.12',
        '192.168.50.67',
        '192.168.50.89'
    ],
    'port_scan': [
        '192.168.50.33'
    ]
}

# Estadísticas
stats = {
    'pcap_received': 0,
    'flows_received': 0,
    'firewall_updates': 0,
    'last_pcap': None,
    'last_flow': None,
    'last_firewall_update': None
}

# Buffer para almacenar los últimos flows recibidos
recent_flows = []
MAX_RECENT_FLOWS = 20

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

def get_simulated_categories(mode='all'):
    """
    Obtener categorías simuladas
    
    Modos:
    - 'all': Todas las IPs de todas las categorías
    - 'random': Subconjunto aleatorio de IPs
    - 'rotate': Rotar entre diferentes categorías
    """
    if mode == 'all':
        return SIMULATED_THREATS.copy()
    
    elif mode == 'random':
        result = {}
        for category, ips in SIMULATED_THREATS.items():
            # Seleccionar aleatoriamente algunas IPs de cada categoría
            num_ips = random.randint(1, len(ips))
            result[category] = random.sample(ips, num_ips)
        return result
    
    elif mode == 'rotate':
        # Seleccionar solo una o dos categorías por vez
        categories = list(SIMULATED_THREATS.keys())
        selected = random.sample(categories, min(2, len(categories)))
        return {cat: SIMULATED_THREATS[cat] for cat in selected}
    
    return SIMULATED_THREATS.copy()

@app.route('/health', methods=['GET'])
def health():
    """Endpoint de health check"""
    return jsonify({
        'status': 'ok',
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
    
    # Guardar el archivo (opcional, para análisis posterior)
    # pcap_file.save(f'/tmp/pcap_{int(time.time())}.pcap')
    
    # Actualizar estadísticas
    stats['pcap_received'] += 1
    stats['last_pcap'] = datetime.now().isoformat()
    
    # Simular análisis y enviar categorías al firewall
    # Puedes cambiar el modo: 'all', 'random', 'rotate'
    categories = get_simulated_categories(mode='all')
    send_to_firewall(categories)
    
    return jsonify({
        'status': 'processed',
        'message': 'PCAP analyzed and firewall updated',
        'categories_sent': list(categories.keys())
    }), 200

@app.route('/flows', methods=['POST'])
def receive_flows():
    """Recibir flows del sistema de captura"""
    global recent_flows
    
    if not request.json or 'flows' not in request.json:
        logger.warning("No se recibieron flows")
        return jsonify({'error': 'No flows provided'}), 400
    
    flows = request.json['flows']
    logger.info(f"Flows recibidos: {len(flows)} flows")
    
    # Actualizar estadísticas
    stats['flows_received'] += 1
    stats['last_flow'] = datetime.now().isoformat()
    
    # Guardar los últimos flows recibidos
    for flow in flows:
        flow['received_at'] = datetime.now().isoformat()
        recent_flows.insert(0, flow)  # Añadir al inicio
    
    # Mantener solo los últimos MAX_RECENT_FLOWS
    recent_flows = recent_flows[:MAX_RECENT_FLOWS]
    
    # Log de algunos flows para debug
    for flow in flows[:3]:  # Primeros 3 flows
        logger.debug(f"Flow: {flow['src_ip']}:{flow['src_port']} -> "
                    f"{flow['dst_ip']}:{flow['dst_port']} "
                    f"({flow['packets']} pkt, {flow['bytes']} bytes)")
    
    # Simular análisis y enviar categorías al firewall
    # Puedes cambiar el modo: 'all', 'random', 'rotate'
    categories = get_simulated_categories(mode='all')
    send_to_firewall(categories)
    
    return jsonify({
        'status': 'processed',
        'message': 'Flows analyzed and firewall updated',
        'flows_analyzed': len(flows),
        'categories_sent': list(categories.keys())
    }), 200

@app.route('/configure', methods=['POST'])
def configure():
    """Endpoint para configurar las IPs y categorías que quieres simular"""
    global SIMULATED_THREATS
    
    if not request.json or 'categories' not in request.json:
        return jsonify({'error': 'No categories provided'}), 400
    
    new_categories = request.json['categories']
    SIMULATED_THREATS = new_categories
    
    logger.info(f"Configuración actualizada: {SIMULATED_THREATS}")
    
    return jsonify({
        'status': 'configured',
        'categories': SIMULATED_THREATS
    }), 200

@app.route('/trigger', methods=['POST'])
def manual_trigger():
    """Endpoint para disparar manualmente actualización del firewall"""
    mode = request.json.get('mode', 'all') if request.json else 'all'
    
    categories = get_simulated_categories(mode=mode)
    success = send_to_firewall(categories)
    
    if success:
        return jsonify({
            'status': 'success',
            'categories': categories
        }), 200
    else:
        return jsonify({
            'status': 'error',
            'message': 'Failed to update firewall'
        }), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """Obtener estadísticas del modelo"""
    return jsonify({
        'stats': stats,
        'current_config': SIMULATED_THREATS
    })

@app.route('/recent_flows', methods=['GET'])
def get_recent_flows():
    """Obtener los últimos flows recibidos"""
    return jsonify({
        'flows': recent_flows,
        'total': len(recent_flows)
    })

# HTML Template para la interfaz web
WEB_INTERFACE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Modelo ML - Control de Firewall</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .header h1 { color: #667eea; margin-bottom: 10px; }
        .status { display: inline-block; padding: 5px 15px; background: #10b981; color: white; border-radius: 20px; font-size: 14px; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
        .card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .card h2 { color: #333; margin-bottom: 20px; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; color: #64748b; margin-bottom: 5px; font-weight: 500; }
        input, select {
            width: 100%;
            padding: 10px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 14px;
        }
        input:focus, select:focus { outline: none; border-color: #667eea; }
        .btn {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            font-size: 14px;
            transition: transform 0.2s;
        }
        .btn:hover { transform: translateY(-2px); }
        .btn-primary { background: #667eea; color: white; }
        .btn-danger { background: #ef4444; color: white; }
        .btn-success { background: #10b981; color: white; }
        .category-list { max-height: 400px; overflow-y: auto; }
        .category-item {
            background: #f1f5f9;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            border-left: 4px solid #667eea;
        }
        .category-name { font-weight: 700; color: #333; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; }
        .ip-badge {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            margin: 3px;
        }
        .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 20px; }
        .stat-box { background: #f8fafc; padding: 15px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 28px; font-weight: 700; color: #667eea; }
        .stat-label { color: #64748b; font-size: 12px; margin-top: 5px; }
        .message { padding: 12px; border-radius: 8px; margin-bottom: 15px; display: none; }
        .message.success { background: #d1fae5; color: #065f46; display: block; }
        .message.error { background: #fee2e2; color: #991b1b; display: block; }
        .btn-remove { background: #ef4444; color: white; border: none; padding: 5px 10px; border-radius: 5px; cursor: pointer; font-size: 12px; }
        .flow-table { width: 100%; border-collapse: collapse; font-size: 12px; }
        .flow-table th { background: #f1f5f9; padding: 10px; text-align: left; font-weight: 600; color: #64748b; border-bottom: 2px solid #e2e8f0; }
        .flow-table td { padding: 8px; border-bottom: 1px solid #e2e8f0; }
        .flow-table tr:hover { background: #f8fafc; }
        .flow-ip { font-family: 'Courier New', monospace; color: #667eea; }
        .flow-port { color: #64748b; font-size: 11px; }
        .flow-proto { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600; }
        .proto-tcp { background: #dbeafe; color: #1e40af; }
        .proto-udp { background: #fef3c7; color: #92400e; }
        .proto-other { background: #f3f4f6; color: #4b5563; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🤖 Modelo ML Simulado - Control de Firewall</h1>
            <span class="status">● Activo</span>
        </div>

        <div class="stats-grid">
            <div class="stat-box">
                <div class="stat-value" id="pcap-count">0</div>
                <div class="stat-label">PCAPs Recibidos</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" id="flow-count">0</div>
                <div class="stat-label">Flows Recibidos</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" id="update-count">0</div>
                <div class="stat-label">Actualizaciones Firewall</div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>➕ Bloquear IP</h2>
                <div id="add-message" class="message"></div>
                <form id="add-form">
                    <div class="form-group">
                        <label>Dirección IP</label>
                        <input type="text" id="ip-input" placeholder="192.168.50.10" pattern="\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" required>
                    </div>
                    <div class="form-group">
                        <label>Categoría</label>
                        <select id="category-input">
                            <option value="malware">Malware</option>
                            <option value="phishing">Phishing</option>
                            <option value="suspicious">Suspicious</option>
                            <option value="port_scan">Port Scan</option>
                            <option value="ddos">DDoS</option>
                            <option value="custom">Personalizada</option>
                        </select>
                    </div>
                    <div class="form-group" id="custom-category-group" style="display:none;">
                        <label>Nombre de categoría personalizada</label>
                        <input type="text" id="custom-category-input" placeholder="mi_categoria">
                    </div>
                    <button type="submit" class="btn btn-primary">Bloquear IP</button>
                </form>
            </div>

            <div class="card">
                <h2>🔥 Acciones Rápidas</h2>
                <div id="action-message" class="message"></div>
                <div style="display: grid; gap: 10px;">
                    <button class="btn btn-success" onclick="triggerUpdate('all')">Enviar Todas las IPs</button>
                    <button class="btn btn-primary" onclick="triggerUpdate('random')">Enviar Subconjunto Aleatorio</button>
                    <button class="btn btn-danger" onclick="clearAll()">Limpiar Todo el Firewall</button>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>📋 Categorías Actuales (<span id="total-ips">0</span> IPs bloqueadas)</h2>
            <div id="categories" class="category-list">
                <p style="color: #64748b; text-align: center; padding: 20px;">Cargando...</p>
            </div>
        </div>

        <div class="card">
            <h2>🌊 Últimos 20 Flows Recibidos</h2>
            <div class="category-list">
                <table class="flow-table">
                    <thead>
                        <tr>
                            <th>Origen</th>
                            <th>Destino</th>
                            <th>Proto</th>
                            <th>Paquetes</th>
                            <th>Bytes</th>
                            <th>Duración</th>
                            <th>Recibido</th>
                        </tr>
                    </thead>
                    <tbody id="flows-table">
                        <tr>
                            <td colspan="7" style="text-align: center; color: #64748b; padding: 20px;">
                                Esperando flows...
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        // Mostrar/ocultar campo de categoría personalizada
        document.getElementById('category-input').addEventListener('change', function() {
            const customGroup = document.getElementById('custom-category-group');
            customGroup.style.display = this.value === 'custom' ? 'block' : 'none';
        });

        // Añadir IP
        document.getElementById('add-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const ip = document.getElementById('ip-input').value;
            let category = document.getElementById('category-input').value;
            
            if (category === 'custom') {
                category = document.getElementById('custom-category-input').value;
                if (!category) {
                    showMessage('add-message', 'Por favor ingresa un nombre de categoría', 'error');
                    return;
                }
            }

            try {
                const response = await fetch('/add_to_category', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({category: category, ips: [ip]})
                });
                const data = await response.json();
                if (response.ok) {
                    showMessage('add-message', `IP ${ip} bloqueada en categoría ${category}`, 'success');
                    document.getElementById('ip-input').value = '';
                    loadCategories();
                    loadStats();
                } else {
                    showMessage('add-message', 'Error al bloquear IP', 'error');
                }
            } catch (error) {
                showMessage('add-message', 'Error de conexión', 'error');
            }
        });

        // Trigger update
        async function triggerUpdate(mode) {
            try {
                const response = await fetch('/trigger', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({mode: mode})
                });
                const data = await response.json();
                if (response.ok) {
                    showMessage('action-message', 'Firewall actualizado exitosamente', 'success');
                    loadStats();
                } else {
                    showMessage('action-message', 'Error al actualizar firewall', 'error');
                }
            } catch (error) {
                showMessage('action-message', 'Error de conexión', 'error');
            }
        }

        // Limpiar todo
        async function clearAll() {
            if (!confirm('¿Estás seguro de limpiar todas las categorías del firewall?')) return;
            try {
                const response = await fetch('/clear_all', {method: 'POST'});
                if (response.ok) {
                    showMessage('action-message', 'Firewall limpiado', 'success');
                    loadCategories();
                    loadStats();
                }
            } catch (error) {
                showMessage('action-message', 'Error de conexión', 'error');
            }
        }

        // Eliminar IP de categoría
        async function removeIP(category, ip) {
            try {
                const response = await fetch('/remove_from_category', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({category: category, ips: [ip]})
                });
                if (response.ok) {
                    loadCategories();
                    loadStats();
                }
            } catch (error) {
                console.error('Error:', error);
            }
        }

        // Mostrar mensaje
        function showMessage(id, text, type) {
            const msg = document.getElementById(id);
            msg.textContent = text;
            msg.className = `message ${type}`;
            setTimeout(() => { msg.style.display = 'none'; }, 3000);
        }

        // Cargar categorías
        async function loadCategories() {
            try {
                const response = await fetch('/get_categories');
                const data = await response.json();
                const container = document.getElementById('categories');
                
                const categories = data.categories || {};
                let totalIPs = 0;
                
                if (Object.keys(categories).length === 0) {
                    container.innerHTML = '<p style="color: #64748b; text-align: center; padding: 20px;">No hay IPs bloqueadas</p>';
                } else {
                    container.innerHTML = '';
                    for (const [category, ips] of Object.entries(categories)) {
                        totalIPs += ips.length;
                        const item = document.createElement('div');
                        item.className = 'category-item';
                        item.innerHTML = `
                            <div class="category-name">
                                <span>${category}</span>
                                <span style="font-size: 12px; color: #64748b;">${ips.length} IPs</span>
                            </div>
                            <div>
                                ${ips.map(ip => `
                                    <span class="ip-badge">
                                        ${ip} 
                                        <button onclick="removeIP('${category}', '${ip}')" style="background:none;border:none;color:white;cursor:pointer;margin-left:5px;">✕</button>
                                    </span>
                                `).join('')}
                            </div>
                        `;
                        container.appendChild(item);
                    }
                }
                
                document.getElementById('total-ips').textContent = totalIPs;
            } catch (error) {
                console.error('Error:', error);
            }
        }

        // Cargar estadísticas
        async function loadStats() {
            try {
                const response = await fetch('/stats');
                const data = await response.json();
                document.getElementById('pcap-count').textContent = data.stats.pcap_received || 0;
                document.getElementById('flow-count').textContent = data.stats.flows_received || 0;
                document.getElementById('update-count').textContent = data.stats.firewall_updates || 0;
            } catch (error) {
                console.error('Error:', error);
            }
        }

        // Cargar flows recientes
        async function loadFlows() {
            try {
                const response = await fetch('/recent_flows');
                const data = await response.json();
                const tbody = document.getElementById('flows-table');
                
                if (data.flows.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 20px;">Esperando flows...</td></tr>';
                } else {
                    tbody.innerHTML = data.flows.map(flow => {
                        const proto = flow.protocol === 6 ? 'TCP' : flow.protocol === 17 ? 'UDP' : 'OTHER';
                        const protoClass = proto === 'TCP' ? 'proto-tcp' : proto === 'UDP' ? 'proto-udp' : 'proto-other';
                        const duration = flow.duration ? flow.duration.toFixed(2) : '0.00';
                        const time = new Date(flow.received_at).toLocaleTimeString();
                        
                        return `
                            <tr>
                                <td>
                                    <span class="flow-ip">${flow.src_ip}</span>
                                    <span class="flow-port">:${flow.src_port}</span>
                                </td>
                                <td>
                                    <span class="flow-ip">${flow.dst_ip}</span>
                                    <span class="flow-port">:${flow.dst_port}</span>
                                </td>
                                <td><span class="flow-proto ${protoClass}">${proto}</span></td>
                                <td>${flow.packets}</td>
                                <td>${formatBytes(flow.bytes)}</td>
                                <td>${duration}s</td>
                                <td style="color: #64748b; font-size: 11px;">${time}</td>
                            </tr>
                        `;
                    }).join('');
                }
            } catch (error) {
                console.error('Error:', error);
            }
        }

        // Formatear bytes
        function formatBytes(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        }

        // Actualizar cada 3 segundos
        loadCategories();
        loadStats();
        loadFlows();
        setInterval(() => {
            loadCategories();
            loadStats();
            loadFlows();
        }, 3000);
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Página principal con interfaz web"""
    return render_template_string(WEB_INTERFACE)

@app.route('/get_categories', methods=['GET'])
def get_categories():
    """Obtener categorías actuales"""
    return jsonify({
        'categories': SIMULATED_THREATS,
        'total_ips': sum(len(ips) for ips in SIMULATED_THREATS.values())
    })

@app.route('/add_to_category', methods=['POST'])
def add_to_category():
    """Añadir IPs a una categoría"""
    global SIMULATED_THREATS
    
    data = request.json
    category = data.get('category')
    ips = data.get('ips', [])
    
    if not category or not ips:
        return jsonify({'error': 'Missing category or ips'}), 400
    
    if category not in SIMULATED_THREATS:
        SIMULATED_THREATS[category] = []
    
    for ip in ips:
        if ip not in SIMULATED_THREATS[category]:
            SIMULATED_THREATS[category].append(ip)
    
    # Enviar al firewall
    send_to_firewall(SIMULATED_THREATS)
    
    return jsonify({
        'status': 'success',
        'category': category,
        'ips_added': len(ips)
    })

@app.route('/remove_from_category', methods=['POST'])
def remove_from_category():
    """Eliminar IPs de una categoría"""
    global SIMULATED_THREATS
    
    data = request.json
    category = data.get('category')
    ips = data.get('ips', [])
    
    if category in SIMULATED_THREATS:
        for ip in ips:
            if ip in SIMULATED_THREATS[category]:
                SIMULATED_THREATS[category].remove(ip)
        
        # Si la categoría quedó vacía, eliminarla
        if not SIMULATED_THREATS[category]:
            del SIMULATED_THREATS[category]
    
    # Enviar al firewall
    send_to_firewall(SIMULATED_THREATS)
    
    return jsonify({'status': 'success'})

@app.route('/clear_all', methods=['POST'])
def clear_all():
    """Limpiar todas las categorías"""
    global SIMULATED_THREATS
    SIMULATED_THREATS = {}
    send_to_firewall({})
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    logger.info("=== Modelo ML Simulado iniciado ===")
    logger.info(f"Configuración inicial de amenazas:")
    for category, ips in SIMULATED_THREATS.items():
        logger.info(f"  {category}: {len(ips)} IPs")
    logger.info("")
    logger.info("Interfaz web disponible en: http://localhost:8000")
    logger.info("")
    
    # Iniciar servidor en puerto 8000
    app.run(host='0.0.0.0', port=8000, debug=False)
