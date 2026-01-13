#!/usr/bin/env python3
"""
dashboard.py - Dashboard web para monitorización del router
Ubicación: /etc/router-system/dashboard.py
"""

from flask import Flask, render_template_string, jsonify
import subprocess
import re
import time
import psutil
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)

# Leer configuración de interfaces desde router-control.sh o /etc/router-system/config
def get_ap_interface():
    """Obtener la interfaz AP desde la configuración"""
    try:
        # Intentar leer desde el script de control
        with open('/etc/router-system/router-control.sh', 'r') as f:
            for line in f:
                if line.strip().startswith('AP_IFACE='):
                    # Extraer el valor entre comillas
                    match = re.search(r'AP_IFACE="([^"]+)"', line)
                    if match:
                        return match.group(1)
    except:
        pass
    
    # Fallback a la interfaz por defecto
    return 'wlxc83a35b5a9f5'

AP_INTERFACE = get_ap_interface()

# Template HTML
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Router Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        .header h1 {
            color: #667eea;
            font-size: 32px;
            margin-bottom: 10px;
        }
        
        .status-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 14px;
        }
        
        .status-active {
            background: #10b981;
            color: white;
        }
        
        .status-inactive {
            background: #ef4444;
            color: white;
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            transition: transform 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
        }
        
        .card h2 {
            color: #333;
            font-size: 20px;
            margin-bottom: 15px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        
        .stat {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin: 12px 0;
            padding: 10px;
            background: #f8fafc;
            border-radius: 8px;
        }
        
        .stat-label {
            color: #64748b;
            font-weight: 500;
        }
        
        .stat-value {
            color: #667eea;
            font-weight: 700;
            font-size: 18px;
        }
        
        .category-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .category-item {
            margin: 10px 0;
            padding: 12px;
            background: #f1f5f9;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            position: relative;
        }
        
        .category-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        
        .category-name {
            font-weight: 700;
            color: #333;
        }
        
        .category-controls {
            display: flex;
            gap: 8px;
            align-items: center;
        }
        
        .toggle-btn {
            background: #10b981;
            color: white;
            border: none;
            padding: 5px 12px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            transition: background 0.2s;
        }
        
        .toggle-btn:hover {
            background: #059669;
        }
        
        .toggle-btn.disabled {
            background: #ef4444;
        }
        
        .toggle-btn.disabled:hover {
            background: #dc2626;
        }
        
        .clear-btn {
            background: #f59e0b;
            color: white;
            border: none;
            padding: 5px 12px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
        }
        
        .clear-btn:hover {
            background: #d97706;
        }
        
        .ip-badge {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            margin: 3px;
        }
        
        .client-list {
            max-height: 300px;
            overflow-y: auto;
        }
        
        .client-item {
            padding: 10px;
            margin: 8px 0;
            background: #f8fafc;
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .mac-address {
            font-family: 'Courier New', monospace;
            color: #667eea;
            font-weight: 600;
        }
        
        .last-update {
            text-align: center;
            color: rgba(255, 255, 255, 0.9);
            margin-top: 20px;
            font-size: 14px;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .updating {
            animation: pulse 2s infinite;
        }
        
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #667eea;
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #764ba2;
        }
        
        .metric-big {
            font-size: 36px;
            font-weight: 700;
            color: #667eea;
            text-align: center;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Router & Firewall Dashboard</h1>
            <span id="status-badge" class="status-badge">Cargando...</span>
        </div>
        
        <div class="grid">
            <div class="card">
                <h2>📊 Estadísticas del Sistema</h2>
                <div class="stat">
                    <span class="stat-label">CPU</span>
                    <span class="stat-value" id="cpu-usage">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Memoria</span>
                    <span class="stat-value" id="mem-usage">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Uptime</span>
                    <span class="stat-value" id="uptime">-</span>
                </div>
            </div>
            
            <div class="card">
                <h2>🌐 Información de Red</h2>
                <div class="stat">
                    <span class="stat-label">Clientes Conectados</span>
                    <span class="stat-value" id="connected-clients">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">IP del Router</span>
                    <span class="stat-value" id="router-ip">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Interfaz AP</span>
                    <span class="stat-value" id="ap-interface">-</span>
                </div>
            </div>
            
            <div class="card">
                <h2>🔥 Estado del Firewall</h2>
                <div class="metric-big" id="blocked-ips">0</div>
                <div style="text-align: center; color: #64748b; margin-bottom: 15px;">IPs Bloqueadas</div>
                <div class="stat">
                    <span class="stat-label">Categorías Activas</span>
                    <span class="stat-value" id="active-categories">-</span>
                </div>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h2>🚫 Categorías de Bloqueo</h2>
                <div id="categories-list" class="category-list">
                    <div style="text-align: center; color: #94a3b8; padding: 20px;">
                        No hay categorías activas
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>👥 Clientes Conectados</h2>
                <div id="clients-list" class="client-list">
                    <div style="text-align: center; color: #94a3b8; padding: 20px;">
                        No hay clientes conectados
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>📈 Tráfico de Red</h2>
                <div class="stat">
                    <span class="stat-label">Bytes Enviados</span>
                    <span class="stat-value" id="bytes-sent">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Bytes Recibidos</span>
                    <span class="stat-value" id="bytes-recv">-</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Paquetes Totales</span>
                    <span class="stat-value" id="packets-total">-</span>
                </div>
            </div>
        </div>
        
        <div class="last-update">
            Última actualización: <span id="last-update">-</span>
        </div>
    </div>
    
    <script>
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
        }
        
        function formatUptime(seconds) {
            const days = Math.floor(seconds / 86400);
            const hours = Math.floor((seconds % 86400) / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            
            if (days > 0) return `${days}d ${hours}h`;
            if (hours > 0) return `${hours}h ${minutes}m`;
            return `${minutes}m`;
        }
        
        function updateDashboard() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    // Estado
                    const statusBadge = document.getElementById('status-badge');
                    if (data.router_active) {
                        statusBadge.textContent = '🟢 Router Activo';
                        statusBadge.className = 'status-badge status-active';
                    } else {
                        statusBadge.textContent = '🔴 Router Inactivo';
                        statusBadge.className = 'status-badge status-inactive';
                    }
                    
                    // Sistema
                    document.getElementById('cpu-usage').textContent = data.system.cpu + '%';
                    document.getElementById('mem-usage').textContent = data.system.memory + '%';
                    document.getElementById('uptime').textContent = formatUptime(data.system.uptime);
                    
                    // Red
                    document.getElementById('connected-clients').textContent = data.network.clients;
                    document.getElementById('router-ip').textContent = data.network.router_ip || '-';
                    document.getElementById('ap-interface').textContent = data.network.ap_interface || '-';
                    
                    // Firewall
                    document.getElementById('blocked-ips').textContent = data.firewall.blocked_ips;
                    document.getElementById('active-categories').textContent = data.firewall.categories;
                    
                    // Categorías
                    const categoriesList = document.getElementById('categories-list');
                    if (data.firewall.category_details && Object.keys(data.firewall.category_details).length > 0) {
                        let html = '';
                        for (const [category, ips] of Object.entries(data.firewall.category_details)) {
                            const isEnabled = data.firewall.active_category_list ? data.firewall.active_category_list.includes(category) : true;
                            html += `
                                <div class="category-item">
                                    <div class="category-header">
                                        <span class="category-name">${category}</span>
                                        <div class="category-controls">
                                            <button class="toggle-btn ${isEnabled ? '' : 'disabled'}" 
                                                    onclick="toggleCategory('${category}', ${!isEnabled})">
                                                ${isEnabled ? '🔴 Desactivar' : '🟢 Activar'}
                                            </button>
                                            <button class="clear-btn" onclick="clearCategory('${category}')">
                                                🗑️ Limpiar
                                            </button>
                                        </div>
                                    </div>
                                    <div>
                                        ${ips.map(ip => `<span class="ip-badge">${ip}</span>`).join('')}
                                    </div>
                                </div>
                            `;
                        }
                        categoriesList.innerHTML = html;
                    } else {
                        categoriesList.innerHTML = '<div style="text-align: center; color: #94a3b8; padding: 20px;">No hay categorías activas</div>';
                    }
                    
                    // Clientes
                    const clientsList = document.getElementById('clients-list');
                    if (data.network.client_details && data.network.client_details.length > 0) {
                        let html = '';
                        data.network.client_details.forEach(client => {
                            html += `
                                <div class="client-item">
                                    <div>
                                        <div class="mac-address">${client.mac}</div>
                                        <div style="font-size: 12px; color: #64748b; margin-top: 3px;">
                                            IP: ${client.ip || 'Pendiente'}
                                        </div>
                                    </div>
                                    <span style="color: #10b981; font-weight: 600;">${client.signal || '-'}</span>
                                </div>
                            `;
                        });
                        clientsList.innerHTML = html;
                    } else {
                        clientsList.innerHTML = '<div style="text-align: center; color: #94a3b8; padding: 20px;">No hay clientes conectados</div>';
                    }
                    
                    // Tráfico
                    document.getElementById('bytes-sent').textContent = formatBytes(data.network.bytes_sent);
                    document.getElementById('bytes-recv').textContent = formatBytes(data.network.bytes_recv);
                    document.getElementById('packets-total').textContent = data.network.packets_total.toLocaleString();
                    
                    // Última actualización
                    document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
                })
                .catch(error => {
                    console.error('Error actualizando dashboard:', error);
                });
        }
        
        function toggleCategory(category, enable) {
            fetch('http://192.168.50.1:5000/toggle_category', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    category: category,
                    enabled: enable
                })
            })
            .then(response => response.json())
            .then(data => {
                console.log('Toggle category response:', data);
                updateDashboard(); // Actualizar inmediatamente
            })
            .catch(error => {
                console.error('Error toggling category:', error);
                alert('Error al cambiar estado de categoría');
            });
        }
        
        function clearCategory(category) {
            if (!confirm(`¿Estás seguro de que quieres eliminar todas las IPs de la categoría "${category}"?`)) {
                return;
            }
            
            fetch('http://192.168.50.1:5000/clear_category', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    category: category
                })
            })
            .then(response => response.json())
            .then(data => {
                console.log('Clear category response:', data);
                updateDashboard(); // Actualizar inmediatamente
            })
            .catch(error => {
                console.error('Error clearing category:', error);
                alert('Error al limpiar categoría');
            });
        }
        
        // Actualizar cada 2 segundos
        updateDashboard();
        setInterval(updateDashboard, 2000);
    </script>
</body>
</html>
"""

def run_command(cmd):
    """Ejecutar comando y retornar output"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return result.stdout
    except Exception:
        return ""

def get_system_stats():
    """Obtener estadísticas del sistema"""
    return {
        'cpu': round(psutil.cpu_percent(interval=1), 1),
        'memory': round(psutil.virtual_memory().percent, 1),
        'uptime': int(time.time() - psutil.boot_time())
    }

def get_network_stats():
    """Obtener estadísticas de red"""
    stats = {
        'clients': 0,
        'router_ip': '192.168.50.1',
        'ap_interface': AP_INTERFACE,
        'bytes_sent': 0,
        'bytes_recv': 0,
        'packets_total': 0,
        'client_details': []
    }
    
    try:
        # Obtener clientes conectados desde iw
        output = run_command(['iw', 'dev', AP_INTERFACE, 'station', 'dump'])
        
        clients = []
        current_client = {}
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('Station'):
                if current_client:
                    clients.append(current_client)
                mac = line.split()[1]
                current_client = {'mac': mac, 'ip': None, 'signal': None}
            elif 'signal:' in line:
                signal = re.search(r'signal:\s+([-\d]+)', line)
                if signal:
                    current_client['signal'] = signal.group(1) + ' dBm'
        
        if current_client:
            clients.append(current_client)
        
        # Obtener IPs desde dnsmasq leases
        try:
            leases_output = run_command(['sudo', 'cat', '/var/lib/misc/dnsmasq.leases'])
            mac_to_ip = {}
            
            for line in leases_output.split('\n'):
                parts = line.split()
                if len(parts) >= 3:
                    # Formato: timestamp mac ip hostname client-id
                    mac_to_ip[parts[1]] = parts[2]
            
            # Asociar IPs con MACs
            for client in clients:
                client['ip'] = mac_to_ip.get(client['mac'], 'Pendiente')
        except Exception as e:
            print(f"Error obteniendo leases: {e}")
        
        stats['clients'] = len(clients)
        stats['client_details'] = clients
        
        # Estadísticas de tráfico
        net_io = psutil.net_io_counters(pernic=True).get(AP_INTERFACE, None)
        if net_io:
            stats['bytes_sent'] = net_io.bytes_sent
            stats['bytes_recv'] = net_io.bytes_recv
            stats['packets_total'] = net_io.packets_sent + net_io.packets_recv
    
    except Exception as e:
        print(f"Error obteniendo stats de red: {e}")
    
    return stats

def get_firewall_stats():
    """Obtener estadísticas del firewall"""
    stats = {
        'blocked_ips': 0,
        'categories': 0,
        'category_details': {}
    }
    
    try:
        # Obtener categorías del firewall manager
        import requests
        response = requests.get('http://localhost:5000/get_categories', timeout=2)
        if response.status_code == 200:
            data = response.json()
            categories = data.get('categories', {})
            active_categories = data.get('active_categories', [])
            stats['categories'] = len(categories)
            stats['category_details'] = categories
            stats['active_category_list'] = active_categories
            stats['blocked_ips'] = sum(len(ips) for ips in categories.values())
    except Exception as e:
        # Si el servicio no está disponible, obtener de iptables
        output = run_command(['iptables', '-L', 'CATEGORY_FILTER', '-n', '-v'])
        
        categories = defaultdict(list)
        for line in output.split('\n'):
            if 'cat:' in line:
                match = re.search(r'cat:(\w+)', line)
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match and ip_match:
                    category = match.group(1)
                    ip = ip_match.group(1)
                    if ip not in categories[category]:
                        categories[category].append(ip)
        
        stats['categories'] = len(categories)
        stats['category_details'] = dict(categories)
        stats['blocked_ips'] = sum(len(ips) for ips in categories.values())
    
    return stats

def check_router_active():
    """Verificar si el modo router está activo"""
    try:
        with open('/etc/router-system/router.state', 'r') as f:
            return f.read().strip() == 'active'
    except:
        return False

@app.route('/')
def index():
    """Página principal del dashboard"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/status')
def api_status():
    """API endpoint para obtener estado del sistema"""
    return jsonify({
        'router_active': check_router_active(),
        'system': get_system_stats(),
        'network': get_network_stats(),
        'firewall': get_firewall_stats(),
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("=== Dashboard iniciado ===")
    print("Accede a: http://192.168.50.1:8081")
    app.run(host='0.0.0.0', port=8081, debug=False)