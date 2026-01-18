#!/usr/bin/env python3
"""
config.py - Carga de configuración desde archivo .env
Ubicación: /firewall/router-system/config.py
"""

import os
from pathlib import Path

# Buscar el archivo .env
def find_env_file():
    """Buscar el archivo .env en el directorio actual o en el padre"""
    current_dir = Path(__file__).parent
    
    # Buscar en el directorio actual
    env_file = current_dir / '.env'
    if env_file.exists():
        return env_file
    
    # Buscar en el directorio padre
    env_file = current_dir.parent / '.env'
    if env_file.exists():
        return env_file
    
    # Buscar en /firewall/
    env_file = current_dir.parent.parent / 'firewall' / '.env'
    if env_file.exists():
        return env_file
    
    return None

def load_env():
    """Cargar variables del archivo .env"""
    env_file = find_env_file()
    
    if not env_file:
        print("⚠ Advertencia: No se encontró archivo .env, usando valores por defecto")
        return
    
    with open(env_file, 'r') as f:
        for line in f:
            line = line.strip()
            
            # Ignorar comentarios y líneas vacías
            if not line or line.startswith('#'):
                continue
            
            # Separar clave=valor
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Remover comillas si existen
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                elif value.startswith("'") and value.endswith("'"):
                    value = value[1:-1]
                
                # Establecer variable de entorno si no existe
                if key not in os.environ:
                    os.environ[key] = value

# Cargar variables al importar el módulo
load_env()

# ============================================
# CONFIGURACIÓN GENERAL DEL SISTEMA
# ============================================

# Interfaces de red
AP_IFACE = os.getenv('AP_IFACE', 'wlxc83a35b5a9f5')
INTERNET_IFACE = os.getenv('INTERNET_IFACE', 'wlp2s0')

# Configuración WiFi
WIFI_SSID = os.getenv('WIFI_SSID', 'RouterFirewall')
WIFI_PASSWORD = os.getenv('WIFI_PASSWORD', 'SecurePass123')
WIFI_CHANNEL = int(os.getenv('WIFI_CHANNEL', '6'))

# Red del punto de acceso
AP_NETWORK = os.getenv('AP_NETWORK', '192.168.50.0/24')
AP_GATEWAY = os.getenv('AP_GATEWAY', '192.168.50.1')
AP_DHCP_START = os.getenv('AP_DHCP_START', '192.168.50.20')
AP_DHCP_END = os.getenv('AP_DHCP_END', '192.168.50.100')

# ============================================
# MODELO Y SERVICIOS
# ============================================

# Modelo a utilizar
MODEL_TYPE = os.getenv('MODEL_TYPE', 'ml_flows')

# URLs de los modelos
MODEL_ML_URL = os.getenv('MODEL_ML_URL', 'http://localhost:5001')
MODEL_SIMULATED_URL = os.getenv('MODEL_SIMULATED_URL', 'http://localhost:8000')
MODEL_DL_URL = os.getenv('MODEL_DL_URL', 'http://localhost:5002')

# Puerto de cada servicio
MODEL_ML_PORT = int(os.getenv('MODEL_ML_PORT', '5001'))
MODEL_SIMULATED_PORT = int(os.getenv('MODEL_SIMULATED_PORT', '8000'))
MODEL_DL_PORT = int(os.getenv('MODEL_DL_PORT', '5002'))
FIREWALL_PORT = int(os.getenv('FIREWALL_PORT', '5000'))
DASHBOARD_PORT = int(os.getenv('DASHBOARD_PORT', '8081'))

# Determinar URL del modelo según el tipo
if MODEL_TYPE == 'ml_flows':
    MODEL_BASE_URL = MODEL_ML_URL
    MODEL_PORT = MODEL_ML_PORT
elif MODEL_TYPE == 'simulated_flows':
    MODEL_BASE_URL = MODEL_SIMULATED_URL
    MODEL_PORT = MODEL_SIMULATED_PORT
elif MODEL_TYPE == 'dl_packets':
    MODEL_BASE_URL = MODEL_DL_URL
    MODEL_PORT = MODEL_DL_PORT
else:
    # Fallback para compatibilidad
    if MODEL_TYPE == 'ml':
        MODEL_BASE_URL = MODEL_ML_URL
        MODEL_PORT = MODEL_ML_PORT
    elif MODEL_TYPE == 'simulated':
        MODEL_BASE_URL = MODEL_SIMULATED_URL
        MODEL_PORT = MODEL_SIMULATED_PORT
    else:
        MODEL_BASE_URL = MODEL_ML_URL
        MODEL_PORT = MODEL_ML_PORT

# ============================================
# CAPTURA DE TRÁFICO
# ============================================

# Modo de captura (auto-detectado según MODEL_TYPE)
_capture_mode = os.getenv('TRAFFIC_CAPTURE_MODE', '')
if not _capture_mode:
    # Auto-detectar según el modelo
    if 'packets' in MODEL_TYPE or 'dl' in MODEL_TYPE:
        TRAFFIC_CAPTURE_MODE = 'packets'
    else:
        TRAFFIC_CAPTURE_MODE = 'flows'
else:
    TRAFFIC_CAPTURE_MODE = _capture_mode

# Configuración para captura de FLOWS
FLOW_BUFFER_SIZE = int(os.getenv('FLOW_BUFFER_SIZE', '100'))
FLOW_SEND_INTERVAL = int(os.getenv('FLOW_SEND_INTERVAL', '10'))
FLOW_IDLE_THRESHOLD = float(os.getenv('FLOW_IDLE_THRESHOLD', '1.0'))
FLOW_CLEANUP_INTERVAL = int(os.getenv('FLOW_CLEANUP_INTERVAL', '300'))

# Configuración para captura de PACKETS
PCAP_BUFFER_SIZE = int(os.getenv('PCAP_BUFFER_SIZE', '1000'))
PCAP_SEND_INTERVAL = int(os.getenv('PCAP_SEND_INTERVAL', '30'))
PACKET_STATS_INTERVAL = int(os.getenv('PACKET_STATS_INTERVAL', '60'))

# Archivos temporales
PCAP_BUFFER_FILE = os.getenv('PCAP_BUFFER_FILE', '/tmp/traffic_buffer.pcap')
FLOW_BUFFER_FILE = os.getenv('FLOW_BUFFER_FILE', '/tmp/flow_buffer.json')

# ============================================
# LOGS
# ============================================

MODEL_ML_LOG = os.getenv('MODEL_ML_LOG', '/tmp/model_server.log')
MODEL_SIMULATED_LOG = os.getenv('MODEL_SIMULATED_LOG', '/tmp/model.log')
FIREWALL_LOG = os.getenv('FIREWALL_LOG', '/tmp/firewall.log')
DASHBOARD_LOG = os.getenv('DASHBOARD_LOG', '/tmp/dashboard.log')
TRAFFIC_CAPTURE_LOG = os.getenv('TRAFFIC_CAPTURE_LOG', '/tmp/traffic_capture.log')
ROUTER_LOG = os.getenv('ROUTER_LOG', '/tmp/router.log')

# Determinar log del modelo según el tipo
if MODEL_TYPE == 'ml':
    MODEL_LOG = MODEL_ML_LOG
else:
    MODEL_LOG = MODEL_SIMULATED_LOG

# ============================================
# TIMEOUTS Y REINTENTOS
# ============================================

HTTP_TIMEOUT = int(os.getenv('HTTP_TIMEOUT', '10'))
HTTP_RETRIES = int(os.getenv('HTTP_RETRIES', '3'))
SERVICE_START_DELAY = int(os.getenv('SERVICE_START_DELAY', '3'))

# ============================================
# FUNCIONES DE UTILIDAD
# ============================================

def get_capture_script():
    """Retorna el nombre del script de captura según el modo configurado"""
    if TRAFFIC_CAPTURE_MODE == 'packets' or 'dl' in MODEL_TYPE:
        return 'traffic_capture_packets.py'
    else:
        return 'traffic_capture.py'

def get_model_dir():
    """Retorna el directorio del modelo según el tipo configurado"""
    if MODEL_TYPE == 'ml_flows' or MODEL_TYPE == 'ml':
        return 'model_ml'
    elif MODEL_TYPE == 'simulated_flows' or MODEL_TYPE == 'simulated':
        return 'simulated-model'
    elif MODEL_TYPE == 'dl_packets' or MODEL_TYPE == 'dl':
        return 'model_dl'
    else:
        return 'model_ml'  # default

# ============================================
# ENDPOINTS (deben definirse después de las funciones)
# ============================================

PCAP_ENDPOINT = f'{MODEL_BASE_URL}/pcap'
FLOWS_ENDPOINT = f'{MODEL_BASE_URL}/flows'
FIREWALL_API_URL = f'http://{AP_GATEWAY}:{FIREWALL_PORT}'

def print_config():
    """Imprime la configuración actual"""
    print("=" * 60)
    print("CONFIGURACIÓN DEL SISTEMA")
    print("=" * 60)
    print(f"Interfaces:")
    print(f"  - AP: {AP_IFACE}")
    print(f"  - Internet: {INTERNET_IFACE}")
    print(f"\nWiFi:")
    print(f"  - SSID: {WIFI_SSID}")
    print(f"  - Channel: {WIFI_CHANNEL}")
    print(f"\nRed AP:")
    print(f"  - Network: {AP_NETWORK}")
    print(f"  - Gateway: {AP_GATEWAY}")
    print(f"  - DHCP: {AP_DHCP_START} - {AP_DHCP_END}")
    print(f"\nModelo:")
    print(f"  - Tipo: {MODEL_TYPE}")
    print(f"  - Directorio: {get_model_dir()}")
    print(f"  - URL: {MODEL_BASE_URL}")
    print(f"  - Puerto: {MODEL_PORT}")
    print(f"\nCaptura:")
    print(f"  - Modo: {TRAFFIC_CAPTURE_MODE}")
    print(f"  - Script: {get_capture_script()}")
    if TRAFFIC_CAPTURE_MODE == 'flows':
        print(f"  - Flow buffer: {FLOW_BUFFER_SIZE}")
        print(f"  - Flow interval: {FLOW_SEND_INTERVAL}s")
        print(f"  - Flow cleanup: {FLOW_CLEANUP_INTERVAL}s")
    else:
        print(f"  - PCAP buffer: {PCAP_BUFFER_SIZE}")
        print(f"  - PCAP interval: {PCAP_SEND_INTERVAL}s")
        print(f"  - Stats interval: {PACKET_STATS_INTERVAL}s")
    print(f"\nEndpoints:")
    print(f"  - PCAP: {PCAP_ENDPOINT}")
    print(f"  - Flows: {FLOWS_ENDPOINT}")
    print("=" * 60)

if __name__ == '__main__':
    print_config()
