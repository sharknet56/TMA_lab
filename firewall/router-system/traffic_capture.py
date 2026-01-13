#!/usr/bin/env python3
"""
traffic_capture.py - Captura de tráfico y envío al modelo
Ubicación: /etc/router-system/traffic_capture.py
"""

from scapy.all import sniff, wrpcap, IP, TCP, UDP
import requests
import threading
import time
import json
import logging
from datetime import datetime
from collections import defaultdict
import os

# Configuración
INTERFACE = 'wlxc83a35b5a9f5'  # Interfaz del punto de acceso
PCAP_BUFFER_FILE = '/tmp/traffic_buffer.pcap'
FLOW_BUFFER_FILE = '/tmp/flow_buffer.json'

# Endpoints del modelo (modificar según tu configuración)
MODEL_BASE_URL = os.getenv('MODEL_URL', 'http://localhost:8000')
PCAP_ENDPOINT = f'{MODEL_BASE_URL}/pcap'
FLOWS_ENDPOINT = f'{MODEL_BASE_URL}/flows'

# Configuración de buffers
PCAP_BUFFER_SIZE = 1000  # Paquetes antes de enviar
PCAP_SEND_INTERVAL = 30  # Segundos
FLOW_SEND_INTERVAL = 10  # Segundos

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Buffers globales
packet_buffer = []
packet_lock = threading.Lock()

# Estructura para flows
flows = defaultdict(lambda: {
    'packets': 0,
    'bytes': 0,
    'start_time': None,
    'end_time': None,
    'src_port': None,
    'dst_port': None,
    'protocol': None,
    'flags': set()
})
flows_lock = threading.Lock()

stats = {
    'total_packets': 0,
    'total_bytes': 0,
    'pcap_sends': 0,
    'flow_sends': 0,
    'last_pcap_send': None,
    'last_flow_send': None,
    'errors': 0
}

def create_flow_key(packet):
    """Crear clave única para un flow (5-tupla)"""
    if IP not in packet:
        return None
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    
    src_port = 0
    dst_port = 0
    
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    
    # Normalizar para bidireccionalidad
    if src_ip < dst_ip:
        return (src_ip, dst_ip, src_port, dst_port, proto)
    else:
        return (dst_ip, src_ip, dst_port, src_port, proto)

def update_flow(packet):
    """Actualizar información de flow"""
    flow_key = create_flow_key(packet)
    if not flow_key:
        return
    
    with flows_lock:
        flow = flows[flow_key]
        current_time = datetime.now()
        
        # Inicializar si es nuevo
        if flow['start_time'] is None:
            flow['start_time'] = current_time
            flow['src_port'] = flow_key[2]
            flow['dst_port'] = flow_key[3]
            flow['protocol'] = flow_key[4]
        
        # Actualizar estadísticas
        flow['packets'] += 1
        flow['bytes'] += len(packet)
        flow['end_time'] = current_time
        
        # Flags TCP
        if TCP in packet:
            tcp_flags = packet[TCP].flags
            if tcp_flags & 0x02:  # SYN
                flow['flags'].add('SYN')
            if tcp_flags & 0x10:  # ACK
                flow['flags'].add('ACK')
            if tcp_flags & 0x01:  # FIN
                flow['flags'].add('FIN')
            if tcp_flags & 0x04:  # RST
                flow['flags'].add('RST')

def packet_handler(packet):
    """Procesar cada paquete capturado"""
    global packet_buffer, stats
    
    # Actualizar estadísticas
    stats['total_packets'] += 1
    if IP in packet:
        stats['total_bytes'] += len(packet)
    
    # Añadir al buffer PCAP
    with packet_lock:
        packet_buffer.append(packet)
    
    # Actualizar flows
    update_flow(packet)
    
    # Enviar si el buffer está lleno
    if len(packet_buffer) >= PCAP_BUFFER_SIZE:
        threading.Thread(target=send_pcap_buffer, daemon=True).start()

def send_pcap_buffer():
    """Enviar buffer PCAP al modelo"""
    global packet_buffer, stats
    
    with packet_lock:
        if not packet_buffer:
            return
        
        # Copiar buffer y limpiar
        packets_to_send = packet_buffer[:]
        packet_buffer = []
    
    try:
        # Guardar en archivo temporal
        wrpcap(PCAP_BUFFER_FILE, packets_to_send)
        
        # Enviar al modelo
        with open(PCAP_BUFFER_FILE, 'rb') as f:
            files = {'file': ('traffic.pcap', f, 'application/vnd.tcpdump.pcap')}
            
            logger.info(f"Enviando {len(packets_to_send)} paquetes al modelo...")
            response = requests.post(
                PCAP_ENDPOINT,
                files=files,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"PCAP enviado exitosamente: {response.status_code}")
                stats['pcap_sends'] += 1
                stats['last_pcap_send'] = datetime.now().isoformat()
            else:
                logger.warning(f"Error enviando PCAP: {response.status_code}")
                stats['errors'] += 1
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error de red enviando PCAP: {e}")
        stats['errors'] += 1
    except Exception as e:
        logger.error(f"Error enviando PCAP: {e}")
        stats['errors'] += 1
    finally:
        # Limpiar archivo temporal
        if os.path.exists(PCAP_BUFFER_FILE):
            os.remove(PCAP_BUFFER_FILE)

def export_flows():
    """Exportar flows a formato JSON"""
    with flows_lock:
        exported_flows = []
        current_time = datetime.now()
        
        for flow_key, flow_data in list(flows.items()):
            if flow_data['start_time'] is None:
                continue
            
            duration = (flow_data['end_time'] - flow_data['start_time']).total_seconds()
            
            flow_export = {
                'src_ip': flow_key[0],
                'dst_ip': flow_key[1],
                'src_port': flow_data['src_port'],
                'dst_port': flow_data['dst_port'],
                'protocol': flow_data['protocol'],
                'packets': flow_data['packets'],
                'bytes': flow_data['bytes'],
                'duration': duration,
                'start_time': flow_data['start_time'].isoformat(),
                'end_time': flow_data['end_time'].isoformat(),
                'flags': list(flow_data['flags']),
                'packets_per_second': flow_data['packets'] / duration if duration > 0 else 0,
                'bytes_per_second': flow_data['bytes'] / duration if duration > 0 else 0
            }
            
            exported_flows.append(flow_export)
        
        # Limpiar flows antiguos (más de 5 minutos sin actividad)
        for flow_key in list(flows.keys()):
            if flows[flow_key]['end_time']:
                age = (current_time - flows[flow_key]['end_time']).total_seconds()
                if age > 300:  # 5 minutos
                    del flows[flow_key]
        
        return exported_flows

def send_flows():
    """Enviar flows al modelo"""
    global stats
    
    try:
        flows_data = export_flows()
        
        if not flows_data:
            logger.debug("No hay flows para enviar")
            return
        
        logger.info(f"Enviando {len(flows_data)} flows al modelo...")
        
        response = requests.post(
            FLOWS_ENDPOINT,
            json={'flows': flows_data},
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if response.status_code == 200:
            logger.info(f"Flows enviados exitosamente: {len(flows_data)} flows")
            stats['flow_sends'] += 1
            stats['last_flow_send'] = datetime.now().isoformat()
        else:
            logger.warning(f"Error enviando flows: {response.status_code}")
            stats['errors'] += 1
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error de red enviando flows: {e}")
        stats['errors'] += 1
    except Exception as e:
        logger.error(f"Error enviando flows: {e}")
        stats['errors'] += 1

def periodic_pcap_send():
    """Enviar PCAP periódicamente"""
    while True:
        time.sleep(PCAP_SEND_INTERVAL)
        
        with packet_lock:
            if packet_buffer:
                threading.Thread(target=send_pcap_buffer, daemon=True).start()

def periodic_flow_send():
    """Enviar flows periódicamente"""
    while True:
        time.sleep(FLOW_SEND_INTERVAL)
        send_flows()

def print_stats():
    """Imprimir estadísticas periódicamente"""
    while True:
        time.sleep(60)  # Cada minuto
        logger.info(f"Stats: {stats['total_packets']} packets, "
                   f"{stats['total_bytes']} bytes, "
                   f"{stats['pcap_sends']} PCAP sends, "
                   f"{stats['flow_sends']} flow sends, "
                   f"{stats['errors']} errors")

def capture_traffic():
    """Iniciar captura de tráfico"""
    logger.info(f"Iniciando captura de tráfico en {INTERFACE}...")
    logger.info(f"Enviando PCAPs a: {PCAP_ENDPOINT}")
    logger.info(f"Enviando flows a: {FLOWS_ENDPOINT}")
    
    try:
        sniff(
            iface=INTERFACE,
            prn=packet_handler,
            store=False
        )
    except KeyboardInterrupt:
        logger.info("Captura detenida por usuario")
    except Exception as e:
        logger.error(f"Error en captura: {e}")

if __name__ == '__main__':
    logger.info("=== Traffic Capture iniciado ===")
    
    # Iniciar threads periódicos
    threading.Thread(target=periodic_pcap_send, daemon=True).start()
    threading.Thread(target=periodic_flow_send, daemon=True).start()
    threading.Thread(target=print_stats, daemon=True).start()
    
    # Iniciar captura (bloqueante)
    try:
        capture_traffic()
    except KeyboardInterrupt:
        logger.info("Deteniendo captura...")
        # Enviar últimos datos
        send_pcap_buffer()
        send_flows()
        logger.info("Captura finalizada")