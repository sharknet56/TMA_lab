#!/usr/bin/env python3
"""
traffic_capture_packets.py - Captura de tráfico y envío de PACKETS al modelo
Ubicación: router-system/traffic_capture_packets.py
Modo: PACKETS (archivos PCAP completos para Deep Learning)
"""

from scapy.all import sniff, wrpcap, IP, TCP, UDP
import requests
import threading
import time
import logging
from datetime import datetime
import os

# Importar configuración centralizada
try:
    from config import (
        AP_IFACE as INTERFACE,
        PCAP_BUFFER_FILE,
        PCAP_ENDPOINT,
        PCAP_BUFFER_SIZE,
        PCAP_SEND_INTERVAL,
        PACKET_STATS_INTERVAL,
        HTTP_TIMEOUT,
        TRAFFIC_CAPTURE_LOG
    )
    CONFIG_LOADED = True
except ImportError:
    print("⚠ Advertencia: config.py no encontrado, usando valores por defecto")
    INTERFACE = 'wlxc83a35b5a9f5'
    PCAP_BUFFER_FILE = '/tmp/traffic_buffer.pcap'
    MODEL_BASE_URL = os.getenv('MODEL_URL', 'http://localhost:5002')
    PCAP_ENDPOINT = f'{MODEL_BASE_URL}/pcap'
    PCAP_BUFFER_SIZE = 1000
    PCAP_SEND_INTERVAL = 30
    PACKET_STATS_INTERVAL = 60
    HTTP_TIMEOUT = 10
    TRAFFIC_CAPTURE_LOG = '/tmp/traffic_capture.log'
    CONFIG_LOADED = False

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(TRAFFIC_CAPTURE_LOG),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Buffers globales (solo packets, no flows)
packet_buffer = []
packet_lock = threading.Lock()

stats = {
    'total_packets': 0,
    'total_bytes': 0,
    'pcap_sends': 0,
    'last_pcap_send': None,
    'errors': 0,
    'tcp_packets': 0,
    'udp_packets': 0,
    'other_packets': 0
}

def packet_handler(packet):
    """Procesar cada paquete capturado (solo añadir al buffer, no flows)"""
    global packet_buffer, stats
    
    # Actualizar estadísticas
    stats['total_packets'] += 1
    
    if IP in packet:
        stats['total_bytes'] += len(packet)
        
        # Clasificar por protocolo
        if TCP in packet:
            stats['tcp_packets'] += 1
        elif UDP in packet:
            stats['udp_packets'] += 1
        else:
            stats['other_packets'] += 1
    
    # Añadir al buffer PCAP
    with packet_lock:
        packet_buffer.append(packet)
    
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
                timeout=HTTP_TIMEOUT
            )
            
            if response.status_code == 200:
                logger.info(f"PCAP enviado exitosamente: {len(packets_to_send)} paquetes")
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

def periodic_pcap_send():
    """Enviar PCAP periódicamente"""
    while True:
        time.sleep(PCAP_SEND_INTERVAL)
        
        with packet_lock:
            if packet_buffer:
                threading.Thread(target=send_pcap_buffer, daemon=True).start()

def print_stats():
    """Imprimir estadísticas periódicamente"""
    while True:
        time.sleep(PACKET_STATS_INTERVAL)
        logger.info(f"Stats: {stats['total_packets']} total packets "
                   f"(TCP: {stats['tcp_packets']}, UDP: {stats['udp_packets']}, "
                   f"Other: {stats['other_packets']}), "
                   f"{stats['total_bytes']} bytes, "
                   f"{stats['pcap_sends']} PCAP sends, "
                   f"{stats['errors']} errors")

def capture_traffic():
    """Iniciar captura de tráfico"""
    logger.info(f"=== Traffic Capture (PACKETS) iniciado ===")
    logger.info(f"Configuración cargada: {'✓' if CONFIG_LOADED else '✗ (usando defaults)'}")
    logger.info(f"Interfaz: {INTERFACE}")
    logger.info(f"Enviando PCAPs a: {PCAP_ENDPOINT}")
    logger.info(f"Tamaño de buffer: {PCAP_BUFFER_SIZE} paquetes")
    logger.info(f"Intervalo de envío: {PCAP_SEND_INTERVAL}s")
    logger.info(f"Intervalo de stats: {PACKET_STATS_INTERVAL}s")
    
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
    # Iniciar threads periódicos (solo PCAP, no flows)
    threading.Thread(target=periodic_pcap_send, daemon=True).start()
    threading.Thread(target=print_stats, daemon=True).start()
    
    # Iniciar captura (bloqueante)
    try:
        capture_traffic()
    except KeyboardInterrupt:
        logger.info("Deteniendo captura...")
        # Enviar últimos packets
        send_pcap_buffer()
        logger.info("Captura finalizada")
