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
import numpy as np

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

# Estructura para flows con todas las features de CICFlowMeter
def create_flow_structure():
    return {
        'start_time': None,
        'end_time': None,
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None,
        'protocol': None,
        'direction_established': False,
        'first_packet_direction': None,
        
        # Listas para cálculos estadísticos
        'fwd_packet_lengths': [],
        'bwd_packet_lengths': [],
        'all_packet_lengths': [],
        'fwd_iat': [],  # Inter-arrival times
        'bwd_iat': [],
        'flow_iat': [],
        'fwd_timestamps': [],
        'bwd_timestamps': [],
        'all_timestamps': [],
        
        # Contadores
        'fwd_packets': 0,
        'bwd_packets': 0,
        'fwd_bytes': 0,
        'bwd_bytes': 0,
        'fwd_header_bytes': 0,
        'bwd_header_bytes': 0,
        
        # TCP Flags
        'fin_flag_count': 0,
        'syn_flag_count': 0,
        'rst_flag_count': 0,
        'psh_flag_count': 0,
        'ack_flag_count': 0,
        'urg_flag_count': 0,
        'cwe_flag_count': 0,
        'ece_flag_count': 0,
        'fwd_psh_flags': 0,
        'bwd_psh_flags': 0,
        'fwd_urg_flags': 0,
        'bwd_urg_flags': 0,
        
        # Window sizes
        'init_fwd_win_bytes': 0,
        'init_bwd_win_bytes': 0,
        
        # Active/Idle times
        'active_times': [],
        'idle_times': [],
        'last_packet_time': None,
        'active_start': None,
        'idle_threshold': 1.0,  # 1 segundo
        
        # Subflow (consideramos 1 subflow por simplicidad)
        'subflow_fwd_packets': 0,
        'subflow_fwd_bytes': 0,
        'subflow_bwd_packets': 0,
        'subflow_bwd_bytes': 0,
    }

flows = defaultdict(create_flow_structure)
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
    """Crear clave única para un flow (5-tupla) sin normalizar"""
    if IP not in packet:
        return None, None
    
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
    
    # Clave sin normalizar para mantener dirección
    flow_key_forward = (src_ip, dst_ip, src_port, dst_port, proto)
    flow_key_backward = (dst_ip, src_ip, dst_port, src_port, proto)
    
    # Clave normalizada para identificar el flow
    if src_ip < dst_ip:
        normalized_key = flow_key_forward
        is_forward = True
    elif src_ip > dst_ip:
        normalized_key = flow_key_backward
        is_forward = False
    else:
        if src_port <= dst_port:
            normalized_key = flow_key_forward
            is_forward = True
        else:
            normalized_key = flow_key_backward
            is_forward = False
    
    return normalized_key, is_forward

def update_flow(packet):
    """Actualizar información de flow con todas las features"""
    flow_key, is_forward = create_flow_key(packet)
    if flow_key is None:
        return
    
    with flows_lock:
        flow = flows[flow_key]
        current_time = time.time()
        packet_length = len(packet)
        
        # Inicializar si es nuevo
        if flow['start_time'] is None:
            flow['start_time'] = current_time
            flow['src_ip'] = flow_key[0]
            flow['dst_ip'] = flow_key[1]
            flow['src_port'] = flow_key[2]
            flow['dst_port'] = flow_key[3]
            flow['protocol'] = flow_key[4]
            flow['first_packet_direction'] = 'forward' if is_forward else 'backward'
            flow['active_start'] = current_time
        
        # Determinar dirección basada en el primer paquete
        if not flow['direction_established']:
            flow['direction_established'] = True
            packet_is_forward = (flow['first_packet_direction'] == 'forward' and is_forward) or \
                               (flow['first_packet_direction'] == 'backward' and not is_forward)
        else:
            # Comparar con la dirección original
            if flow['first_packet_direction'] == 'forward':
                packet_is_forward = is_forward
            else:
                packet_is_forward = not is_forward
        
        flow['end_time'] = current_time
        flow['all_packet_lengths'].append(packet_length)
        flow['all_timestamps'].append(current_time)
        
        # Calcular header length
        header_len = 0
        if IP in packet:
            header_len += packet[IP].ihl * 4
        if TCP in packet:
            header_len += packet[TCP].dataofs * 4
        elif UDP in packet:
            header_len += 8
        
        # Actualizar según dirección
        if packet_is_forward:
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += packet_length
            flow['fwd_packet_lengths'].append(packet_length)
            flow['fwd_timestamps'].append(current_time)
            flow['fwd_header_bytes'] += header_len
            flow['subflow_fwd_packets'] += 1
            flow['subflow_fwd_bytes'] += packet_length
            
            # IAT forward
            if len(flow['fwd_timestamps']) > 1:
                iat = flow['fwd_timestamps'][-1] - flow['fwd_timestamps'][-2]
                flow['fwd_iat'].append(iat)
        else:
            flow['bwd_packets'] += 1
            flow['bwd_bytes'] += packet_length
            flow['bwd_packet_lengths'].append(packet_length)
            flow['bwd_timestamps'].append(current_time)
            flow['bwd_header_bytes'] += header_len
            flow['subflow_bwd_packets'] += 1
            flow['subflow_bwd_bytes'] += packet_length
            
            # IAT backward
            if len(flow['bwd_timestamps']) > 1:
                iat = flow['bwd_timestamps'][-1] - flow['bwd_timestamps'][-2]
                flow['bwd_iat'].append(iat)
        
        # IAT del flow completo
        if len(flow['all_timestamps']) > 1:
            iat = flow['all_timestamps'][-1] - flow['all_timestamps'][-2]
            flow['flow_iat'].append(iat)
        
        # Active/Idle times
        if flow['last_packet_time'] is not None:
            time_diff = current_time - flow['last_packet_time']
            if time_diff > flow['idle_threshold']:
                # Periodo idle
                if flow['active_start'] is not None:
                    active_duration = flow['last_packet_time'] - flow['active_start']
                    if active_duration > 0:
                        flow['active_times'].append(active_duration)
                flow['idle_times'].append(time_diff)
                flow['active_start'] = current_time
        
        flow['last_packet_time'] = current_time
        
        # TCP Flags
        if TCP in packet:
            tcp_flags = packet[TCP].flags
            
            if tcp_flags & 0x02:  # SYN
                flow['syn_flag_count'] += 1
            if tcp_flags & 0x01:  # FIN
                flow['fin_flag_count'] += 1
            if tcp_flags & 0x04:  # RST
                flow['rst_flag_count'] += 1
            if tcp_flags & 0x08:  # PSH
                flow['psh_flag_count'] += 1
                if packet_is_forward:
                    flow['fwd_psh_flags'] += 1
                else:
                    flow['bwd_psh_flags'] += 1
            if tcp_flags & 0x10:  # ACK
                flow['ack_flag_count'] += 1
            if tcp_flags & 0x20:  # URG
                flow['urg_flag_count'] += 1
                if packet_is_forward:
                    flow['fwd_urg_flags'] += 1
                else:
                    flow['bwd_urg_flags'] += 1
            if tcp_flags & 0x80:  # CWE/CWR
                flow['cwe_flag_count'] += 1
            if tcp_flags & 0x40:  # ECE
                flow['ece_flag_count'] += 1
            
            # Window sizes iniciales
            if flow['fwd_packets'] == 1 and packet_is_forward:
                flow['init_fwd_win_bytes'] = packet[TCP].window
            if flow['bwd_packets'] == 1 and not packet_is_forward:
                flow['init_bwd_win_bytes'] = packet[TCP].window

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

def calculate_statistics(values):
    """Calcular estadísticas (mean, std, max, min, var)"""
    if not values:
        return {
            'mean': 0,
            'std': 0,
            'max': 0,
            'min': 0,
            'var': 0
        }
    
    arr = np.array(values)
    return {
        'mean': float(np.mean(arr)),
        'std': float(np.std(arr)),
        'max': float(np.max(arr)),
        'min': float(np.min(arr)),
        'var': float(np.var(arr))
    }

def export_flows():
    """Exportar flows a formato CICFlowMeter"""
    with flows_lock:
        exported_flows = []
        current_time = time.time()
        
        for flow_key, flow in list(flows.items()):
            if flow['start_time'] is None:
                continue
            
            duration = flow['end_time'] - flow['start_time']
            if duration == 0:
                duration = 0.000001  # Evitar división por cero
            
            # Calcular estadísticas de longitudes de paquetes
            fwd_pkt_stats = calculate_statistics(flow['fwd_packet_lengths'])
            bwd_pkt_stats = calculate_statistics(flow['bwd_packet_lengths'])
            all_pkt_stats = calculate_statistics(flow['all_packet_lengths'])
            
            # Calcular estadísticas de IAT
            flow_iat_stats = calculate_statistics(flow['flow_iat'])
            fwd_iat_stats = calculate_statistics(flow['fwd_iat'])
            bwd_iat_stats = calculate_statistics(flow['bwd_iat'])
            
            # Calcular estadísticas de Active/Idle
            active_stats = calculate_statistics(flow['active_times'])
            idle_stats = calculate_statistics(flow['idle_times'])
            
            # Calcular totales y promedios
            total_packets = flow['fwd_packets'] + flow['bwd_packets']
            total_bytes = flow['fwd_bytes'] + flow['bwd_bytes']
            
            # Down/Up Ratio
            down_up_ratio = flow['bwd_packets'] / flow['fwd_packets'] if flow['fwd_packets'] > 0 else 0
            
            # Averages
            pkt_size_avg = total_bytes / total_packets if total_packets > 0 else 0
            fwd_seg_size_avg = flow['fwd_bytes'] / flow['fwd_packets'] if flow['fwd_packets'] > 0 else 0
            bwd_seg_size_avg = flow['bwd_bytes'] / flow['bwd_packets'] if flow['bwd_packets'] > 0 else 0
            
            # Contadores de paquetes con datos (sin considerar solo headers)
            fwd_act_data_pkts = sum(1 for length in flow['fwd_packet_lengths'] 
                                   if length > (flow['fwd_header_bytes'] / max(flow['fwd_packets'], 1)))
            
            # Exportar flow con todas las features
            flow_export = {
                'SrcPort': flow['src_port'],
                'DstPort': flow['dst_port'],
                'Protocol': flow['protocol'],
                'FlowDuration': duration * 1000000,  # En microsegundos
                'TotFwdPkts': flow['fwd_packets'],
                'TotBwdPkts': flow['bwd_packets'],
                'TotLenFwdPkts': flow['fwd_bytes'],
                'TotLenBwdPkts': flow['bwd_bytes'],
                
                # Forward packet length stats
                'FwdPktLenMax': fwd_pkt_stats['max'],
                'FwdPktLenMin': fwd_pkt_stats['min'],
                'FwdPktLenMean': fwd_pkt_stats['mean'],
                'FwdPktLenStd': fwd_pkt_stats['std'],
                
                # Backward packet length stats
                'BwdPktLenMax': bwd_pkt_stats['max'],
                'BwdPktLenMin': bwd_pkt_stats['min'],
                'BwdPktLenMean': bwd_pkt_stats['mean'],
                'BwdPktLenStd': bwd_pkt_stats['std'],
                
                # Flow rates
                'FlowByts/s': total_bytes / duration,
                'FlowPkts/s': total_packets / duration,
                
                # Flow IAT stats
                'FlowIATMean': flow_iat_stats['mean'] * 1000000,  # microsegundos
                'FlowIATStd': flow_iat_stats['std'] * 1000000,
                'FlowIATMax': flow_iat_stats['max'] * 1000000,
                'FlowIATMin': flow_iat_stats['min'] * 1000000,
                
                # Forward IAT stats
                'FwdIATTot': sum(flow['fwd_iat']) * 1000000,
                'FwdIATMean': fwd_iat_stats['mean'] * 1000000,
                'FwdIATStd': fwd_iat_stats['std'] * 1000000,
                'FwdIATMax': fwd_iat_stats['max'] * 1000000,
                'FwdIATMin': fwd_iat_stats['min'] * 1000000,
                
                # Backward IAT stats
                'BwdIATTot': sum(flow['bwd_iat']) * 1000000,
                'BwdIATMean': bwd_iat_stats['mean'] * 1000000,
                'BwdIATStd': bwd_iat_stats['std'] * 1000000,
                'BwdIATMax': bwd_iat_stats['max'] * 1000000,
                'BwdIATMin': bwd_iat_stats['min'] * 1000000,
                
                # TCP Flags
                'FwdPSHFlags': flow['fwd_psh_flags'],
                'BwdPSHFlags': flow['bwd_psh_flags'],
                'FwdURGFlags': flow['fwd_urg_flags'],
                'BwdURGFlags': flow['bwd_urg_flags'],
                
                # Header lengths
                'FwdHeaderLen': flow['fwd_header_bytes'],
                'BwdHeaderLen': flow['bwd_header_bytes'],
                
                # Packets per second
                'FwdPkts/s': flow['fwd_packets'] / duration,
                'BwdPkts/s': flow['bwd_packets'] / duration,
                
                # Overall packet length stats
                'PktLenMin': all_pkt_stats['min'],
                'PktLenMax': all_pkt_stats['max'],
                'PktLenMean': all_pkt_stats['mean'],
                'PktLenStd': all_pkt_stats['std'],
                'PktLenVar': all_pkt_stats['var'],
                
                # Flag counts
                'FINFlagCnt': flow['fin_flag_count'],
                'SYNFlagCnt': flow['syn_flag_count'],
                'RSTFlagCnt': flow['rst_flag_count'],
                'PSHFlagCnt': flow['psh_flag_count'],
                'ACKFlagCnt': flow['ack_flag_count'],
                'URGFlagCnt': flow['urg_flag_count'],
                'CWEFlagCount': flow['cwe_flag_count'],
                'ECEFlagCnt': flow['ece_flag_count'],
                
                # Ratios and averages
                'Down/UpRatio': down_up_ratio,
                'PktSizeAvg': pkt_size_avg,
                'FwdSegSizeAvg': fwd_seg_size_avg,
                'BwdSegSizeAvg': bwd_seg_size_avg,
                
                # Bulk rates (simplificado - se requeriría análisis más complejo)
                'FwdByts/bAvg': fwd_seg_size_avg,  # Aproximación
                'FwdPkts/bAvg': 1.0 if flow['fwd_packets'] > 0 else 0,
                'FwdBlkRateAvg': flow['fwd_bytes'] / duration if duration > 0 else 0,
                'BwdByts/bAvg': bwd_seg_size_avg,
                'BwdPkts/bAvg': 1.0 if flow['bwd_packets'] > 0 else 0,
                'BwdBlkRateAvg': flow['bwd_bytes'] / duration if duration > 0 else 0,
                
                # Subflow stats
                'SubflowFwdPkts': flow['subflow_fwd_packets'],
                'SubflowFwdByts': flow['subflow_fwd_bytes'],
                'SubflowBwdPkts': flow['subflow_bwd_packets'],
                'SubflowBwdByts': flow['subflow_bwd_bytes'],
                
                # Initial window bytes
                'InitFwdWinByts': flow['init_fwd_win_bytes'],
                'InitBwdWinByts': flow['init_bwd_win_bytes'],
                
                # Forward active data packets
                'FwdActDataPkts': fwd_act_data_pkts,
                'FwdSegSizeMin': fwd_pkt_stats['min'],
                
                # Active/Idle stats
                'ActiveMean': active_stats['mean'] * 1000000,
                'ActiveStd': active_stats['std'] * 1000000,
                'ActiveMax': active_stats['max'] * 1000000,
                'ActiveMin': active_stats['min'] * 1000000,
                'IdleMean': idle_stats['mean'] * 1000000,
                'IdleStd': idle_stats['std'] * 1000000,
                'IdleMax': idle_stats['max'] * 1000000,
                'IdleMin': idle_stats['min'] * 1000000,
            }
            
            exported_flows.append(flow_export)
        
        # Limpiar flows antiguos (más de 5 minutos sin actividad)
        for flow_key in list(flows.keys()):
            if flows[flow_key]['end_time']:
                age = current_time - flows[flow_key]['end_time']
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