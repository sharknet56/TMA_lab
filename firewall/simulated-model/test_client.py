#!/usr/bin/env python3
"""
test_client.py - Cliente de prueba para el modelo simulado
Permite probar el modelo sin necesidad del sistema completo
"""

import requests
import json
import time

MODEL_URL = 'http://localhost:8000'
FIREWALL_URL = 'http://localhost:5000'

def test_health():
    """Probar health check del modelo"""
    print("\n=== Test: Health Check ===")
    response = requests.get(f'{MODEL_URL}/health')
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=2))

def test_configure():
    """Configurar categorías personalizadas"""
    print("\n=== Test: Configurar Categorías ===")
    
    custom_categories = {
        "categories": {
            "malware": ["192.168.50.50", "192.168.50.51"],
            "ddos": ["192.168.50.99"]
        }
    }
    
    response = requests.post(
        f'{MODEL_URL}/configure',
        json=custom_categories
    )
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=2))

def test_manual_trigger():
    """Disparar actualización manual del firewall"""
    print("\n=== Test: Trigger Manual ===")
    
    # Probar diferentes modos
    modes = ['all', 'random', 'rotate']
    
    for mode in modes:
        print(f"\nModo: {mode}")
        response = requests.post(
            f'{MODEL_URL}/trigger',
            json={'mode': mode}
        )
        print(f"Status: {response.status_code}")
        print(json.dumps(response.json(), indent=2))
        time.sleep(1)

def test_pcap_simulation():
    """Simular envío de PCAP"""
    print("\n=== Test: Simular PCAP ===")
    
    # Crear un archivo dummy
    with open('/tmp/test.pcap', 'wb') as f:
        f.write(b'DUMMY PCAP DATA')
    
    with open('/tmp/test.pcap', 'rb') as f:
        files = {'file': ('test.pcap', f, 'application/vnd.tcpdump.pcap')}
        response = requests.post(f'{MODEL_URL}/pcap', files=files)
    
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=2))

def test_flows_simulation():
    """Simular envío de flows"""
    print("\n=== Test: Simular Flows ===")
    
    flows_data = {
        "flows": [
            {
                "src_ip": "192.168.50.10",
                "dst_ip": "8.8.8.8",
                "src_port": 54321,
                "dst_port": 80,
                "protocol": 6,
                "packets": 100,
                "bytes": 50000,
                "duration": 10.5,
                "packets_per_second": 9.52,
                "bytes_per_second": 4761.9,
                "flags": ["SYN", "ACK"]
            },
            {
                "src_ip": "192.168.50.15",
                "dst_ip": "1.1.1.1",
                "src_port": 12345,
                "dst_port": 443,
                "protocol": 6,
                "packets": 50,
                "bytes": 25000,
                "duration": 5.0,
                "packets_per_second": 10.0,
                "bytes_per_second": 5000.0,
                "flags": ["SYN", "ACK", "FIN"]
            }
        ]
    }
    
    response = requests.post(
        f'{MODEL_URL}/flows',
        json=flows_data
    )
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=2))

def test_stats():
    """Ver estadísticas del modelo"""
    print("\n=== Test: Estadísticas ===")
    response = requests.get(f'{MODEL_URL}/stats')
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=2))

def check_firewall():
    """Verificar estado del firewall (si está disponible)"""
    print("\n=== Test: Verificar Firewall ===")
    try:
        response = requests.get(f'{FIREWALL_URL}/get_categories', timeout=2)
        print(f"Status: {response.status_code}")
        print(json.dumps(response.json(), indent=2))
    except requests.exceptions.RequestException as e:
        print(f"Firewall no disponible (normal si no estás en modo router): {e}")

def run_all_tests():
    """Ejecutar todos los tests"""
    print("=" * 60)
    print("TESTS DEL MODELO SIMULADO")
    print("=" * 60)
    
    try:
        test_health()
        time.sleep(1)
        
        test_configure()
        time.sleep(1)
        
        test_manual_trigger()
        time.sleep(1)
        
        test_pcap_simulation()
        time.sleep(1)
        
        test_flows_simulation()
        time.sleep(1)
        
        test_stats()
        time.sleep(1)
        
        check_firewall()
        
    except requests.exceptions.ConnectionError:
        print("\n❌ Error: No se puede conectar al modelo.")
        print("Asegúrate de que el modelo esté corriendo:")
        print("  python3 model_server.py")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        test_name = sys.argv[1]
        if test_name == 'health':
            test_health()
        elif test_name == 'configure':
            test_configure()
        elif test_name == 'trigger':
            test_manual_trigger()
        elif test_name == 'pcap':
            test_pcap_simulation()
        elif test_name == 'flows':
            test_flows_simulation()
        elif test_name == 'stats':
            test_stats()
        elif test_name == 'firewall':
            check_firewall()
        else:
            print(f"Test desconocido: {test_name}")
            print("Tests disponibles: health, configure, trigger, pcap, flows, stats, firewall")
    else:
        run_all_tests()
