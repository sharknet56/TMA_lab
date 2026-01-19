#!/usr/bin/env python3
"""
test_client.py - Cliente de prueba para el servidor de modelo DL
Envía archivos PCAP al servidor para clasificación
"""

import requests
import sys
import os
import json

def test_health(base_url):
    """Probar endpoint de health"""
    print("\n=== Test Health ===")
    try:
        response = requests.get(f"{base_url}/health")
        print(f"Status: {response.status_code}")
        data = response.json()
        print(json.dumps(data, indent=2))
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_pcap(base_url, pcap_file):
    """Probar envío de PCAP"""
    print(f"\n=== Test PCAP: {pcap_file} ===")
    
    if not os.path.exists(pcap_file):
        print(f"Error: Archivo no encontrado: {pcap_file}")
        return False
    
    try:
        with open(pcap_file, 'rb') as f:
            files = {'file': (os.path.basename(pcap_file), f, 'application/octet-stream')}
            response = requests.post(f"{base_url}/pcap", files=files)
        
        print(f"Status: {response.status_code}")
        data = response.json()
        print(json.dumps(data, indent=2))
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_stats(base_url):
    """Obtener estadísticas"""
    print("\n=== Stats ===")
    try:
        response = requests.get(f"{base_url}/stats")
        print(f"Status: {response.status_code}")
        data = response.json()
        print(json.dumps(data, indent=2))
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_devices(base_url):
    """Obtener dispositivos detectados"""
    print("\n=== Devices ===")
    try:
        response = requests.get(f"{base_url}/devices")
        print(f"Status: {response.status_code}")
        data = response.json()
        print(json.dumps(data, indent=2))
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    base_url = "http://localhost:5002"
    
    print("=" * 60)
    print(" Test Cliente para Modelo DL")
    print("=" * 60)
    
    # Test 1: Health check
    if not test_health(base_url):
        print("\n Health check falló. ¿Está el servidor corriendo?")
        sys.exit(1)
    
    print("\n Servidor respondiendo correctamente")
    
    # Test 2: Enviar PCAP si se proporciona
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
        if test_pcap(base_url, pcap_file):
            print("\n PCAP procesado correctamente")
            
            # Esperar un poco y obtener stats
            import time
            time.sleep(1)
            test_stats(base_url)
            test_devices(base_url)
        else:
            print("\n Error procesando PCAP")
    else:
        print("\n Uso: python test_client.py <archivo.pcap>")
        print("   Para probar con un archivo PCAP específico")
        
        # Mostrar stats actuales
        test_stats(base_url)
        test_devices(base_url)
    
    print("\n" + "=" * 60)
    print("Dashboard disponible en: http://localhost:5002/")
    print("=" * 60)

if __name__ == '__main__':
    main()
