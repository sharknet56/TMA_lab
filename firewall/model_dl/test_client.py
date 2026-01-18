#!/usr/bin/env python3
"""
test_client.py - Cliente de prueba para el servidor de modelo DL
"""

import requests
import sys
import os
import time

# URL del servidor
SERVER_URL = "http://localhost:5002"

def test_health():
    """Probar endpoint de health"""
    print("🔍 Probando /health...")
    try:
        response = requests.get(f"{SERVER_URL}/health")
        print(f"   Status: {response.status_code}")
        data = response.json()
        print(f"   Model loaded: {data.get('model_loaded')}")
        print(f"   Status: {data.get('status')}")
        return response.status_code == 200
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_pcap(pcap_file):
    """Probar endpoint de PCAP"""
    print(f"\n📦 Probando /pcap con {pcap_file}...")
    
    if not os.path.exists(pcap_file):
        print(f"   ❌ Archivo no encontrado: {pcap_file}")
        return False
    
    try:
        with open(pcap_file, 'rb') as f:
            files = {'file': (os.path.basename(pcap_file), f, 'application/vnd.tcpdump.pcap')}
            
            print(f"   Enviando archivo...")
            start_time = time.time()
            
            response = requests.post(f"{SERVER_URL}/pcap", files=files, timeout=30)
            
            elapsed = time.time() - start_time
            
            print(f"   Status: {response.status_code}")
            print(f"   Tiempo: {elapsed:.2f}s")
            
            if response.status_code == 200:
                data = response.json()
                print(f"\n   ✅ Resultado:")
                result = data.get('result', {})
                print(f"      Dispositivo: {result.get('device')}")
                print(f"      Confianza: {result.get('confidence', 0)*100:.2f}%")
                print(f"      Categoría: {result.get('category')}")
                print(f"      Paquetes: {result.get('valid_packets')}/{result.get('total_packets')}")
                print(f"      Firewall actualizado: {data.get('firewall_updated')}")
                return True
            else:
                print(f"   ❌ Error: {response.text}")
                return False
    
    except requests.exceptions.Timeout:
        print(f"   ❌ Timeout (>30s)")
        return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_stats():
    """Probar endpoint de stats"""
    print(f"\n📊 Probando /stats...")
    try:
        response = requests.get(f"{SERVER_URL}/stats")
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get('stats', {})
            print(f"\n   Estadísticas:")
            print(f"      PCAPs recibidos: {stats.get('pcap_received')}")
            print(f"      Predicciones: {stats.get('predictions_made')}")
            print(f"      Updates al firewall: {stats.get('firewall_updates')}")
            print(f"      Errores: {stats.get('errors')}")
            
            if data.get('recent_predictions'):
                print(f"\n   Últimas predicciones:")
                for pred in data['recent_predictions'][:3]:
                    print(f"      - {pred['device']} ({pred['confidence']*100:.1f}%)")
            
            return True
        else:
            print(f"   ❌ Error: {response.text}")
            return False
    
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def main():
    print("=" * 60)
    print("🧪 Test del servidor de modelo DL")
    print("=" * 60)
    
    # Test 1: Health check
    if not test_health():
        print("\n❌ El servidor no está disponible o el modelo no está cargado")
        print("Asegúrate de que el servidor esté corriendo: python model_server.py")
        sys.exit(1)
    
    # Test 2: Stats
    test_stats()
    
    # Test 3: PCAP (si se proporciona)
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
        test_pcap(pcap_file)
    else:
        print("\n💡 Para probar con un archivo PCAP:")
        print("   python test_client.py <archivo.pcap>")
    
    print("\n" + "=" * 60)
    print("✅ Tests completados")
    print("=" * 60)

if __name__ == "__main__":
    main()
