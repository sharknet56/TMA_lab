#!/usr/bin/env python3
"""
test_client.py - Cliente de prueba para el servidor de clasificación IoT
"""

import requests
import json
import time

# Configuración
SERVER_URL = 'http://localhost:5001'

def test_health():
    """Probar endpoint de health"""
    print("\n" + "="*70)
    print("TEST: Health Check")
    print("="*70)
    
    try:
        response = requests.get(f'{SERVER_URL}/health')
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_flows_simple():
    """Probar con flows simulados simples"""
    print("\n" + "="*70)
    print("TEST: Flows Simulados Simples")
    print("="*70)
    
    # Crear flows de ejemplo
    # NOTA: Estos flows son simulados y pueden no tener todas las features requeridas
    flows = [
        {
            'src_ip': '192.168.50.10',
            'dst_ip': '192.168.50.1',
            'src_port': 45231,
            'dst_port': 80,
            'protocol': 6,  # TCP
            'packets': 150,
            'bytes': 45000,
            'duration': 10.5
        },
        {
            'src_ip': '192.168.50.11',
            'dst_ip': '192.168.50.1',
            'src_port': 52341,
            'dst_port': 443,
            'protocol': 6,  # TCP
            'packets': 500,
            'bytes': 250000,
            'duration': 30.2
        }
    ]
    
    try:
        response = requests.post(
            f'{SERVER_URL}/flows',
            json={'flows': flows},
            timeout=10
        )
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_predict():
    """Probar endpoint de predicción directa"""
    print("\n" + "="*70)
    print("TEST: Predicción Directa")
    print("="*70)
    
    # Datos de ejemplo (deberían coincidir con las features del modelo)
    data = {
        'src_ip': '192.168.50.15',
        'dst_ip': '192.168.50.1',
        'packets': 100,
        'bytes': 50000
    }
    
    try:
        response = requests.post(
            f'{SERVER_URL}/predict',
            json=data,
            timeout=10
        )
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_stats():
    """Obtener estadísticas del servidor"""
    print("\n" + "="*70)
    print("TEST: Estadísticas del Servidor")
    print("="*70)
    
    try:
        response = requests.get(f'{SERVER_URL}/stats')
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"\nEstadísticas:")
            print(f"  PCAPs recibidos: {data['stats']['pcap_received']}")
            print(f"  Flows recibidos: {data['stats']['flows_received']}")
            print(f"  Predicciones: {data['stats']['predictions_made']}")
            print(f"  Actualizaciones firewall: {data['stats']['firewall_updates']}")
            print(f"\nModelo:")
            print(f"  Cargado: {data['model_info']['loaded']}")
            print(f"  Features: {data['model_info']['n_features']}")
            print(f"  Clases: {data['model_info']['classes']}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_dashboard():
    """Verificar que el dashboard está disponible"""
    print("\n" + "="*70)
    print("TEST: Dashboard Web")
    print("="*70)
    
    try:
        response = requests.get(f'{SERVER_URL}/')
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            print(f" Dashboard disponible en: {SERVER_URL}/")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    """Ejecutar todos los tests"""
    print("\n" + "="*70)
    print("CLIENTE DE PRUEBA - Clasificador IoT")
    print("="*70)
    print(f"Servidor: {SERVER_URL}")
    
    tests = [
        ("Health Check", test_health),
        ("Dashboard", test_dashboard),
        ("Estadísticas", test_stats),
        ("Flows Simulados", test_flows_simple),
        ("Predicción Directa", test_predict),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
            time.sleep(1)  # Pausa entre tests
        except KeyboardInterrupt:
            print("\n\nTests interrumpidos por el usuario")
            break
        except Exception as e:
            print(f"\nError en test '{name}': {e}")
            results.append((name, False))
    
    # Resumen
    print("\n" + "="*70)
    print("RESUMEN DE TESTS")
    print("="*70)
    for name, result in results:
        status = " PASS" if result else " FAIL"
        print(f"{status} - {name}")
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    print(f"\nTotal: {passed}/{total} tests pasados")
    
    if passed == total:
        print("\n ¡Todos los tests pasaron!")
    else:
        print("\n⚠️  Algunos tests fallaron")

if __name__ == '__main__':
    main()
