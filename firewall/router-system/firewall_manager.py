#!/usr/bin/env python3
"""
firewall_manager.py - Gestor dinámico de firewall por categorías
Ubicación: /etc/router-system/firewall_manager.py
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import json
import logging
from datetime import datetime
import threading
import time
import os
app = Flask(__name__)
CORS(app)  # Habilitar CORS para todas las rutas

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Estado global de categorías
active_categories = {}
disabled_categories = set()  # Categorías que están desactivadas
category_lock = threading.Lock()
stats = {
    'total_updates': 0,
    'total_blocked_ips': 0,
    'last_update': None
}

def run_command(cmd, ignore_errors=False):
    """Ejecutar comando de sistema"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=not ignore_errors
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        if not ignore_errors:
            logger.error(f"Error ejecutando {' '.join(cmd)}: {e}")
        return False, e.stdout, e.stderr

def initialize_firewall():
    """Inicializar chains de iptables"""
    logger.info("Inicializando chains de firewall...")
    
    # Crear chain si no existe
    run_command(['iptables', '-N', 'CATEGORY_FILTER'], ignore_errors=True)
    
    # Limpiar chain
    run_command(['iptables', '-F', 'CATEGORY_FILTER'])
    
    # Verificar que está en FORWARD
    success, stdout, _ = run_command(['iptables', '-L', 'FORWARD', '-n'])
    if success and 'CATEGORY_FILTER' not in stdout:
        run_command(['iptables', '-I', 'FORWARD', '1', '-j', 'CATEGORY_FILTER'])
        logger.info("Chain CATEGORY_FILTER insertada en FORWARD")

def apply_firewall_rules(categories):
    """Aplicar reglas de firewall basadas en categorías"""
    with category_lock:
        logger.info(f"Aplicando reglas para {len(categories)} categorías")
        
        # Limpiar chain actual
        run_command(['iptables', '-F', 'CATEGORY_FILTER'])
        
        blocked_count = 0
        
        # Aplicar reglas por categoría
        for category, ips in categories.items():
            logger.info(f"Procesando categoría '{category}' con {len(ips)} IPs")
            
            for ip in ips:
                # Validar formato IP
                if not is_valid_ip(ip):
                    logger.warning(f"IP inválida: {ip}")
                    continue
                
                # Bloquear tráfico desde esta IP (origen)
                run_command([
                    'iptables', '-A', 'CATEGORY_FILTER',
                    '-s', ip,
                    '-j', 'DROP',
                    '-m', 'comment', '--comment', f'cat:{category}'
                ])
                
                # Bloquear tráfico hacia esta IP (destino)
                run_command([
                    'iptables', '-A', 'CATEGORY_FILTER',
                    '-d', ip,
                    '-j', 'DROP',
                    '-m', 'comment', '--comment', f'cat:{category}'
                ])
                
                blocked_count += 1
        
        # Actualizar estadísticas
        stats['total_updates'] += 1
        stats['total_blocked_ips'] = blocked_count
        stats['last_update'] = datetime.now().isoformat()
        
        logger.info(f"Reglas aplicadas: {blocked_count} IPs bloqueadas")
        return blocked_count

def is_valid_ip(ip):
    """Validar formato de dirección IP"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def get_current_rules():
    """Obtener reglas actuales de iptables"""
    success, stdout, _ = run_command(['iptables', '-L', 'CATEGORY_FILTER', '-n', '-v'])
    if not success:
        return []
    
    rules = []
    for line in stdout.split('\n')[2:]:  # Skip header
        if line.strip() and 'cat:' in line:
            parts = line.split()
            if len(parts) >= 8:
                rules.append({
                    'pkts': parts[0],
                    'bytes': parts[1],
                    'target': parts[2],
                    'source': parts[7] if parts[7] != '0.0.0.0/0' else 'any',
                    'destination': parts[8] if len(parts) > 8 else 'any'
                })
    
    return rules

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/update_categories', methods=['POST'])
def update_categories():
    """
    Endpoint para actualizar categorías de bloqueo
    
    Formato JSON esperado:
    {
        "categories": {
            "malware": ["192.168.50.15", "192.168.50.23"],
            "suspicious": ["192.168.50.8"],
            "blocked": ["192.168.50.45"]
        }
    }
    """
    global active_categories
    
    try:
        data = request.json
        
        if not data or 'categories' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Formato inválido. Se espera: {"categories": {...}}'
            }), 400
        
        new_categories = data['categories']
        
        # Validar estructura
        if not isinstance(new_categories, dict):
            return jsonify({
                'status': 'error',
                'message': 'categories debe ser un diccionario'
            }), 400
        
        # Validar IPs
        for category, ips in new_categories.items():
            if not isinstance(ips, list):
                return jsonify({
                    'status': 'error',
                    'message': f'IPs para categoría "{category}" deben ser una lista'
                }), 400
        
        # Marcar como desactivadas las categorías nuevas que vienen del modelo
        for category in new_categories.keys():
            if category not in active_categories:
                # Es una categoría completamente nueva, desactivarla por defecto
                disabled_categories.add(category)
                logger.info(f"Nueva categoría '{category}' detectada - desactivada por defecto (debe activarse manualmente)")
        
        # Actualizar categorías
        active_categories = new_categories
        
        # Aplicar reglas solo para categorías no desactivadas
        enabled_cats = {cat: ips for cat, ips in active_categories.items() if cat not in disabled_categories}
        blocked_count = apply_firewall_rules(enabled_cats)
        
        logger.info(f"Categorías actualizadas: {len(new_categories)} categorías, {blocked_count} IPs bloqueadas")
        
        return jsonify({
            'status': 'success',
            'categories_applied': len(new_categories),
            'total_ips_blocked': blocked_count,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Error actualizando categorías: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/add_to_category', methods=['POST'])
def add_to_category():
    """
    Añadir IPs a una categoría existente sin borrar las demás
    
    Formato JSON:
    {
        "category": "malware",
        "ips": ["192.168.50.99", "192.168.50.100"]
    }
    """
    global active_categories
    
    try:
        data = request.json
        category = data.get('category')
        ips = data.get('ips', [])
        
        if not category or not ips:
            return jsonify({
                'status': 'error',
                'message': 'Se requieren "category" e "ips"'
            }), 400
        
        # Añadir a categoría existente o crear nueva
        if category not in active_categories:
            active_categories[category] = []
        
        # Evitar duplicados
        for ip in ips:
            if ip not in active_categories[category]:
                active_categories[category].append(ip)
        
        blocked_count = apply_firewall_rules(active_categories)
        
        return jsonify({
            'status': 'success',
            'category': category,
            'ips_in_category': len(active_categories[category]),
            'total_ips_blocked': blocked_count
        })
    
    except Exception as e:
        logger.error(f"Error añadiendo a categoría: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/remove_from_category', methods=['POST'])
def remove_from_category():
    """
    Eliminar IPs de una categoría
    
    Formato JSON:
    {
        "category": "malware",
        "ips": ["192.168.50.99"]
    }
    """
    global active_categories
    
    try:
        data = request.json
        category = data.get('category')
        ips = data.get('ips', [])
        
        if not category or not ips:
            return jsonify({
                'status': 'error',
                'message': 'Se requieren "category" e "ips"'
            }), 400
        
        if category not in active_categories:
            return jsonify({
                'status': 'error',
                'message': f'Categoría "{category}" no existe'
            }), 404
        
        # Eliminar IPs
        for ip in ips:
            if ip in active_categories[category]:
                active_categories[category].remove(ip)
        
        # Eliminar categoría si está vacía
        if not active_categories[category]:
            del active_categories[category]
        
        blocked_count = apply_firewall_rules(active_categories)
        
        return jsonify({
            'status': 'success',
            'category': category,
            'total_ips_blocked': blocked_count
        })
    
    except Exception as e:
        logger.error(f"Error eliminando de categoría: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/get_categories', methods=['GET'])
def get_categories():
    """Obtener todas las categorías activas"""
    enabled_categories = [cat for cat in active_categories.keys() if cat not in disabled_categories]
    return jsonify({
        'categories': active_categories,
        'active_categories': enabled_categories,
        'stats': stats
    })

@app.route('/get_rules', methods=['GET'])
def get_rules():
    """Obtener reglas actuales de iptables"""
    rules = get_current_rules()
    return jsonify({
        'rules': rules,
        'total': len(rules)
    })

@app.route('/clear_category', methods=['POST'])
def clear_category():
    """
    Limpiar una categoría específica
    
    Formato JSON:
    {
        "category": "malware"
    }
    """
    global active_categories
    
    try:
        data = request.json
        category = data.get('category')
        
        if not category:
            return jsonify({
                'status': 'error',
                'message': 'Se requiere "category"'
            }), 400
        
        if category in active_categories:
            del active_categories[category]
            blocked_count = apply_firewall_rules(active_categories)
            
            return jsonify({
                'status': 'success',
                'message': f'Categoría "{category}" eliminada',
                'total_ips_blocked': blocked_count
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Categoría "{category}" no existe'
            }), 404
    
    except Exception as e:
        logger.error(f"Error limpiando categoría: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/clear_all', methods=['POST'])
def clear_all():
    """Limpiar todas las categorías"""
    global active_categories
    
    try:
        active_categories = {}
        apply_firewall_rules(active_categories)
        
        return jsonify({
            'status': 'success',
            'message': 'Todas las categorías eliminadas'
        })
    
    except Exception as e:
        logger.error(f"Error limpiando todas las categorías: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """Obtener estadísticas del firewall"""
    return jsonify(stats)

@app.route('/toggle_category', methods=['POST'])
def toggle_category():
    """
    Activar/desactivar una categoría completa
    
    Formato JSON:
    {
        "category": "malware",
        "enabled": true/false
    }
    """
    global active_categories, disabled_categories
    
    try:
        data = request.json
        category = data.get('category')
        enabled = data.get('enabled', True)
        
        logger.info(f"Toggle request: category='{category}', enabled={enabled}, current disabled={disabled_categories}")
        
        if not category:
            return jsonify({
                'status': 'error',
                'message': 'Se requiere "category"'
            }), 400
        
        if not enabled:
            # Desactivar: añadir a la lista de desactivadas
            disabled_categories.add(category)
            logger.info(f"Categoría '{category}' desactivada. Disabled: {disabled_categories}")
        else:
            # Activar: quitar de la lista de desactivadas
            disabled_categories.discard(category)
            logger.info(f"Categoría '{category}' activada. Disabled: {disabled_categories}")
        
        # Replicar reglas solo con categorías activas
        enabled_cats = {cat: ips for cat, ips in active_categories.items() if cat not in disabled_categories}
        blocked_count = apply_firewall_rules(enabled_cats)
        
        return jsonify({
            'status': 'success',
            'category': category,
            'enabled': enabled,
            'total_ips_blocked': blocked_count
        })
    
    except Exception as e:
        logger.error(f"Error toggle categoría: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    logger.info("Iniciando Firewall Manager...")
    
    # Inicializar firewall
    initialize_firewall()
    
    logger.info("Firewall Manager listo")
    FIREWALL_PORT = os.getenv('FIREWALL_PORT', '5000')
    logger.info(f"API escuchando en http://0.0.0.0:{FIREWALL_PORT}")
    # Iniciar servidor Flask
    app.run(host='0.0.0.0', port=FIREWALL_PORT, debug=False)