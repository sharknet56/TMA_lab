#!/bin/bash
# Script de inicio rápido sin instalación (solo arranca servicios)
# Uso: sudo ./quick_start.sh [simulated]

# Verificar que se ejecuta como root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Este script debe ejecutarse con sudo"
    echo "Uso: sudo ./quick_start.sh [simulated]"
    exit 1
fi

# Determinar qué modelo usar
MODEL_TYPE=${1:-ml}
if [ "$1" = "simulated" ]; then
    MODEL_TYPE="simulated"
fi

# Obtener el directorio del script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$SCRIPT_DIR"

echo "╔════════════════════════════════════════════╗"
echo "║        Inicio rápido del sistema           ║"
echo "╚════════════════════════════════════════════╝"
echo ""

if [ "$MODEL_TYPE" = "simulated" ]; then
    MODEL_DIR="$PROJECT_DIR/simulated-model"
    MODEL_PORT=8000
    MODEL_LOG="/tmp/model.log"
    echo "📦 Modelo: simulated-model (puerto $MODEL_PORT)"
else
    MODEL_DIR="$PROJECT_DIR/model_ml"
    MODEL_PORT=5001
    MODEL_LOG="/tmp/model_server.log"
    echo "🤖 Modelo: model_ml (puerto $MODEL_PORT)"
fi

# Verificar que existe el directorio del modelo
if [ ! -d "$MODEL_DIR" ]; then
    echo "❌ Error: No se encuentra el directorio $MODEL_DIR"
    exit 1
fi

echo ""
echo "=== 1/3 Deteniendo servicios anteriores ==="
sudo pkill -9 -f "python3 dashboard.py" 2>/dev/null
sudo pkill -9 -f "python3 firewall_manager.py" 2>/dev/null
sudo pkill -9 -f "python model_server.py" 2>/dev/null
pkill -9 -f "python3 model_server.py" 2>/dev/null
pkill -9 -f "python3 traffic_capture.py" 2>/dev/null

# No ejecutar router stop para no limpiar /etc/router-system
# Solo detener los procesos relacionados
sudo pkill -f "hostapd" 2>/dev/null
sudo pkill -f "dnsmasq" 2>/dev/null

echo "✓ Servicios detenidos"
sleep 1

echo ""
echo "=== 2/3 Iniciando modelo ==="
cd "$MODEL_DIR"

if [ "$MODEL_TYPE" = "simulated" ]; then
    python3 model_server.py > "$MODEL_LOG" 2>&1 &
    MODEL_PID=$!
else
    # Verificar entorno virtual
    if [ ! -f "ml/bin/python" ]; then
        echo "❌ Error: Entorno virtual no encontrado en $MODEL_DIR/ml"
        echo "   Ejecuta: cd $MODEL_DIR && python3 -m venv ml && ./ml/bin/pip install -r requirements.txt"
        exit 1
    fi
    
    # Verificar archivos del modelo
    if [ ! -f "model.pkl" ] && [ ! -f "iot_device_classifier_rf.pkl" ]; then
        echo "❌ Error: No se encuentra el archivo del modelo (model.pkl)"
        echo "   Genera el modelo ejecutando el notebook IntentoFinal.ipynb"
        exit 1
    fi
    
    # NOTA: El modelo se iniciará después de configurar el router
    # para que detecte correctamente la red 192.168.50.0/24
    echo "⏳ Modelo se iniciará después de configurar el router..."
fi

sleep 1

echo ""
echo "=== 3/3 Iniciando router-system ==="

# Verificar que existe router-control.sh
if [ ! -f "$PROJECT_DIR/router-system/router-control.sh" ]; then
    echo "❌ Error: No se encuentra router-control.sh"
    echo "   El sistema router no está instalado."
    exit 1
fi

cd "$PROJECT_DIR/router-system"

# Iniciar servicios Python localmente (sin usar /etc/router-system)
echo "Iniciando servicios del router..."

# 1. Iniciar firewall_manager
if [ -f "firewall_manager.py" ]; then
    sudo python3 firewall_manager.py > /tmp/firewall.log 2>&1 &
    FIREWALL_PID=$!
    echo "  ✓ Firewall Manager iniciado (PID: $FIREWALL_PID)"
    sleep 1
fi

# 2. Iniciar dashboard
if [ -f "dashboard.py" ]; then
    sudo python3 dashboard.py > /tmp/dashboard.log 2>&1 &
    DASHBOARD_PID=$!
    echo "  ✓ Dashboard iniciado (PID: $DASHBOARD_PID)"
    sleep 1
fi

# 3. Configurar red y router PRIMERO (hostapd, dnsmasq, iptables)
echo "  Configurando red..."
if sudo ./router-control.sh start 2>&1 | tee /tmp/router_start.log | grep -q "ERROR\|Error" && ! grep -q "activado correctamente" /tmp/router_start.log; then
    echo ""
    echo "⚠ Posibles problemas al configurar la red."
    echo "   Verifica el log: tail -f /tmp/router_start.log"
else
    echo "  ✓ Red configurada (192.168.50.0/24)"
fi

sleep 3

# 4. AHORA sí, iniciar el modelo para que detecte la red correcta
if [ "$MODEL_TYPE" != "simulated" ]; then
    cd "$MODEL_DIR"
    echo "  Iniciando modelo ML..."
    ./ml/bin/python model_server.py > "$MODEL_LOG" 2>&1 &
    MODEL_PID=$!
    echo "  ✓ Modelo ML iniciado (PID: $MODEL_PID)"
    sleep 3
    
    # Verificar que el modelo está corriendo
    if ps -p $MODEL_PID > /dev/null; then
        echo "  ✓ Modelo corriendo correctamente"
        
        # Verificar que responde
        if curl -s http://localhost:$MODEL_PORT/health > /dev/null 2>&1; then
            echo "  ✓ Modelo responde en puerto $MODEL_PORT"
            
            # Verificar red detectada
            DETECTED_NET=$(curl -s http://localhost:$MODEL_PORT/stats 2>/dev/null | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('local_network', 'N/A'))" 2>/dev/null)
            if [ "$DETECTED_NET" = "192.168.50.0/24" ]; then
                echo "  ✓ Red 192.168.50.0/24 detectada correctamente"
            else
                echo "  ⚠ Red detectada: $DETECTED_NET (esperada: 192.168.50.0/24)"
            fi
        fi
    else
        echo "  ❌ Error: el modelo no está corriendo"
        echo "  Ver log: tail -f $MODEL_LOG"
    fi
    
    cd "$PROJECT_DIR/router-system"
fi

# 5. Iniciar traffic_capture DESPUÉS de que todo esté configurado
if [ -f "traffic_capture.py" ]; then
    echo "  Iniciando captura de tráfico..."
    sudo python3 traffic_capture.py > /tmp/traffic_capture.log 2>&1 &
    TRAFFIC_PID=$!
    echo "  ✓ Traffic Capture iniciado (PID: $TRAFFIC_PID)"
    sleep 2
fi

sleep 1

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║         Sistema iniciado                   ║"
echo "╚════════════════════════════════════════════╝"
echo ""
echo "📊 Estado de los servicios:"
SERVICES_RUNNING=$(ps aux | grep -E "python.*(model_server|firewall_manager|dashboard|traffic_capture)" | grep -v grep)
if [ -n "$SERVICES_RUNNING" ]; then
    echo "$SERVICES_RUNNING" | awk '{
        if ($0 ~ /model_server/) name = "Modelo ML";
        else if ($0 ~ /firewall_manager/) name = "Firewall Manager";
        else if ($0 ~ /dashboard/) name = "Dashboard";
        else if ($0 ~ /traffic_capture/) name = "Traffic Capture";
        else name = "Servicio";
        printf "  ✓ PID %-6s - %s\n", $2, name;
    }'
else
    echo "  ⚠ No se detectaron servicios Python corriendo"
    echo "    Verifica los logs para más información"
fi

# Verificar hostapd y dnsmasq
if pgrep hostapd > /dev/null; then
    echo "  ✓ PID $(pgrep hostapd | head -1)      - Hostapd (WiFi AP)"
fi
if pgrep dnsmasq > /dev/null; then
    echo "  ✓ PID $(pgrep dnsmasq | head -1)      - Dnsmasq (DHCP)"
fi

echo ""
echo "🌐 URLs de acceso:"
if [ "$MODEL_TYPE" = "simulated" ]; then
    echo "  • Modelo simulado:        http://localhost:8000"
else
    echo "  • Modelo ML:              http://localhost:5001"
    echo "  • Dashboard del modelo:   http://localhost:5001/"
fi
echo "  • Dashboard del router:   http://192.168.50.1:8081"
echo "  • Firewall API:           http://192.168.50.1:5000/health"

echo ""
echo "📋 Logs disponibles:"
echo "  tail -f $MODEL_LOG"
echo "  tail -f /tmp/firewall.log"
echo "  tail -f /tmp/dashboard.log"

echo ""
echo "🔧 Comandos útiles:"
echo "  ./stop_all.sh                # Detener todo"
echo "  sudo ./quick_start.sh        # Reiniciar con model_ml"
echo "  sudo ./quick_start.sh simulated  # Reiniciar con simulated-model"

echo ""
