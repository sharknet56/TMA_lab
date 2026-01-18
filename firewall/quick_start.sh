#!/bin/bash
# Script de inicio rápido sin instalación (solo arranca servicios)
# Lee configuración desde .env

# Verificar que se ejecuta como root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Este script debe ejecutarse con sudo"
    echo "Uso: sudo ./quick_start.sh"
    exit 1
fi

# Obtener el directorio del script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$SCRIPT_DIR"

echo "╔════════════════════════════════════════════╗"
echo "║        Inicio rápido del sistema           ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# Leer configuración desde .env
if [ -f "$PROJECT_DIR/.env" ]; then
    source "$PROJECT_DIR/.env"
    echo "✓ Configuración leída desde .env"
    echo "  Modelo: $MODEL_TYPE"
else
    echo "⚠ Advertencia: .env no encontrado, usando valores por defecto"
    MODEL_TYPE="ml_flows"
fi

# Determinar directorio y puerto del modelo según MODEL_TYPE
case "$MODEL_TYPE" in
    "ml_flows"|"ml")
        MODEL_DIR="$PROJECT_DIR/model_ml"
        MODEL_PORT=$MODEL_ML_PORT
        MODEL_LOG="$MODEL_ML_LOG"
        echo "🤖 Modelo: model_ml (puerto $MODEL_PORT)"
        ;;
    "simulated_flows"|"simulated")
        MODEL_DIR="$PROJECT_DIR/simulated-model"
        MODEL_PORT=$MODEL_SIMULATED_PORT
        MODEL_LOG=$MODEL_SIMULATED_LOG
        echo "📦 Modelo: simulated-model (puerto $MODEL_PORT)"
        ;;
    "dl_packets")
        MODEL_DIR="$PROJECT_DIR/model_dl"
        MODEL_PORT=$MODEL_DL_PORT
        MODEL_LOG=$MODEL_DL_LOG
        echo "🧠 Modelo: model_dl (puerto $MODEL_PORT)"
        ;;
    *)
        echo "⚠ MODEL_TYPE desconocido: $MODEL_TYPE, usando ml_flows"
        MODEL_DIR="$PROJECT_DIR/model_ml"
        MODEL_PORT=$MODEL_ML_PORT
        MODEL_LOG="$MODEL_ML_LOG"
        ;;
esac

# Verificar que existe el directorio del modelo
if [ ! -d "$MODEL_DIR" ]; then
    echo "❌ Error: No se encuentra el directorio $MODEL_DIR"
    exit 1
fi

# Verificar que existe el entorno virtual unificado
if [ ! -d "$PROJECT_DIR/venv" ]; then
    echo "❌ Error: Entorno virtual no encontrado en $PROJECT_DIR/venv"
    echo "   Ejecuta: sudo ./init_all.sh"
    exit 1
fi

echo ""
echo "=== 1/3 Deteniendo servicios anteriores ==="
# Usar stop_all.sh pero sin salir si falla
"$PROJECT_DIR/stop_all.sh" 2>/dev/null || true
sleep 1

echo ""
echo "=== 2/3 Iniciando modelo ==="
cd "$MODEL_DIR"

# Verificar archivos del modelo si es ml_flows
if [ "$MODEL_TYPE" = "ml_flows" ] || [ "$MODEL_TYPE" = "ml" ]; then
    if [ ! -f "model.pkl" ] && [ ! -f "iot_device_classifier_rf.pkl" ]; then
        echo "❌ Error: No se encuentra el archivo del modelo (model.pkl)"
        echo "   Genera el modelo ejecutando el notebook IntentoFinal.ipynb"
        exit 1
    fi
fi

# Usar entorno virtual unificado para todos los modelos
"$PROJECT_DIR/venv/bin/python" model_server.py > "$MODEL_LOG" 2>&1 &
MODEL_PID=$!
echo "  ✓ Modelo iniciado (PID: $MODEL_PID)"

sleep 2

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
    sudo "$PROJECT_DIR/venv/bin/python" firewall_manager.py > $FIREWALL_LOG 2>&1 &
    FIREWALL_PID=$!
    echo "  ✓ Firewall Manager iniciado (PID: $FIREWALL_PID)"
    sleep 1
fi

# 2. Iniciar dashboard
if [ -f "dashboard.py" ]; then
    sudo "$PROJECT_DIR/venv/bin/python" dashboard.py > $DASHBOARD_LOG 2>&1 &
    DASHBOARD_PID=$!
    echo "  ✓ Dashboard iniciado (PID: $DASHBOARD_PID)"
    sleep 1
fi

# 3. Configurar red y router PRIMERO (hostapd, dnsmasq, iptables)
echo "  Configurando red..."
if sudo ./router-control.sh start 2>&1 | tee $ROUTER_LOG | grep -q "ERROR\|Error" && ! grep -q "activado correctamente" $ROUTER_LOG; then
    echo ""
    echo "⚠ Posibles problemas al configurar la red."
    echo "   Verifica el log: tail -f $ROUTER_LOG"
else
    echo "  ✓ Red configurada ($AP_NETWORK)"
fi

sleep 3

# 4. Verificar que el modelo está corriendo
if ps -p $MODEL_PID > /dev/null; then
    echo "  ✓ Modelo corriendo correctamente"
    
    # Verificar que responde
    if curl -s http://localhost:$MODEL_PORT/health > /dev/null 2>&1; then
        echo "  ✓ Modelo responde en puerto $MODEL_PORT"
        
        # Verificar red detectada (solo para ml_flows)
        if [ "$MODEL_TYPE" = "ml_flows" ] || [ "$MODEL_TYPE" = "ml" ]; then
            DETECTED_NET=$(curl -s http://localhost:$MODEL_PORT/stats 2>/dev/null | "$PROJECT_DIR/venv/bin/python" -c "import sys, json; d=json.load(sys.stdin); print(d.get('local_network', 'N/A'))" 2>/dev/null)
            if [ "$DETECTED_NET" = "$AP_NETWORK" ]; then
                echo "  ✓ Red $AP_NETWORK detectada correctamente"
            else
                echo "  ⚠ Red detectada: $DETECTED_NET (esperada: $AP_NETWORK)"
            fi
        fi
    fi
else
    echo "  ❌ Error: el modelo no está corriendo"
    echo "  Ver log: tail -f $MODEL_LOG"
fi

cd "$PROJECT_DIR/router-system"

# 5. Iniciar traffic_capture DESPUÉS de que todo esté configurado
# El modo se determina automáticamente según MODEL_TYPE
case "$MODEL_TYPE" in
    "ml_flows"|"ml"|"simulated_flows"|"simulated")
        CAPTURE_SCRIPT="traffic_capture.py"
        echo "  📊 Modo de captura: Flows (estadísticas agregadas)"
        ;;
    "dl_packets")
        CAPTURE_SCRIPT="traffic_capture_packets.py"
        echo "  📦 Modo de captura: Packets (PCAPs completos)"
        ;;
esac

if [ -f "$CAPTURE_SCRIPT" ]; then
    echo "  Iniciando captura de tráfico..."
    sudo "$PROJECT_DIR/venv/bin/python" "$CAPTURE_SCRIPT" > $TRAFFIC_CAPTURE_LOG 2>&1 &
    TRAFFIC_PID=$!
    echo "  ✓ Traffic Capture iniciado (PID: $TRAFFIC_PID, script: $CAPTURE_SCRIPT)"
    sleep 2
else
    echo "  ⚠ Advertencia: $CAPTURE_SCRIPT no encontrado"
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
case "$MODEL_TYPE" in
    "ml_flows"|"ml")
        echo "  • Modelo ML:              http://localhost:$MODEL_ML_PORT"
        echo "  • Dashboard del modelo:   http://localhost:$MODEL_ML_PORT/"
        ;;
    "simulated_flows"|"simulated")
        echo "  • Modelo simulado:        http://localhost:8000"
        ;;
    "dl_packets")
        echo "  • Modelo DL:              http://localhost:$MODEL_DL_PORT"
        ;;
esac
echo "  • Dashboard del router:   http://localhost:$DASHBOARD_PORT"
echo "  • Firewall API:           http://localhost:$FIREWALL_PORT/health"

echo ""
echo "📋 Logs disponibles:"
echo "  tail -f $MODEL_LOG"
echo "  tail -f $FIREWALL_LOG"
echo "  tail -f $DASHBOARD_LOG"
echo "  tail -f $TRAFFIC_CAPTURE_LOG"

echo ""
echo "🔧 Comandos útiles:"
echo "  ./stop_all.sh                # Detener todo"
echo "  ./restart_all.sh             # Reiniciar sistema"
echo "  ./config_manager.sh          # Configurar sistema"

echo ""
