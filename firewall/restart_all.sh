#!/bin/bash
# Script para reiniciar todo el sistema limpiamente
# Lee la configuración desde .env

# Obtener el directorio del script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$SCRIPT_DIR"

# Leer configuración desde .env
if [ -f "$PROJECT_DIR/.env" ]; then
    source "$PROJECT_DIR/.env"
    echo "=== Configuración leída desde .env ==="
    echo "Modelo: $MODEL_TYPE"
else
    echo "⚠ Advertencia: .env no encontrado, usando valores por defecto"
    MODEL_TYPE="ml_flows"
fi

# Determinar directorio y puerto del modelo según MODEL_TYPE
case "$MODEL_TYPE" in
    "ml_flows"|"ml")
        MODEL_DIR="$PROJECT_DIR/model_ml"
        MODEL_PORT=$MODEL_ML_PORT
        MODEL_LOG=$MODEL_ML_LOG
        ;;
    "simulated_flows"|"simulated")
        MODEL_DIR="$PROJECT_DIR/simulated-model"
        MODEL_PORT=$MODEL_SIMULATED_PORT
        MODEL_LOG=$MODEL_SIMULATED_LOG
        ;;
    "dl_packets")
        MODEL_DIR="$PROJECT_DIR/model_dl"
        MODEL_PORT=$MODEL_DL_PORT
        MODEL_LOG=$MODEL_DL_LOG
        ;;
    *)
        echo "❌ MODEL_TYPE desconocido: $MODEL_TYPE"
        exit 1
        ;;
esac

echo "Directorio: $MODEL_DIR"
echo "Puerto: $MODEL_PORT"

echo ""
echo "=== Deteniendo todos los servicios ==="
echo "🛑 Llamando a stop_all.sh..."

# Ejecutar stop_all.sh para evitar duplicar código
"$PROJECT_DIR/stop_all.sh"

sleep 2

echo ""
echo "=== Limpiando caché ==="
find "$PROJECT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find "$PROJECT_DIR" -type f -name "*.pyc" -delete 2>/dev/null
echo "✓ Caché eliminados"

echo ""
echo "=== Reiniciando servicios ==="
echo "⏳ Iniciando Firewall Manager..."
cd "$PROJECT_DIR/router-system"
sudo "$PROJECT_DIR/venv/bin/python" firewall_manager.py > $FIREWALL_LOG 2>&1 &
FIREWALL_PID=$!
sleep 2

echo "⏳ Iniciando Dashboard..."
sudo "$PROJECT_DIR/venv/bin/python" dashboard.py > $DASHBOARD_LOG 2>&1 &
DASHBOARD_PID=$!
sleep 2

echo "⏳ Configurando router..."
sudo ./router-control.sh start
sleep 5

# Verificar que la red está configurada
if ip addr show $AP_IFACE | grep -q "$AP_GATEWAY"; then
    echo "✓ Red configurada ($AP_GATEWAY)"
else
    echo "⚠ Advertencia: La red $AP_NETWORK no está configurada"
fi

echo "⏳ Iniciando modelo..."
cd "$MODEL_DIR"

# Usar entorno virtual unificado
"$PROJECT_DIR/venv/bin/python" model_server.py > "$MODEL_LOG" 2>&1 &
MODEL_PID=$!

sleep 3

# Verificar detección de red en el modelo (solo para ml_flows)
if [ "$MODEL_TYPE" = "ml_flows" ] || [ "$MODEL_TYPE" = "ml" ]; then
    DETECTED_NET=$(grep "Red local detectada" "$MODEL_LOG" 2>/dev/null | tail -1 | grep -oP '\d+\.\d+\.\d+\.\d+/\d+' || echo "")
    if [ "$DETECTED_NET" = $AP_NETWORK ]; then
        echo "✓ Red $DETECTED_NET detectada correctamente"
    elif [ -n "$DETECTED_NET" ]; then
        echo "⚠ Advertencia: Modelo detectó red $DETECTED_NET (esperada: $AP_NETWORK)"
    fi
fi

echo "⏳ Iniciando captura de tráfico..."
cd "$PROJECT_DIR/router-system"

# El modo de captura se determina automáticamente por config.py según MODEL_TYPE
# ml_flows/simulated_flows → traffic_capture.py
# dl_packets → traffic_capture_packets.py

# Determinar qué script usar basado en MODEL_TYPE
case "$MODEL_TYPE" in
    "ml_flows"|"ml"|"simulated_flows"|"simulated")
        CAPTURE_SCRIPT="traffic_capture.py"
        echo "📊 Modo: Flows (CICFlowMeter)"
        ;;
    "dl_packets")
        CAPTURE_SCRIPT="traffic_capture_packets.py"
        echo "📦 Modo: Packets (PCAP)"
        ;;
esac

sudo "$PROJECT_DIR/venv/bin/python" "$CAPTURE_SCRIPT" > $TRAFFIC_CAPTURE_LOG 2>&1 &
TRAFFIC_PID=$!
sleep 2

echo ""
echo "=== Estado de los servicios ==="
echo "Firewall Manager (PID: $FIREWALL_PID): $(ps -p $FIREWALL_PID > /dev/null && echo '✓ Activo' || echo '✗ Inactivo')"
echo "Dashboard (PID: $DASHBOARD_PID): $(ps -p $DASHBOARD_PID > /dev/null && echo '✓ Activo' || echo '✗ Inactivo')"
echo "Modelo (PID: $MODEL_PID): $(ps -p $MODEL_PID > /dev/null && echo '✓ Activo' || echo '✗ Inactivo')"
echo "Traffic Capture (PID: $TRAFFIC_PID): $(ps -p $TRAFFIC_PID > /dev/null && echo '✓ Activo' || echo '✗ Inactivo')"
echo "Hostapd: $(sudo systemctl is-active hostapd)"
echo "Dnsmasq: $(sudo systemctl is-active dnsmasq)"

echo ""
echo "=== URLs de acceso ==="
case "$MODEL_TYPE" in
    "ml_flows"|"ml")
        echo "  - Modelo ML: $MODEL_ML_URL"
        echo "  - Dashboard del modelo: http://localhost:5001/"
        ;;
    "simulated_flows"|"simulated")
        echo "  - Modelo simulado: $MODEL_SIMULATED_URL"
        ;;
    "dl_packets")
        echo "  - Modelo DL: MODEL_DL_URL"
        ;;
esac
echo "  - Dashboard del router: http://$AP_GATEWAY:$DASHBOARD_PORT"
echo "  - Firewall API: http://$AP_GATEWAY:$FIREWALL_PORT/health"
echo ""
echo "Para ver logs:"
echo "  tail -f $MODEL_LOG"
echo "  tail -f /tmp/firewall.log"
echo "  tail -f /tmp/dashboard.log"
echo "  tail -f /tmp/traffic_capture.log"
