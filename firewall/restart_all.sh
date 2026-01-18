#!/bin/bash
# Script para reiniciar todo el sistema limpiamente
# Uso: ./restart_all.sh [simulated]
# Por defecto usa model_ml, con argumento 'simulated' usa simulated-model

# Determinar qué modelo usar
MODEL_TYPE=${1:-ml}  # Por defecto "ml"
if [ "$1" = "simulated" ]; then
    MODEL_TYPE="simulated"
fi

# Obtener el directorio del script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$SCRIPT_DIR"

echo "=== Configuración ==="
if [ "$MODEL_TYPE" = "simulated" ]; then
    MODEL_DIR="$PROJECT_DIR/simulated-model"
    MODEL_PORT=8000
    MODEL_LOG="/tmp/model.log"
    echo "Usando: simulated-model (puerto $MODEL_PORT)"
else
    MODEL_DIR="$PROJECT_DIR/model_ml"
    MODEL_PORT=5001
    MODEL_LOG="/tmp/model_server.log"
    echo "Usando: model_ml (puerto $MODEL_PORT)"
fi

echo ""
echo "=== Deteniendo todos los servicios ==="
sudo pkill -9 -f "python3 dashboard.py"
sudo pkill -9 -f "python3 firewall_manager.py"
sudo pkill -9 -f "python model_server.py"
pkill -9 -f "python3 model_server.py"
pkill -9 -f "python3 traffic_capture.py"
sleep 2

echo "=== Deteniendo router ==="
cd "$PROJECT_DIR/router-system"
sudo ./router-control.sh stop
sleep 2

echo "=== Eliminando caché de Python ==="
find "$PROJECT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find "$PROJECT_DIR" -type f -name "*.pyc" -delete 2>/dev/null
echo "Caché eliminada"

echo ""
echo "=== Copiando archivos actualizados a /etc/router-system/ ==="
sudo cp "$PROJECT_DIR/router-system/dashboard.py" /etc/router-system/
sudo cp "$PROJECT_DIR/router-system/firewall_manager.py" /etc/router-system/
sudo cp "$PROJECT_DIR/router-system/traffic_capture.py" /etc/router-system/
echo "Archivos actualizados"

echo ""
echo "=== Limpiando logs antiguos ==="
sudo rm -f /tmp/model.log /tmp/model_server.log /tmp/firewall.log /tmp/dashboard.log

echo ""
echo "=== Iniciando modelo ==="
cd "$MODEL_DIR"
if [ "$MODEL_TYPE" = "simulated" ]; then
    python3 model_server.py > "$MODEL_LOG" 2>&1 &
    MODEL_PID=$!
else
    # Para model_ml, usar el entorno virtual
    ./ml/bin/python model_server.py > "$MODEL_LOG" 2>&1 &
    MODEL_PID=$!
fi
echo "Modelo iniciado (PID: $MODEL_PID, puerto: $MODEL_PORT)"
sleep 3

echo ""
echo "=== Iniciando router y firewall ==="
cd "$PROJECT_DIR/router-system"
sudo ./router-control.sh start
sleep 5

# El router-control.sh ya inicia firewall_manager y dashboard desde /etc/router-system/
# No necesitamos iniciarlos de nuevo

echo ""
echo "=== Estado de los servicios ==="
ps aux | grep -E "python3.*(model_server|firewall_manager|dashboard)" | grep -v grep

echo ""
echo "=== URLs de acceso ==="
if [ "$MODEL_TYPE" = "simulated" ]; then
    echo "  - Modelo simulado: http://localhost:8000"
else
    echo "  - Modelo ML: http://localhost:5001"
    echo "  - Dashboard del modelo: http://localhost:5001/"
fi
echo "  - Dashboard del router: http://192.168.50.1:8081"
echo "  - Firewall API: http://192.168.50.1:5000/health"
echo ""
echo "Para ver logs:"
echo "  tail -f $MODEL_LOG"
echo "  tail -f /tmp/firewall.log"
echo "  tail -f /tmp/dashboard.log"
