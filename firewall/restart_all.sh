#!/bin/bash
# Script para reiniciar todo el sistema limpiamente

# Obtener el directorio home del usuario real (no root)
if [ -n "$SUDO_USER" ]; then
    USER_HOME=$(eval echo ~$SUDO_USER)
else
    USER_HOME=$HOME
fi

PROJECT_DIR="$USER_HOME/Documentos/UPC/TMA/project"

echo "=== Deteniendo todos los servicios ==="
sudo pkill -9 -f "python3 dashboard.py"
sudo pkill -9 -f "python3 firewall_manager.py"
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
sudo rm -f /tmp/model.log /tmp/firewall.log /tmp/dashboard.log

echo ""
echo "=== Iniciando modelo simulado ==="
cd "$PROJECT_DIR/simulated-model"
sudo -u $SUDO_USER python3 model_server.py > /tmp/model.log 2>&1 &
echo "Modelo iniciado (PID: $!)"
sleep 2

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
echo "  - Modelo simulado: http://localhost:8000"
echo "  - Dashboard: http://192.168.50.1:8081"
echo "  - Firewall API: http://192.168.50.1:5000/health"
echo ""
echo "Para ver logs:"
echo "  tail -f /tmp/model.log"
echo "  tail -f /tmp/firewall.log"
echo "  tail -f /tmp/dashboard.log"
