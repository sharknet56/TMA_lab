#!/bin/bash
# Script para detener todo y limpiar completamente el sistema

echo "=== Deteniendo todos los servicios Python ==="
sudo pkill -9 -f "python3 dashboard.py"
sudo pkill -9 -f "python3 firewall_manager.py"
pkill -9 -f "python3 model_server.py"
pkill -9 -f "python3 traffic_capture.py"
echo "Servicios Python detenidos"
sleep 2

echo ""
echo "=== Deteniendo router y servicios ==="
# Obtener el directorio del proyecto
if [ -n "$SUDO_USER" ]; then
    USER_HOME=$(eval echo ~$SUDO_USER)
else
    USER_HOME=$HOME
fi
PROJECT_DIR="$USER_HOME/Documentos/UPC/TMA/project"

cd "$PROJECT_DIR/router-system"
sudo ./router-control.sh stop
echo "Router detenido"
sleep 2

echo ""
echo "=== Eliminando directorio /etc/router-system/ ==="
if [ -d "/etc/router-system" ]; then
    sudo rm -rf /etc/router-system
    echo "Directorio /etc/router-system/ eliminado"
else
    echo "El directorio /etc/router-system/ no existe"
fi

echo ""
echo "=== Limpiando archivos PID y estado ==="
sudo rm -f /var/run/hostapd.pid
sudo rm -f /var/run/dnsmasq.pid
echo "Archivos de estado limpiados"

echo ""
echo "=== Limpiando logs ==="
sudo rm -f /tmp/model.log /tmp/firewall.log /tmp/dashboard.log
sudo rm -f /var/log/hostapd.log /var/log/dnsmasq.log
sudo rm -f /var/log/firewall_manager.log /var/log/traffic_capture.log /var/log/dashboard.log
echo "Logs eliminados"

echo ""
echo "=== Verificando procesos ==="
REMAINING=$(ps aux | grep -E "python3.*(model_server|firewall_manager|dashboard|traffic_capture)" | grep -v grep)
if [ -z "$REMAINING" ]; then
    echo "✓ No hay procesos Python corriendo"
else
    echo "⚠ Procesos restantes:"
    echo "$REMAINING"
fi

echo ""
echo "=== Sistema completamente detenido y limpiado ==="
echo "Para reiniciar ejecuta: sudo ./restart_all.sh"
