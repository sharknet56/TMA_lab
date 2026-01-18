#!/bin/bash
# Script para detener todo y limpiar completamente el sistema

echo "=== Deteniendo todos los servicios Python ==="
sudo pkill -9 -f "python3 dashboard.py" 2>/dev/null || true
sudo pkill -9 -f "python3 firewall_manager.py" 2>/dev/null || true
sudo pkill -9 -f "python model_server.py" 2>/dev/null || true
pkill -9 -f "python3 model_server.py" 2>/dev/null || true
pkill -9 -f "python3 traffic_capture.py" 2>/dev/null || true
pkill -9 -f "python3 traffic_capture_packets.py" 2>/dev/null || true
echo "Servicios Python detenidos"
sleep 2

echo ""
echo "=== Deteniendo router y servicios de red ==="
# Obtener el directorio del script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$SCRIPT_DIR"

cd "$PROJECT_DIR/router-system"
sudo ./router-control.sh stop
echo "Router detenido"

# Detener hostapd y dnsmasq si siguen corriendo
sudo pkill -9 hostapd 2>/dev/null
sudo pkill -9 dnsmasq 2>/dev/null
sleep 2

echo ""
echo "=== Limpiando archivos PID y estado ==="
sudo rm -f /var/run/hostapd.pid
sudo rm -f /var/run/dnsmasq.pid
echo "Archivos de estado limpiados"

echo ""
echo "=== Limpiando logs ==="
sudo rm -f /tmp/model.log $MODEL_ML_LOG /tmp/firewall.log /tmp/dashboard.log /tmp/traffic_capture.log
sudo rm -f /tmp/router_start.log
sudo rm -f /var/log/hostapd.log /var/log/dnsmasq.log
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
echo "Para reiniciar ejecuta:"
echo "  sudo ./quick_start.sh         # Inicio rápido (recomendado)"
echo "  ./restart_all.sh               # Usa model_ml (por defecto)"
echo "  ./restart_all.sh simulated     # Usa simulated-model"
