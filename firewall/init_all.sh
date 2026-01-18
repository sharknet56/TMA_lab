#!/bin/bash
# Script para inicializar todo el sistema desde cero
# Uso: sudo ./init_all.sh [--reinstall]
# Lee configuración desde .env
# --reinstall: Fuerza reinstalación del router-system

# Verificar que se ejecuta como root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Este script debe ejecutarse con sudo"
    echo "Uso: sudo ./init_all.sh [--reinstall]"
    exit 1
fi

# Opciones
FORCE_REINSTALL=false
for arg in "$@"; do
    if [ "$arg" = "--reinstall" ]; then
        FORCE_REINSTALL=true
    fi
done

# Obtener el directorio del script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$SCRIPT_DIR"

echo "╔════════════════════════════════════════════╗"
echo "║   Inicialización completa del sistema      ║"
echo "╚════════════════════════════════════════════╝"
echo ""

echo ""
echo "=== 1/6 Preparando configuración ==="
# Copiar .env.example a .env si no existe
if [ ! -f "$PROJECT_DIR/.env" ]; then
    if [ -f "$PROJECT_DIR/.env.example" ]; then
        cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
        echo "✓ Archivo .env creado desde .env.example"
    else
        echo "⚠ Advertencia: .env.example no encontrado"
    fi
else
    echo "✓ Archivo .env ya existe"
fi

# Leer configuración desde .env
if [ -f "$PROJECT_DIR/.env" ]; then
    source "$PROJECT_DIR/.env"
    echo "✓ Configuración leída desde .env"
    echo "  Modelo: $MODEL_TYPE"
else
    echo "⚠ Usando configuración por defecto"
    MODEL_TYPE="ml_flows"
fi

# Determinar directorio y puerto del modelo según MODEL_TYPE
case "$MODEL_TYPE" in
    "ml_flows"|"ml")
        MODEL_DIR="$PROJECT_DIR/model_ml"
        MODEL_PORT=5001
        MODEL_LOG="/tmp/model_server.log"
        ;;
    "simulated_flows"|"simulated")
        MODEL_DIR="$PROJECT_DIR/simulated-model"
        MODEL_PORT=8000
        MODEL_LOG="/tmp/model.log"
        ;;
    "dl_packets")
        MODEL_DIR="$PROJECT_DIR/model_dl"
        MODEL_PORT=5002
        MODEL_LOG="/tmp/model_dl.log"
        ;;
    *)
        echo "⚠ MODEL_TYPE desconocido: $MODEL_TYPE, usando ml_flows"
        MODEL_DIR="$PROJECT_DIR/model_ml"
        MODEL_PORT=5001
        MODEL_LOG="/tmp/model_server.log"
        ;;
esac

echo "  Directorio: $MODEL_DIR"
echo "  Puerto: $MODEL_PORT"

echo ""
echo "=== 2/6 Limpiando sistema anterior ==="
# Llamar a stop_all.sh para detener servicios
"$PROJECT_DIR/stop_all.sh" 2>/dev/null || true

# Detener router si existe
if [ -f "$PROJECT_DIR/router-system/router-control.sh" ]; then
    cd "$PROJECT_DIR/router-system"
    sudo ./router-control.sh stop 2>/dev/null || true
fi

# Limpiar directorio de configuración
if [ -d "/etc/router-system" ]; then
    sudo rm -rf /etc/router-system
fi

# Limpiar PIDs
sudo rm -f /var/run/hostapd.pid /var/run/dnsmasq.pid

# Limpiar logs
sudo rm -f /tmp/model.log /tmp/model_server.log /tmp/firewall.log /tmp/dashboard.log /tmp/traffic_capture.log
sudo rm -f /var/log/hostapd.log /var/log/dnsmasq.log
sudo rm -f /var/log/firewall_manager.log /var/log/traffic_capture.log /var/log/dashboard.log

echo "✓ Sistema limpio"
sleep 1

echo ""
echo "=== 3/6 Configurando entorno virtual unificado ==="

# Crear entorno virtual único para todo firewall
if [ ! -d "$PROJECT_DIR/venv" ]; then
    echo "Creando entorno virtual en $PROJECT_DIR/venv..."
    python3 -m venv "$PROJECT_DIR/venv"
    echo "✓ Entorno virtual creado"
else
    echo "✓ Entorno virtual ya existe"
fi

# Instalar dependencias desde requirements.txt unificado
echo "Instalando dependencias desde requirements.txt..."
"$PROJECT_DIR/venv/bin/pip" install --upgrade pip -q
"$PROJECT_DIR/venv/bin/pip" install -r "$PROJECT_DIR/requirements.txt" -q

echo "✓ Dependencias instaladas"
sleep 1

echo ""
echo "=== 4/6 Verificando router-system ==="
cd "$PROJECT_DIR/router-system"

# Verificar si ya está instalado
if [ -d "/etc/router-system" ] && [ "$FORCE_REINSTALL" = false ]; then
    echo "✓ Router ya instalado en /etc/router-system (usa --reinstall para forzar reinstalación)"
else
    if [ "$FORCE_REINSTALL" = true ]; then
        echo "🔄 Forzando reinstalación del router..."
        sudo rm -rf /etc/router-system 2>/dev/null
    else
        echo "⚠ Router no instalado. Instalando con valores por defecto..."
    fi
    
    # Detectar interfaces automáticamente
    AP_IFACE=$(ip link show | grep -oP '^\d+: \K(wlx[0-9a-f]+)' | head -1)
    if [ -z "$AP_IFACE" ]; then
        AP_IFACE="wlan1"  # Fallback
    fi
    
    INTERNET_IFACE=$(ip link show | grep -oP '^\d+: \K(wlp\w+)' | head -1)
    if [ -z "$INTERNET_IFACE" ]; then
        INTERNET_IFACE="wlan0"  # Fallback
    fi
    
    echo "  Interfaz Internet: $INTERNET_IFACE"
    echo "  Interfaz AP: $AP_IFACE"
    
    # Ejecutar install.sh con valores por defecto (no interactivo)
    if [ -f "install.sh" ]; then
        # Crear respuestas automáticas para el install.sh
        {
            echo "$INTERNET_IFACE"
            echo "$AP_IFACE"
            echo "$WIFI_SSID"
            echo "$WIFI_PASSWORD"
            echo "http://localhost:$MODEL_PORT/pcap"
            echo "http://localhost:$MODEL_PORT/flows"
        } | sudo ./install.sh 2>&1 | grep -v "^read:"
        echo "✓ Router instalado"
    else
        echo "⚠ install.sh no encontrado, continuando..."
    fi
fi

sleep 2

echo ""
echo "=== 5/6 Iniciando modelo ==="
cd "$MODEL_DIR"

# Todos los modelos usan el mismo entorno virtual unificado
"$PROJECT_DIR/venv/bin/python" model_server.py > "$MODEL_LOG" 2>&1 &
MODEL_PID=$!

echo "✓ Modelo iniciado (PID: $MODEL_PID, puerto: $MODEL_PORT)"
sleep 3

# Verificar que el modelo está corriendo
if ps -p $MODEL_PID > /dev/null; then
    echo "✓ Modelo corriendo correctamente"
else
    echo "❌ Error: el modelo no está corriendo"
    echo "Ver log: tail -f $MODEL_LOG"
    exit 1
fi

echo ""
echo "=== 6/6 Iniciando router-system ==="
cd "$PROJECT_DIR/router-system"
sudo ./router-control.sh start
sleep 5

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║         Sistema iniciado con éxito         ║"
echo "╚════════════════════════════════════════════╝"
echo ""
echo "📊 Estado de los servicios:"
ps aux | grep -E "python.*(model_server|firewall_manager|dashboard|traffic_capture)" | grep -v grep | awk '{printf "  ✓ PID %-6s %s\n", $2, $11}'

echo ""
echo "🌐 URLs de acceso:"
case "$MODEL_TYPE" in
    "ml_flows"|"ml")
        echo "  • Modelo ML:              http://localhost:5001"
        echo "  • Dashboard del modelo:   http://localhost:5001/"
        ;;
    "simulated_flows"|"simulated")
        echo "  • Modelo simulado:        http://localhost:8000"
        ;;
    "dl_packets")
        echo "  • Modelo DL:              http://localhost:5002"
        ;;
esac
echo "  • Dashboard del router:   http://192.168.50.1:8081"
echo "  • Firewall API:           http://192.168.50.1:5000/health"

echo ""
echo "📋 Logs disponibles:"
echo "  tail -f $MODEL_LOG"
echo "  tail -f /tmp/firewall.log"
echo "  tail -f /tmp/dashboard.log"
echo "  tail -f /tmp/traffic_capture.log"

echo ""
echo "🔧 Comandos útiles:"
echo "  ./stop_all.sh                    # Detener todo"
echo "  ./restart_all.sh                 # Reiniciar sistema"
echo "  ./config_manager.sh              # Configurar sistema"
echo "  sudo ./init_all.sh --reinstall   # Forzar reinstalación del router"

echo ""
