#!/bin/bash
# Script para inicializar todo el sistema desde cero
# Uso: sudo ./init_all.sh [simulated] [--reinstall]
# Por defecto usa model_ml, con argumento 'simulated' usa simulated-model
# --reinstall: Fuerza reinstalación del router-system

# Verificar que se ejecuta como root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Este script debe ejecutarse con sudo"
    echo "Uso: sudo ./init_all.sh [simulated] [--reinstall]"
    exit 1
fi

# Determinar qué modelo usar y opciones
MODEL_TYPE=${1:-ml}
FORCE_REINSTALL=false

for arg in "$@"; do
    if [ "$arg" = "simulated" ]; then
        MODEL_TYPE="simulated"
    elif [ "$arg" = "--reinstall" ]; then
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

if [ "$MODEL_TYPE" = "simulated" ]; then
    MODEL_DIR="$PROJECT_DIR/simulated-model"
    MODEL_PORT=8000
    echo "📦 Modelo: simulated-model (puerto $MODEL_PORT)"
else
    MODEL_DIR="$PROJECT_DIR/model_ml"
    MODEL_PORT=5001
    echo "🤖 Modelo: model_ml (puerto $MODEL_PORT)"
fi

echo ""
echo "=== 1/5 Limpiando sistema anterior ==="
# Detener servicios existentes
sudo pkill -9 -f "python3 dashboard.py" 2>/dev/null
sudo pkill -9 -f "python3 firewall_manager.py" 2>/dev/null
sudo pkill -9 -f "python model_server.py" 2>/dev/null
pkill -9 -f "python3 model_server.py" 2>/dev/null
pkill -9 -f "python3 traffic_capture.py" 2>/dev/null

# Detener router si existe
if [ -f "$PROJECT_DIR/router-system/router-control.sh" ]; then
    cd "$PROJECT_DIR/router-system"
    sudo ./router-control.sh stop 2>/dev/null
fi

# Limpiar directorio de configuración
if [ -d "/etc/router-system" ]; then
    sudo rm -rf /etc/router-system
fi

# Limpiar PIDs
sudo rm -f /var/run/hostapd.pid /var/run/dnsmasq.pid

# Limpiar logs
sudo rm -f /tmp/model.log /tmp/model_server.log /tmp/firewall.log /tmp/dashboard.log
sudo rm -f /var/log/hostapd.log /var/log/dnsmasq.log
sudo rm -f /var/log/firewall_manager.log /var/log/traffic_capture.log /var/log/dashboard.log

echo "✓ Sistema limpio"
sleep 2

echo ""
echo "=== 2/5 Instalando dependencias del modelo ==="
cd "$MODEL_DIR"

if [ "$MODEL_TYPE" = "simulated" ]; then
    # Para simulated-model, instalar dependencias del sistema
    if [ -f "requirements.txt" ]; then
        echo "Instalando paquetes Python..."
        pip3 install -q -r requirements.txt
        echo "✓ Dependencias instaladas"
    fi
else
    # Para model_ml, verificar/crear entorno virtual
    if [ ! -d "ml" ]; then
        echo "Creando entorno virtual..."
        python3 -m venv ml
    fi
    
    echo "Instalando dependencias en entorno virtual..."
    ./ml/bin/pip install -q -r requirements.txt
    echo "✓ Entorno virtual configurado"
fi

sleep 1

echo ""
echo "=== 3/5 Verificando router-system ==="
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
            echo "RouterFirewall"
            echo "SecurePass123"
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
echo "=== 4/5 Iniciando modelo ==="
cd "$MODEL_DIR"

if [ "$MODEL_TYPE" = "simulated" ]; then
    MODEL_LOG="/tmp/model.log"
    python3 model_server.py > "$MODEL_LOG" 2>&1 &
else
    MODEL_LOG="/tmp/model_server.log"
    ./ml/bin/python model_server.py > "$MODEL_LOG" 2>&1 &
fi

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
echo "=== 5/5 Iniciando router-system ==="
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
echo "  ./stop_all.sh                    # Detener todo"
echo "  ./restart_all.sh                 # Reiniciar con model_ml"
echo "  ./restart_all.sh simulated       # Reiniciar con simulated-model"
echo "  sudo ./init_all.sh --reinstall   # Forzar reinstalación del router"

echo ""
