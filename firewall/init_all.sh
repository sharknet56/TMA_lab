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
    echo ""
else
    echo "⚠ Usando configuración por defecto"
    echo ""
    MODEL_TYPE="ml_flows"
fi
echo ""
echo "=== Verificando directorios de logs ==="
# Crear directorio de logs si no existe
if [ ! -d "$PROJECT_DIR/logs" ]; then
    mkdir -p "$PROJECT_DIR/logs"
    echo "✓ Directorio logs/ creado"
else
    echo "✓ Directorio logs/ ya existe"
fi

# Crear archivos de log si no existen
LOG_FILES=(
    "$MODEL_ML_LOG"
    "$MODEL_SIMULATED_LOG"
    "$MODEL_DL_LOG"
    "$FIREWALL_LOG"
    "$DASHBOARD_LOG"
    "$TRAFFIC_CAPTURE_LOG"
    "$ROUTER_LOG"
)

for log_file in "${LOG_FILES[@]}"; do
    if [ ! -z "$log_file" ]; then
        log_path="$PROJECT_DIR/$log_file"
        if [ ! -f "$log_path" ]; then
            touch "$log_path"
            chmod 644 "$log_path"
        fi
    fi
done

echo "✓ Archivos de log verificados"
echo ""

# Determinar directorio y puerto del modelo según MODEL_TYPE
case "$MODEL_TYPE" in
    "ml_flows"|"ml")
        MODEL_DIR="$PROJECT_DIR/model_ml"
        MODEL_PORT=$MODEL_ML_PORT
        MODEL_LOG="$MODEL_ML_LOG"
        ;;
    "simulated_flows"|"simulated")
        MODEL_DIR="$PROJECT_DIR/simulated-model"
        MODEL_PORT=$MODEL_SIMULATED_PORT
        MODEL_LOG=$MODEL_ML_LOG
        ;;
    "dl_packets")
        MODEL_DIR="$PROJECT_DIR/model_dl"
        MODEL_PORT=$MODEL_DL_PORT
        MODEL_LOG=$MODEL_DL_LOG
        ;;
    *)
        echo "⚠ MODEL_TYPE desconocido: $MODEL_TYPE, usando ml_flows"
        echo ""
        MODEL_DIR="$PROJECT_DIR/model_ml"
        MODEL_PORT=$MODEL_ML_PORT
        MODEL_LOG="$MODEL_ML_LOG"
        ;;
esac

echo "  Directorio: $MODEL_DIR"
echo "  Puerto: $MODEL_PORT"
echo ""

echo ""
echo "=== 2/6 Limpiando sistema anterior ==="
# Llamar a stop_all.sh para detener servicios
"$PROJECT_DIR/stop_all.sh" 2>/dev/null || true

# Detener router si existe
if [ -f "$PROJECT_DIR/router-system/router-control.sh" ]; then
    cd "$PROJECT_DIR/router-system"
    sudo ./router-control.sh stop 2>/dev/null || true
fi

# Limpiar PIDs
sudo rm -f /var/run/hostapd.pid /var/run/dnsmasq.pid

# Limpiar logs
sudo rm -f $MODEL_ML_LOG $MODEL_ML_LOG $FIREWALL_LOG $DASHBOARD_LOG $TRAFFIC_CAPTURE_LOG
sudo rm -f /var/log/hostapd.log /var/log/dnsmasq.log
sudo rm -f /var/log/firewall_manager.log /var/log/traffic_capture.log /var/log/dashboard.log

echo "✓ Sistema limpio"
echo ""
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
echo ""
sleep 1

echo ""
echo "=== 4/6 Verificando router-system ==="
cd "$PROJECT_DIR/router-system"


    
echo "  Interfaz Internet: $INTERNET_IFACE"
echo "  Interfaz AP: $AP_IFACE"
echo ""
    
# Ejecutar install.sh con valores por defecto (no interactivo)
if [ -f "install.sh" ]; then
    # Crear respuestas automáticas para el install.sh
    {
        echo $INTERNET_IFACE
        echo $AP_IFACE
        echo $WIFI_SSID
        echo $WIFI_PASSWORD
        echo "http://localhost:$MODEL_PORT/pcap"
        echo "http://localhost:$MODEL_PORT/flows"
    } | sudo ./install.sh 2>&1 | grep -v "^read:"
    echo "✓ Router instalado"
    echo ""
else
    echo "⚠ install.sh no encontrado, continuando..."
    echo ""
fi

echo ""
sleep 2

echo ""
echo "=== 5/6 Iniciando modelo ==="
cd "$MODEL_DIR"

# Todos los modelos usan el mismo entorno virtual unificado
"$PROJECT_DIR/venv/bin/python" model_server.py > "$PROJECT_DIR/$MODEL_LOG" 2>&1 &
MODEL_PID=$!

echo "✓ Modelo iniciado (PID: $MODEL_PID, puerto: $MODEL_PORT)"
echo ""
sleep 3

# Verificar que el modelo está corriendo
if ps -p $MODEL_PID > /dev/null; then
    echo "✓ Modelo corriendo correctamente"
    echo ""
else
    echo "❌ Error: el modelo no está corriendo"
    echo "Ver log: tail -f $PROJECT_DIR/$MODEL_LOG"
    echo ""
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
        echo "  • Modelo ML:              http://localhost:$MODEL_ML_PORT"
        echo "  • Dashboard del modelo:   http://localhost:$MODEL_ML_PORT/"
        ;;
    "simulated_flows"|"simulated")
        echo "  • Modelo simulado:        http://localhost:$MODEL_SIMULATED_PORT"
        ;;
    "dl_packets")
        echo "  • Modelo DL:              http://localhost:$MODEL_DL_PORT"
        ;;
esac
echo "  • Dashboard del router:   http://localhost:$DASHBOARD_PORT"
echo "  • Firewall API:           http://localhost:$FIREWALL_PORT/health"

echo ""
echo "📋 Logs disponibles:"
echo "  tail -f $PROJECT_DIR/$MODEL_LOG"
echo "  tail -f $PROJECT_DIR/$FIREWALL_LOG"
echo "  tail -f $PROJECT_DIR/$DASHBOARD_LOG"
echo "  tail -f $PROJECT_DIR/$TRAFFIC_CAPTURE_LOG"

echo ""
echo "🔧 Comandos útiles:"
echo "  ./stop_all.sh                    # Detener todo"
echo "  ./restart_all.sh                 # Reiniciar sistema"
echo "  ./config_manager.sh              # Configurar sistema"
echo "  sudo ./init_all.sh --reinstall   # Forzar reinstalación del router"

echo ""
