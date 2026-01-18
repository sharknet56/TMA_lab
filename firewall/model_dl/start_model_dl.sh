#!/bin/bash
# start_model_dl.sh - Script para iniciar el servidor de modelo DL

echo "=================================================="
echo "🚀 Iniciando servidor de modelo Deep Learning"
echo "=================================================="

# Directorio del script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Verificar archivos del modelo
echo "🔍 Verificando archivos del modelo..."

if [ ! -f "inference/best_model.keras" ]; then
    echo "❌ Error: No se encuentra inference/best_model.keras"
    exit 1
fi

if [ ! -f "inference/label_encoder.pkl" ]; then
    echo "❌ Error: No se encuentra inference/label_encoder.pkl"
    exit 1
fi

if [ ! -f "inference/model_config.json" ]; then
    echo "❌ Error: No se encuentra inference/model_config.json"
    exit 1
fi

echo "✅ Archivos del modelo encontrados"

# Verificar dependencias de Python
echo ""
echo "🔍 Verificando dependencias..."

python3 -c "import flask" 2>/dev/null || {
    echo "⚠ Flask no está instalado. Instalando..."
    pip3 install flask
}

python3 -c "import tensorflow" 2>/dev/null || {
    echo "⚠ TensorFlow no está instalado. Instalando..."
    pip3 install tensorflow
}

python3 -c "import scapy" 2>/dev/null || {
    echo "⚠ Scapy no está instalado. Instalando..."
    pip3 install scapy
}

python3 -c "import requests" 2>/dev/null || {
    echo "⚠ Requests no está instalado. Instalando..."
    pip3 install requests
}

echo "✅ Dependencias verificadas"

# Configuración
export FIREWALL_URL="${FIREWALL_URL:-http://192.168.50.1:5000}"
export MODEL_DL_PORT="${MODEL_DL_PORT:-5002}"

echo ""
echo "📋 Configuración:"
echo "   Puerto: $MODEL_DL_PORT"
echo "   Firewall: $FIREWALL_URL"
echo ""

# Iniciar servidor
echo "🚀 Iniciando servidor..."
echo ""

python3 model_server.py

# Si el script termina
echo ""
echo "⚠ Servidor detenido"
