#!/bin/bash
# test_model_dl.sh - Script para probar el modelo DL sin arrancar todo el sistema

echo "=================================================="
echo "🧪 Test del Modelo Deep Learning"
echo "=================================================="
echo ""

# Directorio del script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_DIR="$SCRIPT_DIR/model_dl"

# 1. Verificar archivos del modelo
echo "1️⃣  Verificando archivos del modelo..."
echo ""

files_ok=true

if [ ! -f "$MODEL_DIR/inference/best_model.keras" ]; then
    echo "❌ No se encuentra: inference/best_model.keras"
    files_ok=false
else
    echo "✅ best_model.keras ($(du -h "$MODEL_DIR/inference/best_model.keras" | cut -f1))"
fi

if [ ! -f "$MODEL_DIR/inference/label_encoder.pkl" ]; then
    echo "❌ No se encuentra: inference/label_encoder.pkl"
    files_ok=false
else
    echo "✅ label_encoder.pkl"
fi

if [ ! -f "$MODEL_DIR/inference/model_config.json" ]; then
    echo "❌ No se encuentra: inference/model_config.json"
    files_ok=false
else
    echo "✅ model_config.json"
fi

if [ "$files_ok" = false ]; then
    echo ""
    echo "❌ Faltan archivos del modelo"
    echo "Asegúrate de tener todos los archivos en model_dl/inference/"
    echo ""
    exit 1
fi

echo ""

# 2. Verificar dependencias de Python
echo "2️⃣  Verificando dependencias de Python..."
echo ""

deps_ok=true

python3 -c "import flask" 2>/dev/null || {
    echo "❌ Flask no está instalado"
    deps_ok=false
}
python3 -c "import flask" 2>/dev/null && echo "✅ flask"

python3 -c "import tensorflow" 2>/dev/null || {
    echo "❌ TensorFlow no está instalado"
    deps_ok=false
}
python3 -c "import tensorflow" 2>/dev/null && echo "✅ tensorflow"

python3 -c "import scapy.all" 2>/dev/null || {
    echo "❌ Scapy no está instalado"
    deps_ok=false
}
python3 -c "import scapy.all" 2>/dev/null && echo "✅ scapy"

python3 -c "import requests" 2>/dev/null || {
    echo "❌ Requests no está instalado"
    deps_ok=false
}
python3 -c "import requests" 2>/dev/null && echo "✅ requests"

python3 -c "import numpy" 2>/dev/null || {
    echo "❌ NumPy no está instalado"
    deps_ok=false
}
python3 -c "import numpy" 2>/dev/null && echo "✅ numpy"

if [ "$deps_ok" = false ]; then
    echo ""
    echo "❌ Faltan dependencias"
    echo "Instalar con: pip install -r $MODEL_DIR/requirements.txt"
    echo ""
    exit 1
fi

echo ""

# 3. Verificar que el puerto esté libre
echo "3️⃣  Verificando puerto 5002..."
echo ""

if lsof -Pi :5002 -sTCP:LISTEN -t >/dev/null 2>&1 ; then
    echo "⚠️  El puerto 5002 ya está en uso"
    echo ""
    echo "Proceso usando el puerto:"
    lsof -Pi :5002 -sTCP:LISTEN
    echo ""
    echo "Opciones:"
    echo "  1. Detener el proceso: kill \$(lsof -t -i:5002)"
    echo "  2. El servidor ya está corriendo, prueba: curl http://localhost:5002/health"
    echo ""
    exit 1
else
    echo "✓ Puerto 5002 disponible"
    echo ""
fi

echo ""

# 4. Iniciar el servidor
echo "4️⃣  Iniciando servidor de modelo DL..."
echo ""
echo "📡 Servidor iniciando en http://localhost:5002"
echo "🌐 Dashboard disponible en http://localhost:5002"
echo ""
echo "Presiona Ctrl+C para detener"
echo ""
echo "=================================================="
echo ""

cd "$MODEL_DIR"
python3 model_server.py
