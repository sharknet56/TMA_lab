# IoT Traffic Analysis

Guía rápida para ejecutar el análisis de tráfico IoT (Flows vs Packets).

## Estructura de Carpetas
El notebook `IoT_Traffic_Analysis.ipynb` debe estar en el mismo directorio que las carpetas de datos del dataset UNSW:
- `flows/` (Archivos CSV)
- `pcaps/` (Archivos PCAP)

## Instalación y Ejecución
Se recomienda usar un entorno virtual para aislar las dependencias:

```bash
# 1. Crear entorno virtual
python3 -m venv venv

# 2. Activar entorno
source venv/bin/activate

# 3. Instalar dependencias básicas
pip install -r requirements.txt
```

Abre el notebook en VS Code o Jupyter y ejecuta las celdas en orden.

## Solución de Problemas GPU
Si tienes una gráfica NVIDIA y el comando `nvidia-smi` funciona, pero TensorFlow dice que faltan librerías (como `libcudart` o `libcudnn`) o usa la CPU:

1. Instala la versión de TensorFlow que incluye las librerías CUDA necesarias:
   ```bash
   pip install "tensorflow[and-cuda]"
   ```
2. **Reinicia el Kernel** del notebook y vuelve a probar la celda de comprobación de GPU.
