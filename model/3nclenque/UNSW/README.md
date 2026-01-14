# IoT Traffic Analysis

Guía rápida para ejecutar el análisis de tráfico IoT (Flows vs Packets).

## Estructura de Carpetas
El notebook `IoT_Traffic_Analysis.ipynb` debe estar en el mismo directorio que las carpetas de datos del dataset UNSW:
- `flows/` (Archivos CSV)
- `pcaps/` (Archivos PCAP)

## Instalación y Ejecución
Se recomienda usar un entorno virtual para aislar las dependencias, **Jupyter te lo crea de forma guiada**, pero si no ejecuta:

```bash
# 1. Crear entorno virtual
python3 -m venv venv

# 2. Activar entorno
source venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt
```

Abre el notebook en VS Code o Jupyter y ejecuta las celdas en orden.

### Solución de problemas GPU
Existe una celda para comprobar el uso de GPU. Si tienes una NVIDIA y `nvidia-smi` funciona pero TensorFlow usa CPU o faltan librerías (ej. `libcudart`, `libcudnn`):

1. Instala la versión de TensorFlow que incluye las librerías CUDA necesarias:
   ```bash
   pip install "tensorflow[and-cuda]"
   ```
2. Reinicia el kernel del notebook y vuelve a ejecutar la celda de comprobación.

Ver resultado de la configuración en `image.png`.

### Hardware y parámetros de entrenamiento
Hardware: NVIDIA RTX 2080

Parámetros usados:
```text
DATA_FRAC = 0.1
CANTIDAD_META = 1000000
MAX_LEN = 500
MAX_PKTS_PER_FILE = 10000