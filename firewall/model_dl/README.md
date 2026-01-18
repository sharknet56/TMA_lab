# Deep Learning Model Server

Servidor de clasificación de dispositivos IoT basado en Deep Learning (LSTM/CNN).

## Descripción

Este servidor recibe **archivos PCAP** (capturas de paquetes de red) y clasifica dispositivos IoT en 14 categorías usando un modelo de Deep Learning entrenado con redes neuronales.

## Diferencias con model_ml

| Característica | model_ml | model_dl |
|----------------|----------|----------|
| **Entrada** | Flows (estadísticas agregadas) | PCAPs (paquetes individuales) |
| **Modelo** | Random Forest (scikit-learn) | LSTM/CNN (TensorFlow/Keras) |
| **Formato** | JSON con features de flows | Archivos binarios PCAP |
| **Procesamiento** | Estadísticas de flujo | Secuencias de paquetes |
| **Puerto** | 5001 | 5002 |

## Arquitectura

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│   Traffic   │ PCAP │   Model DL   │ JSON │  Firewall   │
│   Capture   ├─────→│   Server     ├─────→│   Manager   │
│  (packets)  │      │  (DL/LSTM)   │      │             │
└─────────────┘      └──────────────┘      └─────────────┘
```

## Archivos del Modelo

El modelo requiere tres archivos en la carpeta `inference/`:

1. **best_model.keras** - Modelo de red neuronal entrenado
2. **label_encoder.pkl** - Encoder para decodificar predicciones
3. **model_config.json** - Configuración del modelo (clases, parámetros)

## Categorías Soportadas

- **Alexa / SmartSpeaker** - Asistentes de voz
- **IndoorCamera / SecurityCamera / MonitorCamera** - Cámaras
- **MotionSensor / EnvironmentalSensor / HealthSensor** - Sensores
- **SmartPlug / SmartBulb / SmartLock** - Dispositivos de control
- **Hub** - Hubs de domótica
- **Printer** - Impresoras
- **Other** - Otros dispositivos

## Instalación

```bash
# Instalar dependencias
pip install tensorflow scapy flask requests

# O usar el venv unificado
sudo /path/to/firewall/venv/bin/pip install tensorflow
```

## Uso

### Iniciar el servidor

```bash
cd /path/to/firewall/model_dl
python3 model_server.py
```

O usar el sistema de inicio:

```bash
# Configurar MODEL_TYPE=dl_packets en .env
echo "MODEL_TYPE=dl_packets" >> /path/to/firewall/.env

# Iniciar todo el sistema
sudo ./quick_start.sh
```

### Endpoints

#### Health Check
```bash
GET http://localhost:5002/health
```

Respuesta:
```json
{
  "status": "ok",
  "model_status": "loaded",
  "model_type": "deep_learning",
  "model_classes": ["Alexa", "EnvironmentalSensor", ...],
  "max_len": 500
}
```

#### Enviar PCAP
```bash
POST http://localhost:5002/pcap
Content-Type: multipart/form-data

file: capture.pcap
```

Respuesta:
```json
{
  "status": "processed",
  "predictions_count": 3,
  "devices": ["192.168.50.10", "192.168.50.15"],
  "message": "3 devices classified"
}
```

#### Estadísticas
```bash
GET http://localhost:5002/stats
```

#### Dispositivos Detectados
```bash
GET http://localhost:5002/devices
```

#### Dashboard Web
```
http://localhost:5002/
```

## Cliente de Prueba

```bash
# Test básico
python3 test_client.py

# Test con archivo PCAP
python3 test_client.py /path/to/capture.pcap
```

## Procesamiento de Paquetes

El servidor:
1. Recibe el archivo PCAP
2. Extrae paquetes usando Scapy
3. Agrupa paquetes por IP de origen (dispositivo)
4. Extrae features de cada paquete (tamaño, protocolo, etc.)
5. Crea secuencias de hasta 500 paquetes por dispositivo
6. Aplica padding/truncado para ajustar al tamaño del modelo
7. Predice la categoría con el modelo DL
8. Actualiza el firewall con la clasificación

## Configuración

Editar `config.json`:

```json
{
  "processing": {
    "max_packets_per_sequence": 500,
    "min_packets_for_prediction": 10,
    "confidence_threshold": 0.5
  },
  "firewall": {
    "url": "http://192.168.50.1:5000",
    "enabled": true
  }
}
```

## Logs

Los logs del servidor se guardan en:
```
/path/to/firewall/logs/model_dl.log
```

Ver logs:
```bash
tail -f logs/model_dl.log
```

## Integración con traffic_capture_packets

El script `traffic_capture_packets.py` captura paquetes y los envía automáticamente al modelo:

```python
# En traffic_capture_packets.py
PCAP_SEND_URL = 'http://localhost:5002/pcap'
```

## Troubleshooting

### Modelo no carga
```bash
# Verificar archivos
ls -lh inference/
# Debe mostrar: best_model.keras, label_encoder.pkl, model_config.json
```

### TensorFlow no disponible
```bash
sudo /path/to/venv/bin/pip install tensorflow
```

### Error de memoria
Si el modelo consume demasiada memoria, reducir el tamaño de secuencia en `model_config.json`.

### PCAP no se procesa
Verificar que Scapy está instalado:
```bash
sudo /path/to/venv/bin/pip install scapy
```

## Performance

- **Velocidad**: ~100-200 ms por PCAP (depende del tamaño)
- **Memoria**: ~500 MB - 1 GB (modelo en memoria)
- **CPU**: Utiliza CPU para inferencia (puede usar GPU si TensorFlow está configurado)

## Comparación de Precisión

Según el `model_config.json`:
- **Test Accuracy**: 98.95%
- **F1 Macro**: 92.06%

Excelente para clasificación de dispositivos IoT en tiempo real.
