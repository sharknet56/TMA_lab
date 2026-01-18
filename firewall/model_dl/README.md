# Modelo Deep Learning - Servidor de Inferencia

Servidor Flask que recibe archivos PCAP y clasifica dispositivos IoT usando el modelo de Deep Learning entrenado.

## Archivos

- `model_server.py`: Servidor Flask principal
- `inference/classify_pcap.py`: Script de clasificación de PCAPs
- `inference/best_model.keras`: Modelo entrenado
- `inference/label_encoder.pkl`: Codificador de etiquetas
- `inference/model_config.json`: Configuración del modelo

## Instalación

```bash
pip install flask requests tensorflow scapy numpy
```

## Uso

### Iniciar el servidor

```bash
python model_server.py
```

El servidor se iniciará en `http://localhost:5002`

### Endpoints disponibles

#### `GET /health`
Health check del servidor y estado del modelo

```bash
curl http://localhost:5002/health
```

Respuesta:
```json
{
  "status": "ok",
  "model_loaded": true,
  "classifier_available": true,
  "timestamp": "2026-01-18T...",
  "stats": {...}
}
```

#### `POST /pcap`
Enviar un archivo PCAP para clasificación

```bash
curl -X POST -F "file=@traffic.pcap" http://localhost:5002/pcap
```

Respuesta:
```json
{
  "status": "processed",
  "message": "PCAP analyzed successfully",
  "result": {
    "device": "Amazon_Echo",
    "confidence": 0.95,
    "category": "MULTIMEDIA",
    "total_packets": 1000,
    "valid_packets": 950
  },
  "firewall_updated": true
}
```

#### `GET /stats`
Obtener estadísticas del servidor

```bash
curl http://localhost:5002/stats
```

#### `GET /predictions`
Obtener todas las predicciones recientes

```bash
curl http://localhost:5002/predictions
```

#### `GET /`
Dashboard web con estadísticas en tiempo real

Abre en tu navegador: `http://localhost:5002`

## Integración con el Firewall

El servidor se comunica automáticamente con el firewall en `http://192.168.50.1:5000` enviando categorías de dispositivos detectados.

### Mapeo de Dispositivos a Categorías

El servidor mapea los dispositivos clasificados a categorías de seguridad:

- **MULTIMEDIA**: Amazon Echo, Smart TV, Chromecast
- **SMART_CONTROLS**: SmartThings, TP-Link Plug, Philips Hue
- **SENSORS**: Netatmo Weather, Withings Sleep
- **COMPUTING**: iPhone, MacBook, Android Phone

Puedes personalizar este mapeo editando `DEVICE_TO_CATEGORY` en `model_server.py`.

## Configuración

Variables de entorno:

- `FIREWALL_URL`: URL del firewall (default: `http://192.168.50.1:5000`)
- `MODEL_DL_PORT`: Puerto del servidor (default: `5002`)

## Testing

Ver `test_client.py` para ejemplos de uso del cliente.

## Logs

El servidor registra todas las operaciones con timestamps:

- ✅ Modelo cargado
- 📦 PCAPs recibidos
- 🔄 Clasificaciones en proceso
- ✅ Dispositivos detectados
- 📤 Actualizaciones al firewall
- ❌ Errores

## Notas

- El modelo procesa hasta 1000 paquetes por PCAP para optimizar rendimiento
- Los archivos PCAP se guardan temporalmente y se eliminan después del procesamiento
- Las predicciones recientes se mantienen en memoria (últimas 50)
- El servidor puede tardar unos segundos en cargar el modelo al iniciar
