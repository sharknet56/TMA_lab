# Servidor de Clasificación IoT - Random Forest

Este servidor utiliza un modelo Random Forest entrenado para clasificar dispositivos IoT en 4 macro-categorías basándose en patrones de tráfico de red.

##  Características

- **Modelo**: Random Forest Classifier
- **Categorías**: 
  -  **MULTIMEDIA**: Cámaras, Video, Audio (alto ancho de banda)
  -  **SMART_CONTROLS**: Plugs, Lighting, Sensores de movimiento
  - 🌡️ **SENSORS**: Weather, Air Quality, Sleep (bajo tráfico)
  -  **COMPUTING**: Router, Smartphone, PC

##  Instalación

### 1. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 2. Generar el modelo

Si aún no has generado los archivos del modelo, ejecuta el notebook `IntentoFinal.ipynb`:

```bash
jupyter notebook IntentoFinal.ipynb
```

Esto generará:
- `model.pkl` - Modelo entrenado (Random Forest)
- `encoder.pkl` - Encoder de etiquetas

**Nota**: El servidor carga automáticamente las categorías desde el encoder, por lo que no es necesario configurarlas manualmente.

### 3. Iniciar el servidor

```bash
python model_server.py
```

El servidor estará disponible en `http://localhost:5001`

##  API Endpoints

### Health Check
```bash
GET /health
```
Verifica el estado del servidor y del modelo.

### Recibir Flows
```bash
POST /flows
Content-Type: application/json

{
  "flows": [
    {
      "src_ip": "192.168.50.10",
      "dst_ip": "192.168.50.1",
      "src_port": 45231,
      "dst_port": 80,
      "protocol": 6,
      "packets": 150,
      "bytes": 45000,
      "duration": 10.5
    }
  ]
}
```

### Predicción Directa
```bash
POST /predict
Content-Type: application/json

{
  "packets": 100,
  "bytes": 50000,
  ...
}
```

### Estadísticas
```bash
GET /stats
```
Obtiene estadísticas detalladas del servidor.

### Flows Recientes
```bash
GET /recent_flows?limit=20
```
Obtiene los últimos flows procesados.

### Dashboard Web
```bash
GET /
```
Dashboard web interactivo con estadísticas en tiempo real.

##  Testing

Usa el cliente de prueba para verificar el funcionamiento:

```bash
python test_client.py
```

Este script ejecutará varios tests:
-  Health check
-  Dashboard disponibilidad
-  Estadísticas del servidor
-  Clasificación de flows simulados
-  Predicción directa

##  Estructura del Proyecto

```
5_dataset_model/
├── IntentoFinal.ipynb          # Notebook de entrenamiento
├── model_server.py             # Servidor Flask
├── test_client.py              # Cliente de prueba
├── requirements.txt            # Dependencias
├── config.json                 # Configuración
├── README.md                   # Este archivo
├── iot_device_classifier_rf.pkl  # Modelo entrenado
├── label_encoder.pkl           # Encoder de etiquetas
└── archive/                    # Datasets de entrenamiento
    ├── CIC_IoT_Part_1.csv
    ├── CIC_IoT_Part_2.csv
    ├── Lab_1.csv
    ├── Lab_2.csv
    └── UNSW_IoT_Traces.csv
```

##  Configuración

Edita `config.json` para cambiar:
- Puerto del servidor
- URL del firewall
- Configuración del modelo

##  Integración con Firewall

El servidor puede enviar automáticamente las categorías clasificadas al firewall:

```python
FIREWALL_URL = 'http://192.168.50.1:5000'
```

Las categorías se mapean a niveles de amenaza:
- `MULTIMEDIA` → `high_bandwidth`
- `SMART_CONTROLS` → `iot_control`
- `SENSORS` → `low_traffic`
- `COMPUTING` → `general_device`

##  Métricas del Modelo

El modelo fue entrenado con validación cruzada 5-fold:
- **Accuracy promedio**: ~XX%
- **F1-Score (weighted)**: ~XX%
- **F1-Score (macro)**: ~XX%

(Ver resultados completos en el notebook)

##  Solución de Problemas

### Error: "Model not loaded"
Verifica que existen los archivos:
- `iot_device_classifier_rf.pkl`
- `label_encoder.pkl`

### Error: "Número de features incorrecto"
Los flows deben tener las mismas features que el dataset de entrenamiento.

### Error al conectar con firewall
Verifica que el firewall está ejecutándose en la URL configurada.

##  Notas

- El servidor está optimizado para recibir flows en formato similar al dataset de entrenamiento
- Se requiere ajustar el procesamiento de flows según el formato específico de tu sistema de captura
- El dashboard web se actualiza automáticamente cada 5 segundos

##  Desarrollo

Para modificar el modelo:
1. Edita el notebook `IntentoFinal.ipynb`
2. Re-entrena el modelo
3. Reinicia el servidor

##  Licencia

Este proyecto es parte del laboratorio TMA.
