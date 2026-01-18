
# 🚀 IoT Device Classifier - Inference Package

## 📦 Archivos Incluidos:
- `best_model.keras`: Modelo CNN entrenado
- `label_encoder.pkl`: Codificador de etiquetas
- `model_config.json`: Configuración del modelo
- `classify_pcap.py`: Script de inferencia

## 🎯 Clases que puede detectar:
  - Alexa
  - EnvironmentalSensor
  - HealthSensor
  - Hub
  - IndoorCamera
  - MonitorCamera
  - MotionSensor
  - Other
  - Printer
  - SecurityCamera
  - SmartBulb
  - SmartLock
  - SmartPlug
  - SmartSpeaker

## 📊 Rendimiento:
- Accuracy: 98.95%
- F1-Score: 92.06%

## 🔧 Uso:
```bash
python classify_pcap.py <archivo.pcap>
```

## ⚙️ Requisitos:
```bash
pip install tensorflow scapy numpy
```
