# IoT Traffic Analysis & Intelligent Firewall

This repository contains the implementation of an experimental firewall system powered by Machine Learning and Deep Learning models. The system performs real-time traffic analysis to classify IoT devices (e.g., Cameras, Smart Speakers) and enforces security policies via Access Control Lists (ACLs) based on the identified device type.

## Repository Organization

The project is structured into two main directories distinguishing between the production application and the research phase:

### 1. `firewall/` (Operational System)

Contains the executable code for the real-time firewall.

* **`router-system/`**: Handles traffic capture (`traffic_capture.py`), the web dashboard, and interaction with system `iptables` or ACLs.
* **`model_dl/` & `model_ml/**`: dedicated folders for hosting the Deep Learning and Machine Learning inference engines (servers).
* **`simulated-model/`**: A lightweight dummy model for integration testing.
* **Scripts (`*.sh`)**: Automation scripts for initialization, configuration, and shutdown.

### 2. `models/` (Research & Training)

Contains the Jupyter Notebooks used for data analysis, feature extraction, and model training.

* **`DL-Alberto/`**: Deep Learning experiments focusing on Packet-level analysis, Time Windows, and Burst aggregation.
* **`DL-Oscar/`**: Multi-dataset generalization strategies and specific tests on the UNSW dataset.
* **`ML-David/`**: Baseline Machine Learning implementations (Random Forest/XGBoost) on flow statistics.

---

## Installation & Requirements

The firewall requires **Python 3.10+** and administrative privileges (root/sudo) to capture network traffic and modify firewall rules.

1. Navigate to the firewall directory:
```bash
cd firewall
```

2. Install the necessary dependencies:
```bash
pip install -r requirements.txt
```


---

## Usage Instructions

The system is designed to run as a modular architecture where the **Router/Capture System** and the **Model Server** run as separate processes communicating via sockets.

### 1. Quick Start (Recommended)

The easiest way to launch the full system is using the automated shell script. This script detects the environment and launches the Traffic Capture, the Model Server, and the Dashboard.

```bash
cd firewall
sudo ./quick_start.sh
```

### 2. System Configuration

To switch between the Machine Learning (ML), Deep Learning (DL), or Simulated backends, use the configuration manager before starting the system:

```bash
./config_manager.sh
```

*Follow the on-screen prompts to select the active model architecture.*

### 3. Manual Execution (Modular)

If you need to debug specific components, you can run them individually in separate terminals:

**Terminal 1: Start the Model Server**

```bash
# Example for Deep Learning model
cd firewall/model_dl
python model_server.py
```

**Terminal 2: Start the Router & Capture System**
*Note: This requires the model server to be running first.*

```bash
cd firewall/router-system
sudo python traffic_capture.py
```

**Terminal 3: Start the Dashboard**

```bash
cd firewall/router-system
python dashboard.py
```

### 4. Stopping the System

To safely stop all background processes and restore network rules:

```bash
cd firewall
sudo ./stop_all.sh
```

---

## Estructura Detallada del Proyecto

```
TMA_lab/
│
├── README.md                          # Documentación principal del proyecto
│
├── firewall/                          # Sistema operacional del firewall
│   ├── config_manager.sh              # Script para seleccionar el modelo activo (ML/DL/Simulado)
│   ├── init_all.sh                    # Inicializa todos los componentes del sistema
│   ├── quick_start.sh                 # Lanzamiento rápido del sistema completo
│   ├── stop_all.sh                    # Detiene todos los procesos y restaura reglas de red
│   ├── test_model_dl.sh               # Script de prueba para el modelo de Deep Learning
│   ├── requirements.txt               # Dependencias Python del sistema operacional
│   │
│   ├── model_dl/                      # Servidor de inferencia Deep Learning
│   │   ├── config.json                # Configuración del servidor DL (puerto, modelo, etc.)
│   │   ├── model_server.py            # Servidor de inferencia que procesa datos secuenciales
│   │   ├── test_client.py             # Cliente de prueba para verificar comunicación
│   │   ├── test_model_loading.py      # Verifica la carga correcta del modelo
│   │   ├── README.md                  # Documentación específica del modelo DL
│   │   └── inference/                 # Recursos del modelo entrenado
│   │       ├── best_model.keras       # Modelo Deep Learning entrenado (formato Keras)
│   │       ├── label_encoder.pkl      # Codificador de etiquetas de clases
│   │       ├── model_config.json      # Configuración de arquitectura del modelo
│   │       ├── classify_pcap.py       # Clasificación directa desde archivos PCAP
│   │       └── README.md              # Documentación de inferencia
│   │
│   ├── model_ml/                      # Servidor de inferencia Machine Learning
│   │   ├── config.json                # Configuración del servidor ML
│   │   ├── model_server.py            # Servidor de inferencia basado en flujos estadísticos
│   │   ├── test_client.py             # Cliente de prueba
│   │   ├── test_model_loading.py      # Verificación de carga del modelo
│   │   └── README.md                  # Documentación del modelo ML
│   │
│   ├── simulated-model/               # Modelo simulado para pruebas de integración
│   │   ├── config.json                # Configuración del modelo dummy
│   │   ├── model_server.py            # Servidor simulado (respuestas aleatorias/fijas)
│   │   ├── test_client.py             # Cliente de prueba
│   │   └── README.md                  # Documentación del modelo simulado
│   │
│   └── router-system/                 # Sistema central de captura y control
│       ├── config.py                  # Configuración general (interfaces, IPs, políticas)
│       ├── traffic_capture.py         # Captura de tráfico y envío al modelo (basado en flujos)
│       ├── traffic_capture_packets.py # Captura alternativa basada en paquetes individuales
│       ├── firewall_manager.py        # Gestión de reglas iptables/ACLs
│       ├── dashboard.py               # Dashboard web Flask para monitoreo en tiempo real
│       ├── router-control.sh          # Control manual del sistema del router
│       ├── router.state               # Estado persistente del sistema
│       ├── install.sh                 # Script de instalación de dependencias del router
│       └── README.md                  # Documentación del sistema router
│
└── models/                            # Carpeta de investigación y entrenamiento
    │
    ├── DL-Alberto/                    # Experimentos de Deep Learning (Alberto)
    │   └── [Notebooks Jupyter]        # Análisis a nivel de paquetes, ventanas temporales, bursts
    │
    ├── DL-Oscar/                      # Experimentos de Deep Learning (Oscar)
    │   └── [Notebooks Jupyter]        # Generalización multi-dataset, pruebas UNSW
    │
    └── ML-David/                      # Experimentos de Machine Learning (David)
        └── [Notebooks Jupyter]        # Random Forest, XGBoost, estadísticas de flujos
```

### Descripción de Componentes Clave

#### Sistema Operacional (`firewall/`)

**Scripts de Automatización:**
- `quick_start.sh`: Punto de entrada principal. Detecta el modelo activo y lanza todos los componentes.
- `config_manager.sh`: Interfaz interactiva para cambiar entre backends ML/DL/Simulado.
- `stop_all.sh`: Limpieza segura de procesos y reglas de firewall.

**Servidores de Modelos:**
- Cada carpeta (`model_dl/`, `model_ml/`, `simulated-model/`) contiene un servidor independiente que escucha en un socket TCP.
- Reciben datos preprocesados y devuelven clasificaciones de dispositivos IoT.
- `config.json` define puerto, ruta al modelo y parámetros de inferencia.

**Sistema Router:**
- `traffic_capture.py`: Captura paquetes en tiempo real, los agrupa en flujos y envía características al modelo.
- `firewall_manager.py`: Traduce decisiones del modelo en reglas iptables por dirección MAC.
- `dashboard.py`: Interfaz web (Flask) para visualizar dispositivos detectados, clasificaciones y acciones del firewall.

#### Investigación (`models/`)

Contiene los Jupyter Notebooks utilizados para:
- Exploración de datasets (CIC-IoT, UNSW, laboratorio propio).
- Ingeniería de características (flujos estadísticos, series temporales de paquetes).
- Entrenamiento y evaluación de modelos ML/DL.
- Exportación de modelos finales al directorio `firewall/`.

---

## Architecture Overview

The application follows a real-time pipeline:

1. **Capture:** Raw packets are intercepted from the network interface.
2. **Pre-processing:** Data is transformed into either Flow Statistics (ML) or Time-Series sequences (DL).
3. **Inference:** The data is sent to the active `model_server`.
4. **Decision:** The model returns a device classification (e.g., "Smart Camera").
5. **Enforcement:** If the device type matches a blocklist policy, the `firewall_manager` applies an ACL rule to the device's MAC address.
