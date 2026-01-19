# IoT Traffic Analysis & Intelligent Firewall

This repository contains the implementation of an experimental firewall system powered by Machine Learning and Deep Learning models. The system performs real-time traffic analysis to classify IoT devices (e.g., Cameras, Smart Speakers) and enforces security policies via Access Control Lists (ACLs) based on the identified device type.

## Repository Organization

The project is structured into two main directories distinguishing between the production application (`firewall/`) and the research phase (`models/`).

### Directory Structure

```text
TMA_lab/
│
├── README.md                          # Main project documentation
│
├── firewall/                          # Operational firewall system
│   ├── config_manager.sh              # Script to select active model (ML/DL/Simulated)
│   ├── init_all.sh                    # Initializes all system components
│   ├── quick_start.sh                 # Quick launch for the full system
│   ├── stop_all.sh                    # Stops all processes and restores network rules
│   ├── test_model_dl.sh               # Test script for the Deep Learning model
│   ├── requirements.txt               # Python dependencies for the operational system
│   │
│   ├── model_dl/                      # Deep Learning Inference Server
│   │   ├── config.json                # DL server config (port, model path, etc.)
│   │   ├── model_server.py            # Inference server processing sequential data
│   │   ├── test_client.py             # Test client to verify communication
│   │   ├── test_model_loading.py      # Verifies correct model loading
│   │   ├── README.md                  # DL model specific documentation
│   │   └── inference/                 # Trained model resources
│   │       ├── best_model.keras       # Trained Keras model
│   │       ├── label_encoder.pkl      # Class label encoder
│   │       ├── model_config.json      # Model architecture configuration
│   │       ├── classify_pcap.py       # Direct classification from PCAP files
│   │       └── README.md              # Inference documentation
│   │
│   ├── model_ml/                      # Machine Learning Inference Server
│   │   ├── config.json                # ML server config
│   │   ├── model_server.py            # Inference server based on flow statistics
│   │   ├── test_client.py             # Test client
│   │   ├── test_model_loading.py      # Model loading verification
│   │   └── README.md                  # ML model documentation
│   │
│   ├── simulated-model/               # Simulated Model for Integration Testing
│   │   ├── config.json                # Dummy model config
│   │   ├── model_server.py            # Simulated server (random/fixed responses)
│   │   ├── test_client.py             # Test client
│   │   └── README.md                  # Simulated model documentation
│   │
│   └── router-system/                 # Central Capture and Control System
│       ├── config.py                  # General config (interfaces, IPs, policies)
│       ├── traffic_capture.py         # Traffic capture & dispatch to model (flow-based)
│       ├── traffic_capture_packets.py # Alternative capture based on individual packets
│       ├── firewall_manager.py        # iptables/ACLs rule management
│       ├── dashboard.py               # Flask web dashboard for real-time monitoring
│       ├── router-control.sh          # Manual router system control
│       ├── router.state               # Persistent system state
│       ├── install.sh                 # Router dependencies installation script
│       └── README.md                  # Router system documentation
│
└── models/                            # Research & Training Directory
    │
    ├── DL-Alberto/                    # Deep Learning Experiments (Alberto)
    │   └── [Jupyter Notebooks]        # Packet-level analysis, Time Windows, Bursts
    │
    ├── DL-Oscar/                      # Deep Learning Experiments (Oscar)
    │   └── [Jupyter Notebooks]        # Multi-dataset generalization strategies, UNSW tests
    │
    └── ML-David/                      # Machine Learning Experiments (David)
        └── [Jupyter Notebooks]        # Random Forest, XGBoost, Flow statistics
```

### Key Components Description

#### Operational System (`firewall/`)

**Automation Scripts:**
- `quick_start.sh`: Main entry point. Detects the active environment and launches all components.
- `config_manager.sh`: Interactive interface to switch between ML/DL/Simulated backends.
- `stop_all.sh`: Safely cleans up processes and firewall rules.

**Model Servers:**
- Each folder (`model_dl/`, `model_ml/`, `simulated-model/`) contains an independent server listening on a TCP socket.
- They receive pre-processed data and return IoT device classifications.
- `config.json` defines the port, model path, and inference parameters.

**Router System:**
- `traffic_capture.py`: Captures packets in real-time, groups them into flows, and sends features to the model.
- `firewall_manager.py`: Translates model decisions into `iptables` rules by MAC address.
- `dashboard.py`: Web interface (Flask) to visualize detected devices, classifications, and firewall actions.

#### Research (`models/`)

Contains the Jupyter Notebooks used for:
- Dataset exploration (CIC-IoT, UNSW, custom lab data).
- Feature engineering (statistical flows, packet time-series).
- ML/DL model training and evaluation.
- Exporting final models to the `firewall/` directory.

---

## Installation & Requirements

**Note about the test environment:** This project was tested with a USB Wi‑Fi adapter that creates two virtual network interfaces: one with Internet access and another configured as an access point (AP). Some utilities assume this setup; if your hardware or network layout differs, adjust the network configuration.
A utility script to assist with network interface configuration is provided at firewall/setup_interfaces.sh. Depending on the hardware and network topology in use, the default settings in this script may require modification; review and adapt the configuration to match your environment.
```bash
cd firewall
sudo ./setup_interfaces.sh
```

The firewall requires **Python 3.10+** and administrative privileges (root/sudo) to capture network traffic and modify firewall rules.

1. Navigate to the firewall directory:
```bash
cd firewall
```

2. **First Time Installation (Initialization):**
   Run the initialization script to install dependencies, configure the router settings, and set up the environment variables.
```bash
sudo ./init_all.sh
```
   *This will automatically copy `.env.example` to `.env` if it doesn't exist.*

---

## Usage Instructions

The system is designed to be easy to manage via automated scripts, but also allows for modular execution.

### 1. Quick Start (Daily Use)

To start or restart the full system (Traffic Capture + Model Server + Dashboard) using the current configuration:

```bash
cd firewall
sudo ./quick_start.sh
```

### 2. System Configuration

**In theory there is no need to configure more aspects, but just in case there are some considerations**

The system configuration is centralized in the `.env` file. You can modify it in two ways:

**Option A: Interactive Manager (Recommended)**
Use the configuration script to switch between models (ML, DL, Simulated) and adjust network settings:
```bash
./config_manager.sh
```

**Option B: Manual Edit**
Edit the environment file directly:
```bash
nano .env
```
*Key variables: `MODEL_TYPE` (ml_flows, dl_packets, simulated_flows), `WIFI_SSID`, `WIFI_PASSWORD`.*

### 3. Stopping the System

To safely stop all background processes (Python servers, hostapd, dnsmasq) and restore network rules:

```bash
cd firewall
sudo ./stop_all.sh
```

---

## Architecture Overview

The application follows a real-time pipeline:

1. **Capture:** Raw packets are intercepted from the network interface.
2. **Pre-processing:** Data is transformed into either Flow Statistics (ML) or Time-Series sequences (DL).
3. **Inference:** The data is sent to the active `model_server`.
4. **Decision:** The model returns a device classification (e.g., "Smart Camera").
5. **Enforcement:** If the device type matches a blocklist policy, the `firewall_manager` applies an ACL rule to the device's MAC address.