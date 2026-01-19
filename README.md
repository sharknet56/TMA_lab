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

## Architecture Overview

The application follows a real-time pipeline:

1. **Capture:** Raw packets are intercepted from the network interface.
2. **Pre-processing:** Data is transformed into either Flow Statistics (ML) or Time-Series sequences (DL).
3. **Inference:** The data is sent to the active `model_server`.
4. **Decision:** The model returns a device classification (e.g., "Smart Camera").
5. **Enforcement:** If the device type matches a blocklist policy, the `firewall_manager` applies an ACL rule to the device's MAC address.
