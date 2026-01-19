# Router/Firewall System with Machine Learning

A complete WiFi router system with a dynamic firewall controlled by Machine Learning for IoT device detection and classification.

## Features

### WiFi Router
- Configurable WiFi Access Point (WPA2)
- Automatic DHCP server
- NAT/Routing to the internet
- No loss of connection on the host machine

### Dynamic Firewall
- Blocking by categories (malware, phishing, etc.)
- Real-time updates via REST API
- Granular control per IP
- Enable/Disable categories without losing IPs

### Traffic Capture
- Packet capture (PCAP) or flows (CICFlowMeter)
- Automatic sending to the ML model
- Configurable mode from the dashboard or .env

### ML Models
- **ml_flows**: Random Forest with flows (port 5001)
- **simulated_flows**: Simulated model with flows (port 8000)
- **dl_packets**: Deep Learning with packets (port 5002)

### Web Dashboard
- Real-time monitoring
- Visualization of connected clients
- Control of categories and configuration
- System statistics


## Quick Start

### Full Installation (first time)
```bash
# 1. Copy example configuration (If not done, it will be copied automatically on initialization)
cp .env.example .env

# 2. Edit configuration (optional)
nano .env

# 3. Initialize system
sudo ./init_all.sh
```

### Daily Use
```bash
# Start or restart the system
sudo ./quick_start.sh

# Stop the system
./stop_all.sh
```

## Configuration

### .env File

All system variables are centralized in `.env`:

```bash
# Interfaces
AP_IFACE=wlxc83a35b5a9f5          # WiFi USB for AP
INTERNET_IFACE=wlp2s0              # Internet connection

# WiFi
WIFI_SSID=RouterFirewall           # Network name
WIFI_PASSWORD=SecurePass123        # Password (min 8 characters)
WIFI_CHANNEL=6                     # WiFi channel (1-11)

# Network
AP_NETWORK=192.168.50.0/24
AP_GATEWAY=192.168.50.1
AP_DHCP_START=192.168.50.20
AP_DHCP_END=192.168.50.100

# Model
MODEL_TYPE=ml_flows                # ml_flows | simulated_flows | dl_packets

# Traffic capture (automatic based on MODEL_TYPE)
FLOW_BUFFER_SIZE=100
FLOW_SEND_INTERVAL=10
PCAP_BUFFER_SIZE=1000
PCAP_SEND_INTERVAL=30
```

### Model Types

#### 1. ml_flows (Random Forest + Flows)
```bash
MODEL_TYPE=ml_flows
```
- Port: 5001
- Script: `traffic_capture.py`
- Data: 79 CICFlowMeter features
- Directory: `model_ml/`

#### 2. simulated_flows (Testing + Flows)
```bash
MODEL_TYPE=simulated_flows
```
- Port: 8000
- Script: `traffic_capture.py`
- Data: 79 CICFlowMeter features
- Directory: `simulated-model/`

#### 3. dl_packets (Deep Learning + Packets)
```bash
MODEL_TYPE=dl_packets
```
- Port: 5002
- Script: `traffic_capture_packets.py`
- Data: Full PCAP files
- Directory: `model_dl/`

### Changing Configuration

#### Method 1: Text editor
```bash
nano .env
# Modify variables
sudo ./quick_start.sh
```

#### Method 2: Web Dashboard
1. Open `http://localhost:8081`
2. "Configuration" section
3. Change capture mode
4. Click "Apply Change"

#### Method 3: Interactive script
```bash
./config_manager.sh
```

## Available Scripts

### `init_all.sh` - Full installation
Installs and configures the entire system from scratch.

```bash
sudo ./init_all.sh              # Use model_ml
sudo ./init_all.sh simulated    # Use simulated-model
sudo ./init_all.sh --reinstall  # Force router reinstallation
```

**Includes:**
- Cleanup of previous installations
- Dependency installation
- Router configuration
- Copying `.env.example` to `.env`
- Starting all services

### `quick_start.sh` - Quick start
Starts the system without reinstalling (faster).

```bash
sudo ./quick_start.sh           # Use .env configuration
```

**Requirements:**
- Router already installed
- `.env` file configured


### `stop_all.sh` - Stop all
Stops all services and cleans up resources.

```bash
./stop_all.sh
```

**Actions:**
- Stops Python processes (dashboard, firewall, model, capture)
- Stops router (hostapd, dnsmasq)
- Cleans PIDs and logs

### `config_manager.sh` - Configuration manager
Interactive tool to modify `.env`.

**Options:**
1. Change capture mode
2. Configure interfaces
3. Configure WiFi
4. Configure AP network
5. Adjust buffers and timings

## Access URLs

Once the system is started:

| Service          | URL                               |
|------------------|-----------------------------------|
| Router Dashboard | http://localhost:8081          |
| Firewall API     | http://localhost:5000/health   |
| ML Model         | http://localhost:5001             |
| Simulated Model  | http://localhost:8000             |
| Model Dashboard  | http://localhost:5001/            |


## Troubleshooting

### System does not start
```bash
# View logs
tail -f /tmp/model_server.log
tail -f /tmp/firewall.log
tail -f /tmp/dashboard.log
tail -f /tmp/traffic_capture.log

# Check processes
ps aux | grep python3 | grep -E "model_server|firewall|dashboard|traffic_capture"
```

### Interfaces not detected
```bash
# List available interfaces
ip link show

# Edit .env with correct interfaces
nano .env

# Restart
sudo ./restart_all.sh
```

### Model does not load
```bash
# Check model files
ls -la model_ml/*.pkl

# For model_ml: check virtual environment
ls -la model_ml/ml/

# For simulated-model: check dependencies
pip3 install -r simulated-model/requirements.txt
```

### Changes in .env are not applied
```bash
# Check current configuration
python3 router-system/config.py

# Restart system
sudo ./restart_all.sh
```

### "Model not loaded" error
```bash
# For model_ml
cd model_ml
./ml/bin/pip install -r requirements.txt

# Check files
ls -la *.pkl
```

### Port in use
```bash
# See which process is using the port
sudo lsof -i :5001
sudo lsof -i :8000
sudo lsof -i :5002

# Stop all and restart
sudo ./quick_start.sh
```

## System Components

For more information on each component, consult the specific READMEs:

- [router-system/](router-system/README.md): Router, firewall, dashboard, and traffic capture system
- [model_ml/](model_ml/README.md): Random Forest model for flow-based classification
- [simulated-model/](simulated-model/README.md): Simulated model for testing and development
- [model_dl/](model_dl/README.md): Deep Learning model for PCAP packet analysis

## Important Notes

### Differences between Capture Scripts

**traffic_capture.py (FLOWS)**
- Calculates 79 features per flow (CICFlowMeter)
- Sends aggregated statistics
- Lower bandwidth usage
- Compatible with: ml_flows, simulated_flows

**traffic_capture_packets.py (PACKETS)**
- Sends full PCAP files
- More detailed information
- Higher bandwidth usage
- Compatible with: dl_packets

### Model Compatibility

The system automatically detects which script to use based on `MODEL_TYPE`:
- `ml_flows` → uses `traffic_capture.py`
- `simulated_flows` → uses `traffic_capture.py`
- `dl_packets` → uses `traffic_capture_packets.py`

### Logs

All logs are saved in `/tmp/`:
```bash
/tmp/model_server.log      # ML Model
/tmp/model.log             # Simulated Model
/tmp/firewall.log          # Firewall manager
/tmp/dashboard.log         # Dashboard
/tmp/traffic_capture.log   # Traffic capture
```

## Security

- The `.env` file contains sensitive information and is excluded from git
- Use `.env.example` as a template
- Change the default `WIFI_PASSWORD`
- Passwords must be at least 8 characters long

## License

This project is part of the TMA - UPC laboratory.