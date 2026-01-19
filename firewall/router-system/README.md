# Router-Firewall System

Integrated WiFi router system with a dynamic firewall and traffic capture for analysis using Machine Learning models.

## Components

### config.py
Centralized configuration module that loads variables from the `.env` file and provides unified access to the system's configuration.

**Functionalities:**
- Loading of environment variables from `.env`
- Configuration validation
- Automatic detection of capture mode based on model type
- Calculation of absolute paths for temporary files

### dashboard.py
Web interface for real-time system monitoring and control.

**Features:**
- Visualization of clients connected to the AP
- Firewall category management
- IP blocking/unblocking control
- System statistics
- Dynamic configuration of capture mode

**Port:** Defined in `DASHBOARD_PORT` (default 8081)

**Access:** `http://localhost:DASHBOARD_PORT`

### firewall_manager.py
Firewall manager using iptables that controls IP blocking by categories.

**Functionalities:**
- Management by categories
- Activation/deactivation of entire categories
- REST API for integration with ML models
- Rule persistence

**Port:** Defined in `FIREWALL_PORT` (default 5000)

### traffic_capture.py
Network traffic capture system in flows mode (CICFlowMeter).

**Features:**
- Packet capture on the AP interface
- Calculation of 79 features per flow
- Traffic aggregation by quintuples (src_ip, dst_ip, src_port, dst_port, protocol)
- Periodic sending to the ML model
- Management of active and inactive flows

**Compatible with:**
- `MODEL_TYPE=ml_flows`
- `MODEL_TYPE=simulated_flows`

### traffic_capture_packets.py
Network traffic capture system in packets mode (full PCAP).

**Features:**
- Raw packet capture
- Generation of PCAP files
- Sending of complete files to the DL model
- Configurable packet buffer

**Compatible with:**
- `MODEL_TYPE=dl_packets`

### router-control.sh
Control script for the WiFi router (hostapd and dnsmasq).

**Commands:**
```bash
./router-control.sh start    # Start router
./router-control.sh stop     # Stop router
./router-control.sh restart  # Restart router
./router-control.sh status   # View status
```

### install.sh
Installer for the WiFi router system.

**Actions:**
- Installation of dependencies (hostapd, dnsmasq, iptables)
- Configuration of hostapd and dnsmasq
- Configuration of NAT and IP forwarding
- Configuration persistence

## Environment Variables

All variables are defined in the `.env` file in the parent directory (`firewall/.env`).

### Network Interfaces
```bash
AP_IFACE=wlxc83a35b5a9f5         # WiFi interface for access point
INTERNET_IFACE=wlp2s0             # Interface with Internet connection
```

### WiFi Configuration
```bash
WIFI_SSID=RouterFirewall          # WiFi network name
WIFI_PASSWORD=SecurePass123       # WPA2 password
WIFI_CHANNEL=6                    # WiFi channel (1-13)
```

### Access Point Network
```bash
AP_NETWORK=192.168.50.0/24        # Network range
AP_GATEWAY=192.168.50.1           # Gateway IP
AP_DHCP_START=192.168.50.10       # First DHCP IP
AP_DHCP_END=192.168.50.100        # Last DHCP IP
```

### Traffic Capture
```bash
TRAFFIC_CAPTURE_MODE=packets      # Mode: flows or packets
FLOW_BUFFER_SIZE=100              # Flows in buffer
FLOW_SEND_INTERVAL=10             # Send interval (seconds)
PCAP_BUFFER_SIZE=1000             # Packets in buffer
PCAP_SEND_INTERVAL=30             # PCAP send interval (seconds)
```

### Service Ports
```bash
FIREWALL_PORT=5000                # Firewall manager port
DASHBOARD_PORT=8081               # Dashboard port
```

## APIs

### Firewall Manager API

#### Health Check
```bash
GET http://localhost:5000/health
```

Checks the server status.

Response:
```json
{
  "status": "healthy",
  "timestamp": "2026-01-19T10:30:00"
}
```

#### Update Categories
```bash
POST http://localhost:5000/update_categories
Content-Type: application/json

{
  "categories": {
    "malware": ["192.168.50.15", "192.168.50.23"],
    "phishing": ["192.168.50.8"],
    "suspicious": ["192.168.50.12"]
  }
}
```

Replaces all categories with the new ones provided.

Response:
```json
{
  "status": "success",
  "categories_applied": 3,
  "total_ips_blocked": 5,
  "timestamp": "2026-01-19T10:30:00"
}
```

#### Add IPs to Category
```bash
POST http://localhost:5000/add_to_category
Content-Type: application/json

{
  "category": "malware",
  "ips": ["192.168.50.99", "192.168.50.100"]
}
```

Adds IPs to an existing category without removing others.

#### Remove IPs from Category
```bash
POST http://localhost:5000/remove_from_category
Content-Type: application/json

{
  "category": "malware",
  "ips": ["192.168.50.99"]
}
```

Removes specific IPs from a category.

#### Get Active Categories
```bash
GET http://localhost:5000/get_categories
```

Returns all categories and their IPs.

Response:
```json
{
  "categories": {
    "malware": ["192.168.50.15"],
    "phishing": ["192.168.50.8"]
  },
  "active_categories": ["malware", "phishing"],
  "stats": {
    "total_updates": 10,
    "total_blocked_ips": 2,
    "last_update": "2026-01-19T10:30:00"
  }
}
```

#### Get iptables Rules
```bash
GET http://localhost:5000/get_rules
```

Returns the current iptables rules.

#### Enable/Disable Category
```bash
POST http://localhost:5000/toggle_category
Content-Type: application/json

{
  "category": "malware",
  "enabled": true
}
```

Enables or disables an entire category without removing its IPs.

#### Clear Specific Category
```bash
POST http://localhost:5000/clear_category
Content-Type: application/json

{
  "category": "malware"
}
```

Deletes a category and all its IPs.

#### Clear All Categories
```bash
POST http://localhost:5000/clear_all
```

Deletes all categories and firewall rules.

#### Statistics
```bash
GET http://localhost:5000/stats
```

Returns firewall statistics.

Response:
```json
{
  "total_updates": 10,
  "total_blocked_ips": 15,
  "last_update": "2026-01-19T10:30:00"
}
```

### Dashboard API

The dashboard exposes endpoints for the web interface and system control. Access through the browser at the dashboard URL.

## Workflow

1. **Traffic Capture**: The capture module (`traffic_capture.py` or `traffic_capture_packets.py`) monitors the AP interface
2. **Send to Model**: Captured data is sent to the configured ML model
3. **Classification**: The model analyzes and classifies the traffic
4. **Firewall Update**: The model sends categories to the firewall manager
5. **Rule Application**: The firewall manager updates iptables to block IPs
6. **Monitoring**: The dashboard shows the real-time status

## Logs

System logs are saved in the directory specified in `.env`:

```bash
FIREWALL_LOG=logs/firewall.log
DASHBOARD_LOG=logs/dashboard.log
TRAFFIC_CAPTURE_LOG=logs/traffic_capture.log
ROUTER_LOG=logs/router.log
```

## System Requirements

### System Dependencies
- hostapd
- dnsmasq
- iptables
- iproute2
- Python 3.8+

### Python Dependencies
- Flask
- requests
- scapy
- psutil

## Troubleshooting

### Interface not detected
Check available interfaces:
```bash
ip link show
```

### Firewall not blocking
Check iptables rules:
```bash
sudo iptables -L -n -v
```

### Capture not working
Check permissions and that the interface is in promiscuous mode:
```bash
sudo ip link set ${AP_IFACE} promisc on
```

### Debug logs
Check logs in real-time:
```bash
tail -f logs/traffic_capture.log
tail -f logs/firewall.log
tail -f logs/dashboard.log
```

## Security Notes

- The system requires root privileges to manage iptables and packet capture
- WiFi credentials must be configured in `.env` and the file kept out of version control
- The firewall only acts on AP traffic, it does not affect the host
- It is recommended to use strong passwords for WiFi (minimum 8 characters)
