# Simulated Model for Testing

Simulated ML model server that allows testing the firewall system without needing a real model. It receives PCAP files and flows, and sends predefined categories to the firewall to block specific IPs.

## Description

This simulated model acts as a configurable traffic classification server that allows:
- Manually defining which IPs should be blocked and in which categories
- Testing the firewall's behavior without training models
- Simulating different threat scenarios
- Validating the entire system flow

## Configuration

### Environment Variables

The server uses the following variables defined in `.env`:

```bash
MODEL_SIMULATED_PORT=8000      # Simulated server port
FIREWALL_PORT=5000             # Firewall manager port
```

### Predefined Categories

The model includes default threat categories:
- `malware`: Malware-infected devices
- `phishing`: Phishing activity
- `suspicious`: Suspicious behavior
- `port_scan`: Port scanning
- `ddos`: Denial of service attacks

## API Endpoints

### Health Check
```bash
GET /health
```
Checks the server status and returns statistics.

### Receive PCAP
```bash
POST /pcap
Content-Type: multipart/form-data

file: file.pcap
```
Receives PCAP files from the capture system.

### Receive Flows
```bash
POST /flows
Content-Type: application/json

{
  "flows": [
    {
      "src_ip": "192.168.50.10",
      "dst_ip": "8.8.8.8",
      "src_port": 54321,
      "dst_port": 443,
      "protocol": 6,
      "packets": 10,
      "bytes": 1500
    }
  ]
}
```
Receives aggregated flows from the capture system.

### Configure Categories
```bash
POST /configure
Content-Type: application/json

{
  "categories": {
    "malware": ["192.168.50.15", "192.168.50.23"],
    "phishing": ["192.168.50.8"]
  }
}
```
Updates the IPs and categories to simulate.

### Manual Trigger
```bash
POST /trigger
Content-Type: application/json

{
  "mode": "all"  // Options: all, random, rotate
}
```
Manually triggers a firewall update.

### IP Management
```bash
POST /add_to_category
Content-Type: application/json

{
  "category": "malware",
  "ips": ["192.168.50.25"]
}
```

```bash
POST /remove_from_category
Content-Type: application/json

{
  "category": "malware",
  "ips": ["192.168.50.25"]
}
```

### Statistics
```bash
GET /stats
```
Returns server statistics and current configuration.

### Recent Flows
```bash
GET /recent_flows
```
Gets the last received flows (maximum 20).

## Web Interface

The server includes a web control interface available at (depending on the configured port):
```
http://localhost:8000
```

### Interface Features
- Real-time statistics visualization
- Manual blocking/unblocking of IPs
- Category management
- Recent flows visualization
- Quick actions (send all IPs, random subset, clear)

## Usage

### Start the Server
```bash
# From the simulated-model directory
python3 model_server.py
```

### With Environment Variables
```bash
MODEL_SIMULATED_PORT=8000 FIREWALL_PORT=5000 python3 model_server.py
```

### System Integration
The server starts automatically with:
```bash
sudo ./quick_start.sh
```
when `MODEL_TYPE=simulated_flows` in `.env`.

## Logs

The server logs events in:
```
logs/model_simulated.log
```

## Dependencies

```
Flask
requests
```

Install with:
```bash
pip3 install -r requirements.txt
```

## Use Cases

### Firewall Testing
Useful for validating that the firewall correctly blocks IPs according to categories.

### Development
Allows developing and testing system components without dependencies on complex ML models.

### Demos
Ideal for demonstrations where full control over which IPs are blocked is needed.

## Notes

- The server communicates with the firewall manager at `http://localhost:${FIREWALL_PORT}`
- Categories are sent automatically after receiving PCAP or flows
- The last 20 received flows are kept in memory for visualization
- Statistics are updated in real-time
