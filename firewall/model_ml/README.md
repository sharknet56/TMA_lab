# Machine Learning Model - Random Forest

Random Forest-based Machine Learning model server for IoT device classification through network flow analysis.

## Description

This model uses Random Forest to classify network traffic in real-time. It processes aggregated flows (connection statistics) with 79 features calculated by CICFlowMeter and determines which devices should be blocked based on their behavior.

## Features

- Real-time network traffic classification
- Model trained with IoT device datasets
- Processing of flows with 79 features
- REST API for integration with the capture system
- Web interface for monitoring

## Configuration

### Environment Variables

The server uses the following variables defined in `.env`:

```bash
MODEL_ML_PORT=5001             # Model server port
FIREWALL_PORT=5000             # Firewall manager port
MODEL_ML_LAST_FLOWS=10         # Number of recent flows to process
```

### Model Files

The model requires the following PKL (pickle) files in the `model_ml/` directory:

- `model.pkl`: Trained Random Forest model
- `scaler.pkl`: Feature normalizer
- `feature_columns.pkl`: List of feature columns

## Installation

### Create Virtual Environment

```bash
cd model_ml
python3 -m venv ml
source ml/bin/activate
pip install -r requirements.txt
```

### Verify Installation

```bash
python3 test_model_loading.py
```

## API Endpoints

### Health Check
```bash
GET /health
```
Checks the server status and if the model is loaded.

Response:
```json
{
  "status": "ok",
  "model_status": "loaded",
  "model_classes": ["MULTIMEDIA", "SMART_CONTROLS", "SENSORS", "COMPUTING"],
  "timestamp": "2026-01-19T10:30:00",
  "stats": {...}
}
```

### Receive PCAP
```bash
POST /pcap
Content-Type: multipart/form-data

file: traffic.pcap
```

Receives PCAP files from the capture system (compatibility endpoint).

Response:
```json
{
  "status": "received",
  "message": "PCAP file received"
}
```

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
      "bytes": 1500,
      "duration": 1.5
    }
  ]
}
```

Receives flows from the capture system, processes them with the model, and sends categories to the firewall.

Response:
```json
{
  "status": "processed",
  "flows_analyzed": 10,
  "predictions": ["normal", "malware", "normal"],
  "blocked_ips": ["192.168.50.15"]
}
```

### Manual Prediction
```bash
POST /predict
Content-Type: application/json

{
  "flows": [...]
}
```

Performs prediction without updating the firewall.

Response:
```json
{
  "predictions": ["normal", "malware"],
  "classes": [0, 1]
}
```

### Statistics
```bash
GET /stats
```

Returns detailed model statistics.

Response:
```json
{
  "stats": {
    "flows_received": 150,
    "predictions_made": 150,
    "firewall_updates": 12,
    "last_flow": "2026-01-19T10:30:00"
  },
  "devices": {
    "192.168.50.10": {
      "main_category": "MULTIMEDIA",
      "total_predictions": 15,
      "percentages": {"MULTIMEDIA": 100.0}
    }
  },
  "local_network": "192.168.50.0/24",
  "total_devices": 1,
  "categories_summary": {...},
  "model_info": {...}
}
```

### Get Devices
```bash
GET /devices
```

Returns detailed information about all detected devices.

Response:
```json
{
  "devices": [
    {
      "ip": "192.168.50.10",
      "main_category": "MULTIMEDIA",
      "total_predictions": 15,
      "percentages": {"MULTIMEDIA": 100.0}
    }
  ],
  "total": 1
}
```

### Get Device Info
```bash
GET /device/<ip>
```

Returns detailed information about a specific device.

Response:
```json
{
  "ip": "192.168.50.10",
  "total_predictions": 15,
  "main_category": "MULTIMEDIA",
  "percentages": {"MULTIMEDIA": 100.0}
}
```

### Recent Flows
```bash
GET /recent_flows?limit=20
```
Gets the latest processed flows.

### Web Interface
```bash
GET /
```
Interactive web dashboard with real-time statistics.

### Clear Predictions
```bash
POST /clear_predictions
```

Clears all device predictions and processed flows cache.

Response:
```json
{
  "status": "success",
  "message": "All predictions cleared",
  "timestamp": "2026-01-19T10:30:00"
}
```

### Reset Statistics
```bash
POST /reset_stats
```

Resets all global server statistics.

Response:
```json
{
  "status": "success",
  "message": "Statistics reset successfully",
  "timestamp": "2026-01-19T10:30:00"
}
```

## Model Features

The model processes 79 features per flow, including:

### Flow Statistics
- Flow duration
- Number of packets (forward/backward)
- Number of bytes (forward/backward)
- Packet and byte rate

### Packet Characteristics
- Average, minimum, maximum size
- Standard deviation of size
- Variance of size

### Protocol Information
- Protocol (TCP/UDP/ICMP)
- Source and destination ports
- TCP flags

### Temporal Characteristics
- Inter-arrival time (IAT)
- Active/idle time
- Segment duration

### Window Characteristics
- TCP window size
- Window statistics

## Classification Classes

The model classifies devices into the following categories:

- **MULTIMEDIA**: Cameras, Video, Audio devices
- **SMART_CONTROLS**: Smart Plugs, Lighting, Motion sensors
- **SENSORS**: Weather stations, Air Quality, Sleep sensors
- **COMPUTING**: Routers, Smartphones, PCs
- **ENVIRONMENT_SENSING**: Environmental monitoring devices
- **HOME_AUTOMATION**: Home automation hubs
- **NETWORK_CORE**: Core network devices
- **PERSONAL_DEVICES**: Personal computing devices
- **SMART_APPLIANCES**: Smart home appliances
- **VIDEO_STREAMING**: Video streaming devices

## Usage

### Start the Server

```bash
# With virtual environment
cd model_ml
source ml/bin/activate
python3 model_server.py
```

### With Environment Variables

```bash
MODEL_ML_PORT=5001 FIREWALL_PORT=5000 python3 model_server.py
```

### System Integration

The server starts automatically with:
```bash
sudo ./quick_start.sh
```
when `MODEL_TYPE=ml_flows` in `.env`.

## Testing

Use the test client to verify functionality:

```bash
python test_client.py
```

This script will run several tests:
- Health check
- Dashboard availability
- Server statistics
- Classification of simulated flows
- Direct prediction

## Logs

The server logs events in:
```
logs/model_ml.log
```

### Log Levels
- INFO: Normal operations
- WARNING: Warnings (model not loaded, etc.)
- ERROR: Processing errors

## Dependencies

```
scikit-learn
pandas
numpy
Flask
requests
```

Install with:
```bash
pip install -r requirements.txt
```

## Processing Pipeline

1. **Reception**: The server receives flows from `traffic_capture.py`
2. **Validation**: The 79 required features are validated
3. **Normalization**: The scaler is applied to normalize data
4. **Prediction**: The Random Forest model classifies each flow
5. **Aggregation**: IPs with malicious behavior are identified
6. **Update**: Categories are sent to the firewall manager


## Project Structure

```
model_ml/
├── model_server.py             # Flask server
├── test_client.py              # Test client
├── test_model_loading.py       # Model loading test
├── config.json                 # Configuration
├── README.md                   # This file
├── model.pkl                   # Trained model
├── scaler.pkl                  # Normalizer
├── feature_columns.pkl         # Feature columns
```

## Troubleshooting

### Model does not load
Verify that the PKL files exist:
```bash
ls -la model_ml/*.pkl
```

### Feature error
Ensure the capture system sends the correct 79 features. Check logs:
```bash
tail -f logs/model_ml.log
```

### Connection error with firewall
Verify that the firewall manager is active:
```bash
curl http://localhost:5000/health
```

### Insufficient memory
Adjust `MODEL_ML_LAST_FLOWS` to a lower value in `.env`.

## Optimization

### Buffer Adjustment
Configure `MODEL_ML_LAST_FLOWS` according to available resources:
- More flows = Higher accuracy, more memory
- Fewer flows = Lower accuracy, less memory

### Update Frequency
Adjust `FLOW_SEND_INTERVAL` in `.env` to control the sending frequency to the model.

## Firewall Integration

The server automatically sends the classified categories to the firewall:

```bash
FIREWALL_URL = http://localhost:5000
```

The categories are mapped to threat levels, and the firewall updates the corresponding iptables rules.

## Notes

- The model requires complete flows with all features
- Predictions are automatically sent to the firewall
- The server maintains statistics in memory
- Only compatible with `flows` capture mode
