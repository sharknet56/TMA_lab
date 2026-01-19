# Deep Learning Model - CNN/RNN

Deep Learning model server for network traffic classification through raw packet (PCAP) analysis.

## Description

This model uses deep neural networks (CNN/RNN/LSTM) to classify network traffic by directly analyzing packets. Unlike the ML model that processes aggregated flows, this model analyzes complete PCAP files to detect patterns in raw traffic.

## Differences with model_ml

| Feature        | model_ml                      | model_dl                          |
|----------------|-------------------------------|-----------------------------------|
| **Input**      | Flows (aggregated statistics) | PCAPs (individual packets)        |
| **Model**      | Random Forest (scikit-learn)  | LSTM/CNN (TensorFlow/Keras)       |
| **Format**     | JSON with flow features       | Binary PCAP files                 |
| **Processing** | Flow statistics               | Packet sequences                  |
| **Port**       | 5001                          | 5002                              |

## Features

- Raw packet analysis from PCAP files
- Processing with deep neural networks
- Detection of complex patterns in traffic
- REST API for integration with the capture system
- Web interface for monitoring

## Configuration

### Environment Variables

The server uses the following variables defined in `.env`:

```bash
MODEL_DL_PORT=5002             # DL model server port
FIREWALL_PORT=5000             # Firewall manager port
PCAP_BUFFER_SIZE=1000          # Number of packets in buffer
PCAP_SEND_INTERVAL=30          # PCAP send interval (seconds)
```

## Model Files

The model requires the following files in the `inference/` directory:

- **best_model.keras**: Trained neural network model
- **label_encoder.pkl**: Encoder for decoding predictions
- **model_config.json**: Model configuration (classes, parameters)

## Installation

### Create Virtual Environment

```bash
cd model_dl
python3 -m venv dl_env
source dl_env/bin/activate
pip install -r requirements.txt
```

### Install System Dependencies

```bash
# For PCAP analysis
sudo apt-get install tcpdump libpcap-dev
```

### Verify Installation

```bash
python3 test_model_loading.py
```

## Usage

### Start the Server

```bash
cd model_dl
source dl_env/bin/activate
python3 model_server.py
```

### With Environment Variables

```bash
MODEL_DL_PORT=5002 FIREWALL_PORT=5000 python3 model_server.py
```

### System Integration

The server starts automatically with:
```bash
sudo ./quick_start.sh
```
when `MODEL_TYPE=dl_packets` in `.env`.

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
  "model_type": "deep_learning",
  "model_classes": ["Alexa", "EnvironmentalSensor"],
  "max_len": 500
}
```

### Receive PCAP
```bash
POST /pcap
Content-Type: multipart/form-data

file: traffic.pcap
```

Receives PCAP files from the capture system, processes them with the model, and sends categories to the firewall.

Response:
```json
{
  "status": "processed",
  "predictions_count": 3,
  "devices": ["192.168.50.10", "192.168.50.15"],
  "message": "3 devices classified"
}
```

### Recent Predictions
```bash
GET /predictions
```

Gets the list of recent predictions made by the model.

Response:
```json
{
  "predictions": [
    {
      "ip": "192.168.50.10",
      "category": "Alexa",
      "confidence": 0.95,
      "packets": 15,
      "timestamp": "2026-01-19T10:30:00"
    }
  ],
  "count": 1,
  "timestamp": "2026-01-19T10:30:00"
}
```

### Statistics
```bash
GET /stats
```

Returns model statistics.

Response:
```json
{
  "pcap_received": 45,
  "packets_analyzed": 45000,
  "predictions_made": 45,
  "firewall_updates": 8,
  "last_pcap": "2026-01-19T10:30:00"
}
```

### Detected Devices
```bash
GET /devices
```

Gets information about recently detected devices.

### Web Interface
```bash
GET /
```

Interactive web dashboard with real-time statistics.

### Reset Metrics
```bash
POST /reset
```

Resets all statistics and metrics to start fresh.

Response:
```json
{
  "status": "ok",
  "message": "Metrics reset successfully",
  "timestamp": "2026-01-19T10:30:00"
}
```

## Processing Pipeline

The server:
1. Receives the PCAP file
2. Extracts packets using Scapy
3. Groups packets by source IP (device)
4. Extracts features from each packet (size, protocol, etc.)
5. Creates sequences of up to 500 packets per device
6. Applies padding/truncation to fit the model's input size
7. Predicts the category with the DL model
8. Updates the firewall with the classification

## Supported Categories

- **Alexa / SmartSpeaker**: Voice assistants
- **IndoorCamera / SecurityCamera / MonitorCamera**: Cameras
- **MotionSensor / EnvironmentalSensor / HealthSensor**: Sensors
- **SmartPlug / SmartBulb / SmartLock**: Control devices
- **Hub**: Home automation hubs
- **Printer**: Printers
- **Other**: Other devices

## Configuration

Edit `config.json`:

```json
{
  "processing": {
    "max_packets_per_sequence": 500,
    "min_packets_for_prediction": 10,
    "confidence_threshold": 0.5
  },
  "firewall": {
    "url": "http://192.168.50.1:5000",
    "enabled": true
  }
}
```

## Test Client

```bash
# Basic test
python3 test_client.py

# Test with PCAP file
python3 test_client.py /path/to/capture.pcap
```

## Logs

Server logs are saved in:
```
logs/model_dl.log
```

View logs in real-time:
```bash
tail -f logs/model_dl.log
```

### Log Levels
- INFO: Normal operations
- WARNING: Warnings (model not loaded, corrupt PCAP)
- ERROR: Processing errors

## Dependencies

```
tensorflow
keras
scapy
numpy
pandas
Flask
requests
```

Install with:
```bash
pip install -r requirements.txt
```

## Project Structure

```
model_dl/
├── model_server.py             # Flask server
├── test_client.py              # Test client
├── test_model_loading.py       # Model loading test
├── requirements.txt            # Dependencies
├── config.json                 # Configuration
├── README.md                   # This file
├── dl_env/                     # Virtual environment
├── inference/                  # Models and inference
│   ├── best_model.keras       # Trained model
│   ├── label_encoder.pkl      # Label encoder
│   └── model_config.json      # Model configuration
└── training/                   # Training scripts
```

## Integration with traffic_capture_packets

The `traffic_capture_packets.py` script captures packets and sends them automatically to the model:

```python
PCAP_SEND_URL = 'http://localhost:${MODEL_DL_PORT}/pcap'
```

## Troubleshooting

### Model does not load
Verify that the model files exist:
```bash
ls -lh inference/
# Should show: best_model.keras, label_encoder.pkl, model_config.json
```

### TensorFlow not available
```bash
source dl_env/bin/activate
pip install tensorflow
```

### Memory error
Reduce the sequence size in `model_config.json` or adjust `PCAP_BUFFER_SIZE` in `.env`.

### PCAP not processed
Verify that Scapy is installed:
```bash
pip install scapy
```

### Connection error with firewall
Verify that the firewall manager is active:
```bash
curl http://localhost:5000/health
```

## Performance

- **Speed**: 100-200 ms per PCAP (depends on size)
- **Memory**: 500 MB - 1 GB (model in memory)
- **CPU**: Uses CPU for inference (can use GPU if configured)

## Model Metrics

According to `model_config.json`:
- **Test Accuracy**: 98.95%
- **F1 Macro**: 92.06%

Excellent accuracy for real-time IoT device classification.

## GPU Support

To accelerate processing, GPU can be used:

```bash
# TensorFlow with GPU
pip install tensorflow-gpu

# PyTorch with GPU (if used)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
```

Check GPU availability:
```python
import tensorflow as tf
print(tf.config.list_physical_devices('GPU'))
```

## Optimization

### Buffer Adjustment
Configure `PCAP_BUFFER_SIZE` according to available memory:
- More packets = More context, more memory and time
- Fewer packets = Faster response, less memory

### Send Frequency
Adjust `PCAP_SEND_INTERVAL` in `.env` to control the analysis interval.

### Batch Processing
The model can process multiple devices in parallel to improve performance.

## Advantages vs ML Model

### Advantages
- Greater ability to detect complex patterns
- Full payload analysis (not just statistics)
- Detection of subtle behaviors
- Does not require manual calculation of 79 features

### Disadvantages
- Higher resource consumption (CPU/GPU, memory)
- Slower processing
- Requires more training data
- Greater implementation complexity

## Notes

- The model requires valid PCAP files
- Processing can be resource-intensive
- GPU is recommended for better performance
- Only compatible with `packets` capture mode
- Temporary PCAP files are deleted after processing
- Sequences with fewer than 10 packets may not be classified correctly
