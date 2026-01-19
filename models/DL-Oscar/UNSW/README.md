# IoT Traffic Analysis

Quick start guide to run IoT traffic analysis (Flows vs Packets).

## Folder Structure
The notebook `IoT_Traffic_Analysis.ipynb` must be in the same directory as the UNSW dataset data folders:
- `flows/` (CSV files)
- `pcaps/` (PCAP files)

## Installation and Execution
It is recommended to use a virtual environment to isolate dependencies. **Jupyter creates it in a guided way**, but if not, run:

```bash
# 1. Create virtual environment
python3 -m venv venv

# 2. Activate environment
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

Open the notebook in VS Code or Jupyter and run the cells in order.

### GPU Troubleshooting
There is a cell to check GPU usage. If you have an NVIDIA GPU and `nvidia-smi` works but TensorFlow uses CPU or is missing libraries (e.g. `libcudart`, `libcudnn`):

1. Install the TensorFlow version that includes necessary CUDA libraries:
   ```bash
   pip install "tensorflow[and-cuda]"
   ```
2. Restart the notebook kernel and re-run the check cell.

See the configuration result in `image.png`.

### Hardware and Training Parameters
Hardware: NVIDIA RTX 2080 && 48GB RAM DDR4 3200MHz

Parameters used:
```text
DATA_FRAC = 0.1
CANTIDAD_META = 1000000
MAX_LEN = 500
MAX_PKTS_PER_FILE = 10000
```

### Execution with Scripts

There are three main scripts in the directory:

- main_comparacion.py — Orchestrates the Flows vs Packets comparison.  
   Typical usage:
   ```bash
   python3 main_comparacion.py
   ```

- script_flows.py — Processes CSVs in the `flows/` folder and generates features/results.
   ```bash
   python3 script_flows.py
   ```

- script_pcaps.py — Processes PCAP files in `pcaps/`, extracts packets and features.
   ```bash
   python3 script_pcaps.py
   ```

Run from the project root with the virtual environment activated (see installation section).