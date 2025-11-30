# ---- CONFIG ----
PYTHON := python
VENV    = .venv
MAC_CSV = dataset/CSVs/macAddresses.csv
PCAP_DIR ?= dataset/pcapIoT
OUTDIR  ?= outputs
CSV_NAME ?= flows_labeled.csv

# Default PCAP (can be overridden: make flows PCAP=...)
PCAP ?= $(PCAP_DIR)/52093085_IoT_2023-07-12.pcap

# ---- ENV / INSTALL ----

.PHONY: venv
venv:
	$(PYTHON) -m venv $(VENV)

.PHONY: install
install:
	$(VENV)/bin/pip install -r requirements.txt

# ---- SINGLE-PCAP WORKFLOW ----

# 1) Generate labeled flows for a single pcap
.PHONY: flows
flows:
	$(VENV)/bin/python -m src.tools.pcap_to_labeled_flows \
	  --pcap $(PCAP) \
	  --mac-csv $(MAC_CSV)

# 2) EDA on raw pcap
.PHONY: pcap-eda
pcap-eda:
	$(VENV)/bin/python -m src.tools.plotting.pcap_eda \
	  --pcap $(PCAP) \
	  --mac-csv $(MAC_CSV) \
	  --outdir $(OUTDIR)

# 3) EDA on flows for that pcap
.PHONY: flows-eda
flows-eda:
	$(VENV)/bin/python -m src.tools.plotting.flows_eda \
	  --csv $(OUTDIR)/$(notdir $(basename $(PCAP)))/flows_labeled.csv \
	  --pcap-name $(PCAP) \
	  --outdir $(OUTDIR)

# Convenience: run full pipeline for a single pcap
.PHONY: pipeline
pipeline: flows pcap-eda flows-eda

# ---- BATCH MODES ----

# Generate labeled flows for all pcaps in a directory
.PHONY: batch-flows
batch-flows:
	$(VENV)/bin/python -m src.tools.pcap_to_labeled_flows \
	  --pcap-dir $(PCAP_DIR) \
	  --mac-csv $(MAC_CSV)

# EDA for all pcaps in a directory
.PHONY: batch-pcap-eda
batch-pcap-eda:
	$(VENV)/bin/python -m src.tools.plotting.pcap_eda \
	  --pcap-dir $(PCAP_DIR) \
	  --mac-csv $(MAC_CSV) \
	  --outdir $(OUTDIR)

# EDA for all flow CSVs in outputs/
.PHONY: batch-flows-eda
batch-flows-eda:
	$(VENV)/bin/python -m src.tools.plotting.flows_eda \
	  --csv-dir $(OUTDIR) \
	  --outdir $(OUTDIR)

# ---- AGGREGATION + TRAINING ----

.PHONY: aggregate
aggregate:
	$(VENV)/bin/python -m src.tools.ml.aggregate_flows \
	  --root $(OUTDIR) \
	  --csv-name $(CSV_NAME) \
	  --skip-unknown \
	  --out-prefix aggregated_flows_known

.PHONY: train
train:
	$(VENV)/bin/python -m src.tools.ml.train_baseline \
	  --dataset $(OUTDIR)/aggregated_flows_known.parquet \
	  --exp-name rf_on_aggregated

# Convenience: full batch preprocessing (flows + pcap EDA + flows EDA + aggregate), no training
.PHONY: batch-prep
batch-prep: batch-flows batch-pcap-eda batch-flows-eda aggregate

# Convenience: full batch pipeline (flows -> agg -> train)
.PHONY: batch-all
batch-all: batch-flows aggregate train
