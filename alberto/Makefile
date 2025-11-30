# ---- CONFIG ----
PYTHON  := $(VENV)/bin/python
VENV    := .venv

MAC_CSV := dataset/CSVs/macAddresses.csv
PCAP_DIR ?= dataset/pcapIoT
OUTDIR  ?= outputs
CSV_NAME ?= flows_labeled.csv

# Default PCAP (can be overridden: make pipeline PCAP=...)
PCAP ?= $(PCAP_DIR)/52093085_IoT_2023-07-12.pcap

# Aggregated dataset name (prefix without extension)
AGG_PREFIX ?= aggregated_flows_known
AGG_DATASET ?= $(OUTDIR)/$(AGG_PREFIX).parquet

# All supported ML models (see train_baseline._make_model)
MODELS := rf et gb hgb mlp logreg

# ---- ENV / INSTALL ----

.PHONY: venv
venv:
	$(PYTHON) -m venv $(VENV)

.PHONY: install
install:
	$(VENV)/bin/pip install -r requirements.txt

# ---- SINGLE-PCAP WORKFLOW ----
# This is useful for quick dev/debug on one capture.

# 1) Generate labeled flows for a single PCAP
.PHONY: flows
flows:
	$(PYTHON) -m src.iotnet.cli pcap labeled-flows \
	  $(PCAP) \
	  --mac-csv $(MAC_CSV)

# 2) EDA on raw PCAP
.PHONY: pcap-eda
pcap-eda:
	$(PYTHON) -m src.iotnet.cli pcap-eda run \
	  $(PCAP) \
	  --mac-csv $(MAC_CSV) \
	  --outdir $(OUTDIR)

# 3) EDA on flows for that PCAP
.PHONY: flows-eda
flows-eda:
	$(PYTHON) -m src.iotnet.cli flows eda \
	  $(OUTDIR)/$(notdir $(basename $(PCAP)))/flows_labeled.csv \
	  --outdir $(OUTDIR)/eda/flows

# Convenience: run full pipeline for a single PCAP (flows + EDA on PCAP + EDA on flows)
.PHONY: pipeline
pipeline: flows pcap-eda flows-eda

# Tiny ML experiment on the aggregated dataset (subsampled)
.PHONY: train-small
train-small:
	$(PYTHON) -m src.iotnet.cli ml train \
	  $(AGG_DATASET) \
	  --model rf \
	  --max-rows 50000 \
	  --exp-name rf_small_experiment \
	  --outdir $(OUTDIR)

# ---- BATCH MODES ----
# Batch flows/EDA/aggregation over all PCAPs in $(PCAP_DIR)

# Generate labeled flows for all PCAPs in a directory
.PHONY: batch-flows
batch-flows:
	$(PYTHON) -m src.iotnet.cli pcap labeled-flows-batch \
	  $(PCAP_DIR) \
	  --mac-csv $(MAC_CSV)

# EDA for all PCAPs in a directory
.PHONY: batch-pcap-eda
batch-pcap-eda:
	$(PYTHON) -m src.iotnet.cli pcap-eda batch \
	  $(PCAP_DIR) \
	  --mac-csv $(MAC_CSV) \
	  --outdir $(OUTDIR)

# EDA for all flow CSVs in $(OUTDIR)
# (loop over each subdir containing flows_labeled.csv)
.PHONY: batch-flows-eda
batch-flows-eda:
	@for d in $(OUTDIR)/*; do \
	  if [ -d "$$d" ] && [ -f "$$d/$(CSV_NAME)" ]; then \
	    echo "Running flows EDA for $$d/$(CSV_NAME)"; \
	    $(PYTHON) -m src.iotnet.cli flows eda \
	      "$$d/$(CSV_NAME)" \
	      --outdir $(OUTDIR)/eda/flows; \
	  fi; \
	done

# ---- AGGREGATION + TRAINING ----

# Aggregate all labeled flow CSVs under $(OUTDIR)/<pcap_name>/ into one dataset
.PHONY: aggregate
aggregate:
	$(PYTHON) -m src.iotnet.cli flows aggregate \
	  $(OUTDIR) \
	  --csv-name $(CSV_NAME) \
	  --skip-unknown \
	  --out-prefix $(AGG_PREFIX) \
	  --outdir $(OUTDIR)

# Train a single model (RandomForest by default) on the aggregated dataset
.PHONY: train
train:
	$(PYTHON) -m src.iotnet.cli ml train \
	  $(AGG_DATASET) \
	  --model rf \
	  --exp-name rf_on_aggregated \
	  --outdir $(OUTDIR)

# Train all supported models (rf, et, gb, hgb, mlp, logreg)
.PHONY: train-all
train-all:
	@for M in $(MODELS); do \
	  echo "=== Training model: $$M ==="; \
	  $(PYTHON) -m src.iotnet.cli ml train \
	    $(AGG_DATASET) \
	    --model $$M \
	    --exp-name "$${M}_on_aggregated" \
	    --outdir $(OUTDIR); \
	  echo ""; \
	done

# Convenience: full batch preprocessing (flows + PCAP EDA + flows EDA + aggregate), no training
.PHONY: batch-prep
batch-prep: batch-flows batch-pcap-eda batch-flows-eda aggregate

# Convenience: full batch pipeline (flows -> EDA -> aggregate -> single RF train)
.PHONY: batch-all
batch-all: batch-prep train
