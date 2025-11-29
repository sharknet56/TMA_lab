## Environment

```sh
python -m venv .venv #if venv not created already
source .venv/bin/activate

#install requirements.txt
pip install -r requirements.txt

# save your installed additional dependencies
pip freeze > requirements.txt

```

## Analysis

How to Generate flows from a pcap file:

```sh
python -m src.tools.pcap_to_labeled_flows \
    --pcap dataset/pcapIoT/52093085_IoT_2023-07-12.pcap \
    --mac-csv dataset/CSVs/macAddresses.csv

# Saved 15380 labeled flows to outputs/52093085_IoT_2023-07-12/flows_labeled.csv
```

How to plot data for a pcap file:

```sh
python -m src.tools.plotting.pcap_eda \
  --pcap dataset/pcapIoT/52093085_IoT_2023-07-12.pcap \
  --mac-csv dataset/CSVs/macAddresses.csv \
  --outdir outputs

# Saved: outputs/52093085_IoT_2023-07-12/pcap_summary.txt
# Saved: outputs/52093085_IoT_2023-07-12/pcap_pkt_len_hist.png
# Saved: outputs/52093085_IoT_2023-07-12/pcap_pps_timeseries.png
```

How to plot data for a flow file (previously generated):

```sh
python -m src.tools.plotting.flows_eda \
  --csv outputs/52093085_IoT_2023-07-12/flows_labeled.csv \
  --pcap-name dataset/pcapIoT/52093085_IoT_2023-07-12.pcap \
  --outdir outputs

# Saved summary: outputs/52093085_IoT_2023-07-12/flows_summary.txt
# Saved: outputs/52093085_IoT_2023-07-12/flows_duration_hist.png
# Saved: outputs/52093085_IoT_2023-07-12/flows_total_bytes_hist.png
# Saved: outputs/52093085_IoT_2023-07-12/flows_duration_vs_bytes.png
# Saved: outputs/52093085_IoT_2023-07-12/flows_duration_vs_bytes_by_device.png
```

---

Generate flows from pcap directory:

```sh
python -m src.tools.pcap_to_labeled_flows \
  --pcap-dir kk-prueba-pcap_to_flows_dir \
  --mac-csv dataset/CSVs/macAddresses.csv

#Found 12 pcap files in kk-prueba-pcap_to_flows_dir, processing in batch...
#[52093124_IoT_2023-07-11] Saved 14525 labeled flows to outputs/52093124_IoT_2023-07-11/flows_labeled.csv (elapsed: 372.11s)
#[52093139_IoT_2023-07-13] Saved 15094 labeled flows to outputs/52093139_IoT_2023-07-13/flows_labeled.csv (elapsed: 491.98s)
#[52093154_IoT_2023-05-29] Saved 28938 labeled flows to outputs/52093154_IoT_2023-05-29/flows_labeled.csv (elapsed: 685.51s)
#[52093157_IoT_2023-07-18] Saved 22875 labeled flows to outputs/52093157_IoT_2023-07-18/flows_labeled.csv (elapsed: 638.54s)
#[52093169_IoT_2023-05-22] Saved 17530 labeled flows to outputs/52093169_IoT_2023-05-22/flows_labeled.csv (elapsed: 1072.61s)
#[IoT_2023-07-25] Saved 27074 labeled flows to outputs/IoT_2023-07-25/flows_labeled.csv (elapsed: 918.03s)
#[IoT_2024-05-24] Saved 37634 labeled flows to outputs/IoT_2024-05-24/flows_labeled.csv (elapsed: 930.03s)
#[IoT_2024-05-25] Saved 36326 labeled flows to outputs/IoT_2024-05-25/flows_labeled.csv (elapsed: 866.16s)
#[IoT_2024-05-26] Saved 36193 labeled flows to outputs/IoT_2024-05-26/flows_labeled.csv (elapsed: 897.32s)
#[IoT_2024-05-27] Saved 36204 labeled flows to outputs/IoT_2024-05-27/flows_labeled.csv (elapsed: 881.75s)
#[IoT_2024-05-28] Saved 36583 labeled flows to outputs/IoT_2024-05-28/flows_labeled.csv (elapsed: 916.64s)
#[IoT_2024-05-29] Saved 9772 labeled flows to outputs/IoT_2024-05-29/flows_labeled.csv (elapsed: 235.54s)
#Batch processing completed in 8906.27s
```

Aggregate flows into ML-ready file:

```sh
python -m src.tools.ml.aggregate_flows \
  --root outputs \
  --csv-name flows_labeled.csv \
  --out-prefix aggregated_flows_all

# Or skip unknown device types
python -m src.tools.ml.aggregate_flows \
  --root outputs \
  --csv-name flows_labeled.csv \
  --skip-unknown \
  --out-prefix aggregated_flows_known

```

Use aggregated flows for training:

```sh
python -m src.tools.ml.train_baseline \
  --dataset outputs/aggregated_flows_all.parquet \
  --exp-name rf_on_aggregated

#Old method (multiple CSVs)
python -m src.tools.ml.train_baseline \
  --csv outputs/foo/flows_labeled.csv \
  --csv outputs/bar/flows_labeled.csv \
  --exp-name rf_multi

#Train on all pcap outputs automatically
python -m src.tools.ml.train_baseline \
  --csv-dir outputs \
  --csv-name flows_labeled.csv \
  --exp-name rf_from_outputs


```

-------------
