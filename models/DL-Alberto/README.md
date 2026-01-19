# Deep Learning Experiments on UNSW IoT dataset

Most of these experiments have been tested with low accuracy for "device type" classification. There are different versions, each explaining what are the experiments done, how they have been changed, and what are the results. All the execution traces are included on the notebooks, they can be visualized in any editor.

## How to run

Ideally, create a virtual environment for your jupyter environment

```sh
sudo dnf install python3.10
python3.10 -m venv .venv
./.venv/bin/python3.10 -m ipykernel install --user --name venv-py310 --display-name "Python 3.10 (.venv TMA)"
```

Then afterwards, run in any cell:

```py
%pip install -r requirements.txt
```

All that is left is re-running each desired notebook. There are previous result executions already, so running would not be mandatory for checking them out.

## Already experimented

* Raw byte packets:
    * ML, DL classification of device (deviceID... not device type)
    * with masking of IP, ports and checksum
    * baseline of classification by device type, with / without masking
* Time-windows of packets:
    * DL classification of device type
    * masked vs unmasked (slight improvement when masking IP/port/checksums)
* Packet-features:
    * First experiment: with basic packet-vector features
    * (this already stops giving part of the payloads in the experiment, making the experiment faster and receive less "noise" from payload during training)
* Attempt improving packet-vector features, instead of directly "first 500 raw bytes"
    * Replace ports with categories (instead of masking)... so "full ports vs masked ports vs 'buckets' of ports"
    * Add features of "burstiness" and "directional volume features" (especially good for cameras vs sensors)
    * Multi-scale windows (short time windows vs long time windows)
* Add "heading" to window, to make the data type "flow-like" (summary stats per window)
* Experiments with packet-windows vs time-windows


## Pending

* CNNs vs Transformers vs RNNs, deep comparisons
* Change current list of labels (list of device types). Currently it's too small, only 5.
    * Also, hubs / routers are too generic and different... dropping this category could help
