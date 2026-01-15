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


## Pending

* Attempt improving packet-vector features, instead of directly "first 500 raw bytes"
    * Replace ports with categories (instead of masking)... so "full ports vs masked ports vs 'buckets' of ports" **I have some questions about this...**
    * Add features of "burstiness" and "directional volume features" (especially good for cameras vs sensors)
    * Multi-scale windows (short time windows vs long time windows)
* Add "heading" to window, to make the data type "flow-like" (summary stats per window)
* Change current list of labels (list of device types). Currently it's too small, only 5.
    * Also, hubs / routers are too generic and different... dropping it could help
* Trying flows... since we no longer use packet bytes
* Experiments with packet-windows vs time-windows
* CNNs vs Transformers vs RNNs