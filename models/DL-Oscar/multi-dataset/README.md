# IoT Multi-Dataset Training - Granular Taxonomy Classification

## Overview

This notebook implements a CNN-based classifier for IoT device identification using multiple datasets (UNSW, IoT-23, Deakin) with a granular 17-category taxonomy. The main focus is training without data leakage by implementing file-stratified splitting to ensure proper model generalization to unseen devices.

## Dataset Requirements

### Directory Structure

The datasets must be located in the following directories:

```
$DATA_ROOT/
├── UNSW-IoTraffic/pcaps/          # UNSW dataset PCAP files
├── IoT-23/Malware-Project/
│   └── BigDataset/IoTScenarios/   # IoT-23 dataset PCAP files
└── Deakin_IoT/
    ├── pcapIoT/                   # Deakin PCAP files
    └── CSVs/macAddresses.csv      # MAC address mapping file
```

**Note**: Update the `DATA_ROOT` variable in the notebook (cell 5) if your datasets are located in a different directory.

## Device Categories

The model classifies devices into 17 specific categories:
- **Voice Assistants**: Alexa, GoogleHome, HomePod, SmartSpeaker
- **Cameras**: SecurityCamera, IndoorCamera, MonitorCamera
- **Sensors**: MotionSensor, EnvironmentalSensor, HealthSensor
- **Control**: SmartBulb, SmartPlug, SmartSwitch
- **Security**: SmartLock
- **Others**: Hub, Printer, Other

## Execution Order (Reduce Data Leakage)

To train the model correctly without data leakage, execute the following cells in order:

### Initial Setup

1. **Cell 2**: Install dependencies from requirements.txt
2. **Cell 3**: Install TensorFlow with CUDA support
3. **Cell 4**: Check GPU availability and configure memory growth

### Configuration and Data Loading Functions

4. **Cell 5**: Load configuration (paths, taxonomy mappings, parameters)
   - Defines `DATA_ROOT`, `MAX_PKTS`, `MAX_LEN`
   - Configures dataset activation via `DATASET_ENABLED`
   - Defines device taxonomy and label mappings

### Data Loading with File Tracking (Critical for No Leakage)

5. **Cell 46**: Define `load_datasets_with_file_tracking()` function
   - This function tracks which file each packet originates from
   - Essential for file-stratified splitting

6. **Cell 47**: Define `file_stratified_split()` function
   - Implements file-level data splitting
   - Prevents packets from the same device appearing in both train and test sets

### Data Preparation Pipeline

7. **Cell 49**: Execute complete data loading and splitting pipeline
   - Loads data with file tracking
   - Performs file-stratified split (60% train, 20% validation, 20% test)
   - Encodes labels
   - Normalizes data to [0, 1] range
   - Reshapes for CNN input
   - Calculates class weights for imbalanced classes

### Model Architecture

8. **Cell 50**: Build simplified CNN model
   - Single convolutional layer architecture
   - Designed to prevent overfitting
   - Output layer adapted to the number of detected classes

9. **Cell 51**: Configure training callbacks
   - EarlyStopping (patience=15)
   - ModelCheckpoint (saves best model)
   - ReduceLROnPlateau (adaptive learning rate)

### Training

10. **Cell 52**: Train the model
    - 50 epochs maximum with early stopping
    - Batch size: 64
    - Uses class weights for imbalanced data
    - Expected initial accuracy: 50-70% (indicates proper learning, not memorization)

### Evaluation and Analysis

11. **Cell 53**: Analyze training progression
    - Epoch-by-epoch performance metrics
    - Train/validation gap analysis

12. **Cell 55**: Plot training history
    - Accuracy and loss curves
    - Overfitting detection

13. **Cell 57**: Evaluate on test set
    - Calculate accuracy, F1-score (macro and weighted)
    - Generate classification report
    - Display confusion matrix

14. **Cell 59**: Analyze per-class performance
    - Precision, recall, F1-score breakdown by device category

15. **Cell 61**: Error analysis
    - Most confused class pairs
    - Misclassification patterns

### Model Export

16. **Cell 65**: Save final model and artifacts
    - Exports trained model
    - Saves label encoder and configuration
    - Generates README with model details

## Expected Results

With the file-stratified approach (no data leakage):

- **Initial accuracy** (epoch 1): 50-70% - indicates proper learning without memorization
- **Final accuracy**: 80-90% - demonstrates genuine pattern learning
- **Generalization**: Model should correctly classify devices from unseen files/physical units

## Configuration Parameters

Key parameters that can be adjusted in cell 5:

- `MAX_PKTS`: Maximum packets per PCAP file (default: 50000)
- `MAX_LEN`: Bytes per packet (default: 500)
- `DEAKIN_MAX_FILES`: Limit for Deakin dataset files (default: 999, no limit)
- `DEAKIN_MAX_FILES_ALEXA`: Limit for Alexa-specific files (default: 999, no limit)

Enable/disable datasets by modifying `DATASET_ENABLED` dictionary in cell 5:
```python
DATASET_ENABLED = {
    "UNSW":   True,
    "IoT23":  True,
    "Deakin": True,
    "ACI":    False
}
```

## Cross-Dataset Validation (Optional)

For advanced validation across different datasets, execute the optional cells in Section 3:

- **Cell 69**: Configure cross-validation strategy
- **Cell 71**: Load data for cross-validation
- **Cell 73**: Preprocess cross-validation data
- **Cell 76**: Configure early stopping parameters
- **Cell 77**: Train with cross-validation setup
- **Cell 79**: Evaluate out-of-domain performance

## Troubleshooting

### High Initial Accuracy (>90% epoch 1)
If you observe very high accuracy in the first epoch, this indicates data leakage. Ensure you executed cell 49 which implements file-stratified splitting, not cell 21 or cell 30 which use the old packet-level splitting method.

### High gap between test accuracy and val_accuracy
Consider overfitting because of the lack of sanitization in training data or lower amount of data used in trainning (for example our case, we can't use more data because it doesnt fit in our hardware).

### Missing Datasets
Verify that all dataset paths in `PATHS` dictionary (cell 5) point to valid directories.

### GPU Memory Issues
Reduce `MAX_PKTS` to decrease memory usage.

### Class Imbalance Warnings
The model automatically handles class imbalance using computed class weights. No manual intervention required.

## Output Artifacts

After training, the following files are generated in `/media/orb/SSD 1TB2/TMA/models/`:

- `best_model_fixed.keras`: Best model checkpoint based on validation accuracy
- `processed_data.pkl`: Preprocessed data for quick reloading (optional, cell 32)

## Additional Information

- **Training time**: 25 minutes in our case. Depends on `MAX_PKTS`, data used and hardware
- **Memory requirements**: Tested with 48GB of RAM. Crashed with a maximum usage of 30/40 GB.
- **GPU requirements**: Tested with an NVIDIA RTX 2080. VRAM does swapping with system RAM in our case, so we can use bigger ammounts of data.
- **Python version**: 3.8+
- **TensorFlow version**: 2.x with CUDA support recommended

## References

- **UNSW Dataset**: [IoT network traffic from UNSW Sydney (Only pcaps)](https://iotanalytics.unsw.edu.au/unsw-iotraffic.html)
- **IoT-23 Dataset**: [IoT malware capture scenarios by Stratosphere Lab (Only benign traffic)](https://www.stratosphereips.org/datasets-iot23)
- **Deakin Dataset**: [ioT traffic from Deakin University (Only pcaps IoT)](https://dro.deakin.edu.au/articles/dataset/Deakin_IoT_Traffic_Dataset/28013234)
