# IoT Device Classification & Analysis

Quick start guide for IoT device analysis and classification using Machine Learning (Random Forest).

## Folder Structure
The `MLcode.ipynb` notebook must be in the same directory as a folder named `archive` containing the datasets. Due to GitHub limits, the data is not included in the repository.

The structure should be:
- `MLcode.ipynb`
- `archive/`
  - `CIC_IoT_Part_1.csv`
  - `CIC_IoT_Part_2.csv`
  - `Lab_1.csv`
  - `Lab_2.csv`
  - `UNSW_IoT_Traces.csv`

**Data Source:** [Kaggle - IoT and Non-IoT Device Classification](https://www.kaggle.com/datasets/mizanunswcyber/iot-and-non-iot-device-classification-dataset)

## Installation and Execution
It is recommended to use a virtual environment to isolate dependencies.

```bash
# 1. Create virtual environment
python3 -m venv venv

# 2. Activate environment
# On Windows:
.\venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# 3. Install dependencies
pip install pandas numpy matplotlib seaborn scikit-learn imbalanced-learn category-encoders tqdm ipywidgets
```

Open the `MLcode.ipynb` notebook in VS Code or Jupyter and run the cells in order.

### Training Parameters
The main model used is a **Random Forest Classification**.

Optimized parameters used in the final script:
```text
n_estimators = 50
max_depth = 15
min_samples_split = 10
class_weight = 'balanced'
n_jobs = -1 (Use all available CPU cores)
```

### Execution

The project focuses on a single notebook that orchestrates the entire process:

- **MLcode.ipynb** — Performs data loading, cleaning, grouping into macro-categories, training, and evaluation.
  1. **Loading and Cleaning**: Imports the 5 CSVs and removes irrelevant columns (IPs, Timestamps, etc.).
  2. **Feature Engineering**: Maps devices to macro-categories (VIDEO_STREAMING, HOME_AUTOMATION, etc.).
  3. **Optimization**: Runs a Randomized Search with "Leave-One-Dataset-Out" cross-validation.
  4. **Evaluation**: Performs a 5-Fold Cross-Validation dynamically filtering unknown classes.
  5. **Export**: Generates the final model `iot_device_classifier_rf.pkl`.

To reproduce the results, run all cells sequentially.