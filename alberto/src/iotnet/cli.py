# src/iotnet/cli.py

import pathlib
from typing import Optional

import typer

# tools
from src.iotnet.tools import pcap_to_labeled_flows, pcap_to_flows
from src.iotnet.tools.ml import aggregate_flows, train_baseline
from src.iotnet.tools.plotting import flows_eda, pcap_eda

app = typer.Typer(help="IoT network traffic toolkit (pcap → flows → ML).")

# -------------------------------------------------------------------
# PCAP → FLOWS
# -------------------------------------------------------------------

pcap_app = typer.Typer(help="Convert PCAP files into labeled flow files.")
app.add_typer(pcap_app, name="pcap")

@pcap_app.command("raw-flows")
def cmd_pcap_raw_flows(
    pcap_path: pathlib.Path = typer.Argument(..., exists=True),
    timeout: float = typer.Option(60.0, "--timeout", "-t", help="Flow timeout (seconds)"),
    out_csv: pathlib.Path | None = typer.Option(None, "--out", "-o", help="Output CSV (single-file mode only)"),
):
    """
    Convert a single PCAP into raw flows (no labels).
    """
    pcap_to_flows.process_single_pcap(pcap_path=pcap_path, timeout=timeout, out_csv=out_csv)


@pcap_app.command("raw-flows-batch")
def cmd_pcap_raw_flows_batch(
    pcap_dir: pathlib.Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    timeout: float = typer.Option(60.0, "--timeout", "-t", help="Flow timeout (seconds)"),
):
    """
    Convert all PCAPs in a directory into raw flows.
    """
    pcap_to_flows.process_pcap_directory(pcap_dir=pcap_dir, timeout=timeout)


@pcap_app.command("labeled-flows")
def cmd_pcap_labeled_flows(
    pcap_path: pathlib.Path = typer.Argument(..., exists=True),
    mac_csv: pathlib.Path = typer.Option(..., "--mac-csv", help="Path to macAddresses.csv"),
    out_csv: pathlib.Path | None = typer.Option(None, "--out", "-o", help="Output CSV (single-file mode only)"),
):
    """
    Convert a single PCAP into labeled flows using MAC→device_type mapping.
    """
    pcap_to_labeled_flows.process_single_pcap(pcap_path=pcap_path, mac_csv=str(mac_csv), out_csv=out_csv)


@pcap_app.command("labeled-flows-batch")
def cmd_pcap_labeled_flows_batch(
    pcap_dir: pathlib.Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    mac_csv: pathlib.Path = typer.Option(..., "--mac-csv", help="Path to macAddresses.csv"),
):
    """
    Convert all PCAPs in a directory into labeled flows.
    """
    pcap_to_labeled_flows.process_pcap_directory(pcap_dir=pcap_dir, mac_csv=str(mac_csv))


# -------------------------------------------------------------------
# FLOW AGGREGATION + EDA (FLOWS)
# -------------------------------------------------------------------

flows_app = typer.Typer(help="Work with flow files (aggregation, EDA).")
app.add_typer(flows_app, name="flows")

@flows_app.command("aggregate")
def cmd_flows_aggregate(
    root: pathlib.Path = typer.Argument(
        pathlib.Path("outputs"),
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Root directory containing per-PCAP subdirectories with flow CSVs.",
    ),
    csv_name: str = typer.Option(
        "flows_labeled.csv",
        "--csv-name",
        help="Flow CSV filename to look for in each subdirectory.",
    ),
    out_prefix: str = typer.Option(
        "aggregated_flows",
        "--out-prefix",
        help="Prefix for aggregated dataset files.",
    ),
    outdir: pathlib.Path = typer.Option(
        pathlib.Path("outputs"),
        "--outdir",
        help="Directory to write aggregated outputs to.",
    ),
    skip_unknown: bool = typer.Option(
        False,
        "--skip-unknown",
        help="Drop rows where device_type == 'unknown'.",
    ),
):
    """
    Aggregate per-PCAP flow CSVs into a single ML-ready dataset.
    """
    aggregate_flows.aggregate_flows(
        root=root,
        csv_name=csv_name,
        out_prefix=out_prefix,
        skip_unknown=skip_unknown,
        outdir=outdir,
    )

@flows_app.command("eda")
def flows_do_eda(
    dataset: pathlib.Path = typer.Argument(..., exists=True, help="Flow CSV (per-PCAP) or aggregated flows CSV."),
    output_dir: pathlib.Path = typer.Option(
        "outputs/eda/flows",
        "--outdir",
        "-o",
        help="Directory to store EDA plots.",
    ),
):
    """
    Run EDA on a flow CSV (per-PCAP or aggregated).
    """
    flows_eda.run_eda(dataset_path=dataset, output_dir=output_dir)

# -------------------------------------------------------------------
# PCAP-LEVEL EDA
# -------------------------------------------------------------------

pcap_eda_app = typer.Typer(help="Exploratory plots directly from PCAPs.")
app.add_typer(pcap_eda_app, name="pcap-eda")


@pcap_eda_app.command("run")
def cmd_pcap_eda_run(
    pcap_path: pathlib.Path = typer.Argument(..., exists=True, help="Input PCAP file."),
    mac_csv: pathlib.Path = typer.Option(
        ...,
        "--mac-csv",
        help="Path to macAddresses.csv used to map MAC → device_type.",
    ),
    output_dir: pathlib.Path = typer.Option(
        "outputs",
        "--outdir",
        "-o",
        help="Base output directory (PCAP-specific subfolder will be created).",
    ),
):
    """
    Run packet-level EDA on a single PCAP.
    """
    output_dir.mkdir(parents=True, exist_okay=True)
    pcap_eda.run_eda(
        pcap_path=pcap_path,
        mac_csv=str(mac_csv) if mac_csv else None,
        outdir=str(output_dir),
    )

@pcap_eda_app.command("batch")
def cmd_pcap_eda_batch(
    pcap_dir: pathlib.Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True, help="Directory containing PCAP files."),
    mac_csv: pathlib.Path = typer.Option(
        ...,
        "--mac-csv",
        help="Path to macAddresses.csv used to map MAC → device_type.",
    ),
    output_dir: pathlib.Path = typer.Option(
        "outputs",
        "--outdir",
        "-o",
        help="Base output directory (one subfolder per PCAP).",
    ),
):
    """
    Run packet-level EDA on all PCAPs in a directory.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    pcap_eda.process_pcap_directory(
        pcap_dir=pcap_dir,
        mac_csv=str(mac_csv) if mac_csv else None,
        outdir=str(output_dir),
    )


# -------------------------------------------------------------------
# ML TRAINING
# -------------------------------------------------------------------

ml_app = typer.Typer(help="Train and evaluate ML models for device classification.")
app.add_typer(ml_app, name="ml")

@ml_app.command("train")
def ml_train(
    dataset: pathlib.Path = typer.Argument(
        ...,
        exists=True,
        help="Aggregated flow dataset (CSV or Parquet).",
    ),
    model: str = typer.Option(
        "rf",
        "--model",
        "-m",
        help="Which model to use. Currently supported: 'rf', 'et', 'gb', 'hgb', 'mlp', 'logreg'. (default: 'rf')",
    ),
    test_size: float = typer.Option(
        0.3,
        "--test-size",
        help="Fraction of data to use as validation set (e.g. 0.3).",
    ),
    random_state: int = typer.Option(
        42,
        "--seed",
        help="Random seed.",
    ),
    max_rows: int | None = typer.Option(
        None,
        "--max-rows",
        help="Optional maximum number of rows to use (subsample if larger).",
    ),
    exp_name: str = typer.Option(
        "baseline_experiment",
        "--exp-name",
        "-e",
        help="Name of the training experiment.",
    ),
    output_dir: pathlib.Path = typer.Option(
        pathlib.Path("outputs"),
        "--outdir",
        "-o",
        help="Base output directory for results.",
    ),
):
    """
    Train a baseline classifier on the given aggregated dataset.
    """
    train_baseline.train_from_dataset(
        dataset_path=dataset,
        exp_name=exp_name,
        outdir=output_dir,
        model_name=model,
        test_size=test_size,
        random_state=random_state,
        max_rows=max_rows,
    )

# -------------------------------------------------------------------
# ENTRYPOINT
# -------------------------------------------------------------------

def main():
    app()


if __name__ == "__main__":
    main()
