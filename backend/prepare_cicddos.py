"""
Convert CIC-DDoS2019 CICFlowMeter CSV files into 10-second traffic windows.

Expected input: extracted CIC-DDoS2019 CSV files. This dataset contains
flow records, not HTTP request logs. Flow count/sec is therefore an
approximation of request rate for this research prototype.

The CIC-DDoS2019 benchmark is primarily a DDoS benchmark. It does not
provide a reliable, dedicated Flash Crowd class. The live application
uses a conservative traffic-diversity heuristic to flag possible flash
crowds; validate that separately with your own labelled legitimate-spike
traffic before claiming 3-class ML performance.
"""
import argparse
import glob
import os
import numpy as np
import pandas as pd

def find_col(df, candidates):
    lookup = {str(c).strip().lower(): c for c in df.columns}
    for name in candidates:
        if name.lower() in lookup:
            return lookup[name.lower()]
    return None

def normalize_label(value):
    s = str(value).strip().lower()
    if s in {"benign", "normal", "0"} or "benign" in s:
        return "Normal"
    return "DDoS"

def convert_file(path, window_seconds):
    # CICFlowMeter CSVs can be large; process in chunks.
    chunks = []
    for chunk in pd.read_csv(path, low_memory=False, chunksize=250_000):
        chunk.columns = [str(c).strip() for c in chunk.columns]
        time_col = find_col(chunk, ["Timestamp"])
        ip_col = find_col(chunk, ["Source IP", "Src IP"])
        bytes_col = find_col(chunk, ["Flow Bytes/s", "Flow Bytes/s "])
        rst_col = find_col(chunk, ["RST Flag Count"])
        label_col = find_col(chunk, ["Label"])
        if not all([time_col, ip_col, bytes_col, label_col]):
            raise ValueError(
                f"{path}: missing required CICFlowMeter columns. "
                "Need Timestamp, Source IP, Flow Bytes/s, Label."
            )
        chunk["_time"] = pd.to_datetime(chunk[time_col], errors="coerce")
        chunk["_src"] = chunk[ip_col].astype(str)
        chunk["_bps"] = pd.to_numeric(chunk[bytes_col], errors="coerce").replace(
            [np.inf, -np.inf], np.nan
        ).fillna(0).clip(lower=0)
        chunk["_rst"] = (
            pd.to_numeric(chunk[rst_col], errors="coerce").fillna(0).clip(lower=0)
            if rst_col else 0
        )
        chunk["_label"] = chunk[label_col].map(normalize_label)
        chunk = chunk.dropna(subset=["_time"])
        chunks.append(chunk[["_time", "_src", "_bps", "_rst", "_label"]])
    if not chunks:
        return pd.DataFrame()
    df = pd.concat(chunks, ignore_index=True)
    df["_window"] = df["_time"].dt.floor(f"{window_seconds}s")
    grouped = df.groupby("_window", sort=True)
    out = grouped.agg(
        flow_count=("_src", "size"),
        unique_ips=("_src", "nunique"),
        bytes_per_sec=("_bps", "sum"),
        reset_count=("_rst", "sum"),
        label=("_label", lambda x: "DDoS" if (x == "DDoS").mean() >= 0.5 else "Normal")
    ).reset_index()
    out["requests_per_sec"] = out["flow_count"] / float(window_seconds)
    out["avg_inter_request_ms"] = np.where(
        out["requests_per_sec"] > 0, 1000.0 / out["requests_per_sec"], 0
    )
    out["error_rate"] = (out["reset_count"] / out["flow_count"].clip(lower=1)).clip(0, 1)
    return out[[
        "requests_per_sec", "unique_ips", "avg_inter_request_ms",
        "bytes_per_sec", "error_rate", "label"
    ]]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Folder containing CIC-DDoS2019 CSV files")
    parser.add_argument("--output", default="traffic_windows.csv")
    parser.add_argument("--window", type=int, default=10)
    args = parser.parse_args()
    paths = glob.glob(os.path.join(args.input, "**", "*.csv"), recursive=True)
    if not paths:
        raise SystemExit("No CSV files found under the input folder.")
    results = []
    for path in paths:
        print("Processing:", path)
        converted = convert_file(path, args.window)
        if not converted.empty:
            results.append(converted)
    if not results:
        raise SystemExit("No usable rows found. Check the CICFlowMeter CSV column names.")
    data = pd.concat(results, ignore_index=True)
    counts = data["label"].value_counts()
    print("Window labels:", counts.to_dict())
    if "Normal" not in counts or "DDoS" not in counts:
        raise SystemExit(
            "Training needs both Normal/Benign and DDoS windows. "
            "The supplied files appear to contain only one class. Add benign "
            "traffic CSVs or another labelled benign source."
        )
    data.to_csv(args.output, index=False)
    print(f"Saved {len(data)} windows to {args.output}")
    print("Note: Flash Crowd is not a native CIC-DDoS2019 label.")

if __name__ == "__main__":
    main()
