import argparse
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

FEATURES = [
    "requests_per_sec", "unique_ips", "avg_inter_request_ms",
    "bytes_per_sec", "error_rate"
]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="traffic_windows.csv")
    parser.add_argument("--output", default="traffic_model.joblib")
    args = parser.parse_args()

    df = pd.read_csv(args.data)
    missing = [c for c in FEATURES + ["label"] if c not in df.columns]
    if missing:
        raise SystemExit(f"Dataset missing columns: {missing}")

    df = df.dropna(subset=["label"])
    X = df[FEATURES].apply(pd.to_numeric, errors="coerce")
    y = df["label"].astype(str).str.strip()
    if y.nunique() < 2:
        raise SystemExit("Need at least two classes (Normal and DDoS).")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    model = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("rf", RandomForestClassifier(
            n_estimators=250, class_weight="balanced_subsample",
            random_state=42, n_jobs=-1, min_samples_leaf=2
        ))
    ])
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    print(classification_report(y_test, pred, zero_division=0))
    print("Confusion matrix:\n", confusion_matrix(y_test, pred, labels=model.classes_))
    joblib.dump({"model": model, "features": FEATURES}, args.output)
    print("Saved model:", args.output)
    print("Do not treat a random row split as proof of deployment performance. "
          "For a report, also test on a separate capture/day/source.")

if __name__ == "__main__":
    main()
