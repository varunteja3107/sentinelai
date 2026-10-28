"""Train SentinelAI models on CIC-IDS2017 flow CSV files."""

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

FEATURES = [
    "Destination Port",
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
]

LABEL = "Label"

ALIASES = {
    re.sub(r"\s+", " ", name.strip()).casefold(): name
    for name in FEATURES + [LABEL]
}


def normalize_column(name):
    name = str(name).replace("\ufeff", "").strip()
    return re.sub(r"\s+", " ", name).casefold()


def load_dataset(path, max_rows_per_file):
    path = Path(path).expanduser()

    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = sorted(path.rglob("*.csv"))
    else:
        raise FileNotFoundError(f"Dataset path not found: {path}")

    if not files:
        raise FileNotFoundError("No CSV files found at the supplied path.")

    sampled_files = []

    for csv_path in files:
        print(f"\nReading: {csv_path.name}", flush=True)
        parts = []

        try:
            reader = pd.read_csv(
                csv_path,
                chunksize=50000,
                usecols=lambda col: normalize_column(col) in ALIASES,
                low_memory=False,
            )

            for chunk in reader:
                rename = {
                    col: ALIASES[normalize_column(col)]
                    for col in chunk.columns
                    if normalize_column(col) in ALIASES
                }
                chunk = chunk.rename(columns=rename)

                if LABEL not in chunk.columns:
                    raise ValueError(
                        f"{csv_path.name} has no recognized Label column."
                    )

                missing = [f for f in FEATURES if f not in chunk.columns]
                if missing:
                    raise ValueError(
                        f"{csv_path.name} is missing required features: {missing}"
                    )

                chunk = chunk[FEATURES + [LABEL]].copy()
                chunk[LABEL] = chunk[LABEL].astype("string").str.strip()

                for feature in FEATURES:
                    chunk[feature] = pd.to_numeric(
                        chunk[feature], errors="coerce"
                    )

                chunk[FEATURES] = chunk[FEATURES].replace(
                    [np.inf, -np.inf], np.nan
                )

                # Infinite or missing feature values are handled by the
                # training-only imputer. Rows with no usable features go.
                chunk = chunk.dropna(subset=FEATURES, how="all")
                chunk = chunk.dropna(subset=[LABEL])

                if len(chunk):
                    # Sample each chunk to keep memory use manageable.
                    parts.append(
                        chunk.sample(
                            n=min(len(chunk), 10000),
                            random_state=42,
                        )
                    )

        except pd.errors.EmptyDataError as exc:
            raise ValueError(f"{csv_path.name} is empty.") from exc

        if not parts:
            print("No usable rows found in this file.")
            continue

        file_data = pd.concat(parts, ignore_index=True)

        if len(file_data) > max_rows_per_file:
            file_data = file_data.sample(
                n=max_rows_per_file, random_state=42
            )

        print(f"Retained {len(file_data):,} sampled rows.")
        sampled_files.append(file_data)

    if not sampled_files:
        raise ValueError("No usable labeled traffic rows were found.")

    data = pd.concat(sampled_files, ignore_index=True)
    data[LABEL] = data[LABEL].str.strip()
    data = data.drop_duplicates()

    # Keep classes with enough samples for a train/test split.
    counts = data[LABEL].value_counts()
    rare_labels = counts[counts < 2].index.tolist()

    if rare_labels:
        print(
            f"Excluding labels with fewer than 2 rows: {rare_labels}"
        )
        data = data[~data[LABEL].isin(rare_labels)].copy()

    if data[LABEL].nunique() < 2:
        raise ValueError(
            "At least two traffic classes with sufficient samples are required."
        )

    print(f"\nUsable rows: {len(data):,}")
    print("\nClass distribution:")
    print(data[LABEL].value_counts().to_string())

    return data, [str(f) for f in files]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--data",
        required=True,
        help="Path to a CIC-IDS2017 CSV file or directory of CSV files.",
    )
    parser.add_argument(
        "--max-rows-per-file",
        type=int,
        default=200000,
        help="Maximum sampled rows retained from each CSV.",
    )
    parser.add_argument(
        "--output",
        default="backend/artifacts/sentinelai_ml.joblib",
    )
    args = parser.parse_args()

    if args.max_rows_per_file < 100:
        parser.error("--max-rows-per-file must be at least 100")

    data, files = load_dataset(args.data, args.max_rows_per_file)

    X = data[FEATURES].astype(float)
    y = data[LABEL].astype(str)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    # Fit imputation on training data only to prevent test-set leakage.
    classifier = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("model", RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced_subsample",
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
        )),
    ])

    print("\nTraining Random Forest...", flush=True)
    classifier.fit(X_train, y_train)

    predictions = classifier.predict(X_test)
    accuracy = float(accuracy_score(y_test, predictions))

    report = classification_report(
        y_test,
        predictions,
        output_dict=True,
        zero_division=0,
    )

    print(f"\nHeld-out accuracy: {accuracy:.4f}")
    print("\nClassification report:")
    print(classification_report(
        y_test, predictions, zero_division=0
    ))
    print("Confusion matrix (rows=true, columns=predicted):")
    print(confusion_matrix(
        y_test,
        predictions,
        labels=classifier.classes_,
    ))

    # Train anomaly detection on BENIGN training flows only.
    benign_mask = y_train.str.strip().str.upper().eq("BENIGN")
    benign_train = X_train.loc[benign_mask]

    anomaly_model = None

    if len(benign_train) >= 100:
        imputer = classifier.named_steps["imputer"]
        benign_values = imputer.transform(benign_train)

        # Bound memory and training time for larger datasets.
        if len(benign_values) > 50000:
            rng = np.random.default_rng(42)
            selected = rng.choice(
                len(benign_values), size=50000, replace=False
            )
            benign_values = benign_values[selected]

        anomaly_model = IsolationForest(
            n_estimators=150,
            contamination="auto",
            random_state=42,
            n_jobs=-1,
        )
        print("\nTraining Isolation Forest on BENIGN training flows...")
        anomaly_model.fit(benign_values)
    else:
        print(
            "\nWARNING: Not enough BENIGN training rows for Isolation Forest."
        )

    output = Path(args.output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)

    bundle = {
        "classifier": classifier,
        "anomaly_model": anomaly_model,
        "features": FEATURES,
        "classes": [str(c) for c in classifier.classes_],
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_files": files,
        "sampled_rows": int(len(data)),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "accuracy": accuracy,
        "classification_report": report,
        "training_label_counts": {
            str(k): int(v) for k, v in y_train.value_counts().items()
        },
        "evaluation_label_counts": {
            str(k): int(v) for k, v in y_test.value_counts().items()
        },
    }

    joblib.dump(bundle, output)

    print(f"\nSaved trained model bundle: {output.resolve()}")
    print("Training complete. Review per-class recall and false positives")
    print("before using predictions for live security decisions.")


if __name__ == "__main__":
    main()
