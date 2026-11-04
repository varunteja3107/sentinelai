"""SentinelAI-X research evaluation engine.

Supervised classification and unsupervised anomaly detection are evaluated
separately. Metrics are based on a held-out test split.
"""

from __future__ import annotations

import random
import time
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split


LABEL_CANDIDATES = {
    "label", "class", "attack", "attack_type",
    "attack type", "category", "target",
}

BENIGN_LABELS = {"BENIGN", "NORMAL", "LEGITIMATE"}


def _find_label_column(columns, requested=None):
    if requested:
        if requested not in columns:
            raise ValueError(f"Label column '{requested}' was not found.")
        return requested

    for column in columns:
        if str(column).strip().lower() in LABEL_CANDIDATES:
            return column

    raise ValueError(
        "Could not identify a label column. Supply label_column explicitly."
    )


def _load_sampled_data(
    file_path,
    label_column=None,
    max_rows_per_class=5000,
    chunksize=25000,
    random_state=42,
):
    """Read a CSV in chunks and use class-aware reservoir sampling."""

    path = Path(file_path)
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError("The CSV file is empty or unavailable.")

    if not 100 <= max_rows_per_class <= 20000:
        raise ValueError("max_rows_per_class must be between 100 and 20000.")

    rng = random.Random(random_state)
    reservoirs = {}
    seen_counts = {}
    rows_scanned = 0
    feature_columns = None
    resolved_label = None

    try:
        reader = pd.read_csv(path, chunksize=chunksize, low_memory=False)

        for chunk in reader:
            chunk.columns = [str(c).strip() for c in chunk.columns]

            if resolved_label is None:
                resolved_label = _find_label_column(
                    chunk.columns, label_column
                )
                feature_columns = [
                    c for c in chunk.columns if c != resolved_label
                ]

            if resolved_label not in chunk.columns:
                raise ValueError("CSV columns changed between chunks.")

            rows_scanned += len(chunk)

            labels = chunk[resolved_label].fillna("").astype(str).str.strip()
            numeric = chunk[feature_columns].copy()

            for column in feature_columns:
                numeric[column] = pd.to_numeric(
                    numeric[column], errors="coerce"
                )

            numeric = numeric.replace([np.inf, -np.inf], np.nan)

            usable = numeric.notna().any(axis=1)
            valid = labels.ne("") & usable
            numeric = numeric.loc[valid]
            labels = labels.loc[valid]

            for label, group in numeric.groupby(labels):
                label = str(label)
                bucket = reservoirs.setdefault(label, [])
                seen = seen_counts.get(label, 0)

                values = group.to_numpy(dtype=float)

                for row in values:
                    seen += 1
                    record = row.tolist()

                    if len(bucket) < max_rows_per_class:
                        bucket.append(record)
                    else:
                        replacement = rng.randrange(seen)
                        if replacement < max_rows_per_class:
                            bucket[replacement] = record

                seen_counts[label] = seen

    except pd.errors.EmptyDataError as exc:
        raise ValueError("The CSV file contains no data.") from exc

    if not reservoirs:
        raise ValueError("No usable labelled numeric rows were found.")

    sampled_labels = [
        label
        for label, records in reservoirs.items()
        if len(records) >= 2
    ]

    if len(sampled_labels) < 2:
        raise ValueError(
            "At least two classes with two or more usable rows are required."
        )

    selected_features = []
    selected_labels = []

    for label in sampled_labels:
        for record in reservoirs[label]:
            selected_features.append(record)
            selected_labels.append(label)

    X = pd.DataFrame(selected_features, columns=feature_columns)
    y = pd.Series(selected_labels, name=resolved_label)

    usable_columns = [
        column for column in X.columns
        if X[column].notna().any()
        and X[column].nunique(dropna=True) > 1
    ]

    if len(usable_columns) < 2:
        raise ValueError("At least two usable numeric features are required.")

    X = X[usable_columns].replace([np.inf, -np.inf], np.nan)

    # Remove rows with no usable numeric values.
    valid_rows = X.notna().any(axis=1)
    X = X.loc[valid_rows].reset_index(drop=True)
    y = y.loc[valid_rows].reset_index(drop=True)

    counts = y.value_counts()
    if len(counts) < 2 or counts.min() < 2:
        raise ValueError("Each evaluated class needs at least two rows.")

    return {
        "X": X,
        "y": y,
        "label_column": resolved_label,
        "rows_scanned": rows_scanned,
        "class_counts": {
            str(key): int(value) for key, value in y.value_counts().items()
        },
        "full_class_counts": {
            str(key): int(value) for key, value in seen_counts.items()
        },
    }


def _classification_metrics(y_true, predictions, labels):
    matrix = confusion_matrix(y_true, predictions, labels=labels)

    total = int(matrix.sum())
    per_class_fpr = {}

    for index, label in enumerate(labels):
        false_positives = int(matrix[:, index].sum() - matrix[index, index])
        true_negatives = (
            total
            - int(matrix[index, :].sum())
            - int(matrix[:, index].sum())
            + int(matrix[index, index])
        )
        denominator = false_positives + true_negatives
        per_class_fpr[str(label)] = (
            round(false_positives / denominator, 6)
            if denominator else 0.0
        )

    return {
        "accuracy": round(float(accuracy_score(y_true, predictions)), 6),
        "weighted_precision": round(float(
            precision_score(
                y_true, predictions, average="weighted", zero_division=0
            )
        ), 6),
        "weighted_recall": round(float(
            recall_score(
                y_true, predictions, average="weighted", zero_division=0
            )
        ), 6),
        "weighted_f1": round(float(
            f1_score(
                y_true, predictions, average="weighted", zero_division=0
            )
        ), 6),
        "macro_f1": round(float(
            f1_score(y_true, predictions, average="macro", zero_division=0)
        ), 6),
        "macro_false_positive_rate": round(
            float(np.mean(list(per_class_fpr.values()))), 6
        ),
        "false_positive_rates_by_class": per_class_fpr,
        "confusion_matrix": matrix.tolist(),
        "classification_report": classification_report(
            y_true,
            predictions,
            labels=labels,
            output_dict=True,
            zero_division=0,
        ),
    }


def _run_supervised_models(X_train, X_test, y_train, y_test):
    results = {}
    imputer = SimpleImputer(strategy="median")

    train_values = imputer.fit_transform(X_train)
    test_values = imputer.transform(X_test)
    labels = sorted(y_train.unique().tolist())

    models = [
        (
            "random_forest",
            RandomForestClassifier(
                n_estimators=150,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            ),
        )
    ]

    try:
        from xgboost import XGBClassifier

        models.append((
            "xgboost",
            XGBClassifier(
                n_estimators=120,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.9,
                colsample_bytree=0.9,
                objective="binary:logistic",
                eval_metric="logloss",
                random_state=42,
                n_jobs=2,
            ),
        ))
    except ImportError:
        results["xgboost"] = {
            "status": "unavailable",
            "reason": "Install the optional xgboost package to enable it.",
        }

    for name, model in models:
        started = time.perf_counter()

        if name == "xgboost":
            # XGBoost requires numeric class IDs in this experiment.
            class_to_id = {label: index for index, label in enumerate(labels)}
            id_to_class = {index: label for label, index in class_to_id.items()}

            encoded_train = y_train.map(class_to_id)
            model.fit(train_values, encoded_train)
        else:
            model.fit(train_values, y_train)

        training_seconds = time.perf_counter() - started

        started = time.perf_counter()
        predictions = model.predict(test_values)

        if name == "xgboost":
            predictions = [id_to_class[int(value)] for value in predictions]

        inference_seconds = time.perf_counter() - started

        results[name] = {
            "status": "completed",
            "metrics": _classification_metrics(
                y_test, predictions, labels
            ),
            "training_time_seconds": round(training_seconds, 6),
            "inference_time_seconds": round(inference_seconds, 6),
            "test_samples_per_second": round(
                len(test_values) / inference_seconds, 2
            ) if inference_seconds > 0 else None,
        }

    return results, imputer, train_values, test_values


def _run_isolation_forest(X_train, X_test, y_train, y_test, imputer):
    normalized = y_train.astype(str).str.strip().str.upper()
    benign_mask = normalized.isin(BENIGN_LABELS)

    if int(benign_mask.sum()) < 100:
        return {
            "status": "skipped",
            "reason": (
                "At least 100 benign training rows are required for "
                "the Isolation Forest experiment."
            ),
        }

    train_values = imputer.transform(X_train)
    test_values = imputer.transform(X_test)
    benign_values = train_values[benign_mask.to_numpy()]

    model = IsolationForest(
        n_estimators=150,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )

    started = time.perf_counter()
    model.fit(benign_values)
    training_seconds = time.perf_counter() - started

    started = time.perf_counter()
    raw_predictions = model.predict(test_values)
    inference_seconds = time.perf_counter() - started

    # Isolation Forest returns -1 for anomaly and 1 for inlier.
    predictions = (raw_predictions == -1).astype(int)

    test_labels = y_test.astype(str).str.strip().str.upper()
    true_binary = (~test_labels.isin(BENIGN_LABELS)).astype(int).to_numpy()

    matrix = confusion_matrix(true_binary, predictions, labels=[0, 1])
    tn, fp, fn, tp = [int(value) for value in matrix.ravel()]

    return {
        "status": "completed",
        "task": "benign_vs_anomaly",
        "labels": {"0": "BENIGN", "1": "ANOMALY"},
        "metrics": {
            "accuracy": round(float(accuracy_score(
                true_binary, predictions
            )), 6),
            "precision": round(float(precision_score(
                true_binary, predictions, zero_division=0
            )), 6),
            "recall": round(float(recall_score(
                true_binary, predictions, zero_division=0
            )), 6),
            "f1": round(float(f1_score(
                true_binary, predictions, zero_division=0
            )), 6),
            "false_positive_rate": round(
                fp / (fp + tn), 6
            ) if (fp + tn) else 0.0,
            "confusion_matrix": matrix.tolist(),
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
        },
        "training_time_seconds": round(training_seconds, 6),
        "inference_time_seconds": round(inference_seconds, 6),
        "test_samples_per_second": round(
            len(test_values) / inference_seconds, 2
        ) if inference_seconds > 0 else None,
        "training_benign_samples": int(len(benign_values)),
    }


def evaluate_research_dataset(
    file_path,
    label_column=None,
    max_rows_per_class=5000,
    include_autoencoder=True,
):
    """Run supervised and anomaly-detection experiments on a labelled CSV."""

    dataset = _load_sampled_data(
        file_path,
        label_column=label_column,
        max_rows_per_class=max_rows_per_class,
    )

    X = dataset["X"]
    y = dataset["y"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    supervised, imputer, _, _ = _run_supervised_models(
        X_train, X_test, y_train, y_test
    )

    anomaly = _run_isolation_forest(
        X_train, X_test, y_train, y_test, imputer
    )

    autoencoder_result = {
        "status": "disabled",
        "reason": "Autoencoder evaluation was disabled for this run.",
    }

    if include_autoencoder:
        from .autoencoder import evaluate_autoencoder

        autoencoder_result = evaluate_autoencoder(
            X_train, X_test, y_train, y_test
        )

    return {
        "status": "completed",
        "experiment": "SentinelAI-X multi-model research evaluation",
        "label_column": dataset["label_column"],
        "features_used": list(X.columns),
        "rows_scanned": dataset["rows_scanned"],
        "sampled_rows": int(len(X)),
        "training_rows": int(len(X_train)),
        "testing_rows": int(len(X_test)),
        "classes": sorted(y.unique().tolist()),
        "class_distribution": dataset["class_counts"],
        "full_dataset_class_distribution": dataset["full_class_counts"],
        "supervised_classification": supervised,
        "unsupervised_anomaly_detection": {
            "isolation_forest": anomaly,
            "autoencoder": autoencoder_result,
        },
        "methodology": {
            "sampling": "Class-aware reservoir sampling",
            "split": "Stratified 75/25 train/test split",
            "random_state": 42,
            "imputation": "Median imputation fitted on training data only",
            "supervised_metrics": "Weighted and macro classification metrics",
            "anomaly_task": "Benign versus anomaly, evaluated separately",
        },
        "limitations": [
            "Results describe this dataset and split, not live network performance.",
            "Class-aware sampling changes the sampled class proportions.",
            "Anomaly detection is evaluated as benign versus non-benign.",
            "Model scores must not independently trigger firewall actions.",
            "Independent datasets and chronological validation are still required.",
        ],
    }
