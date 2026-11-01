import random
from collections import Counter

import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split


LABEL_CANDIDATES = {
    "label", "class", "attack", "attack_type",
    "attack type", "category", "target",
}


def evaluate_dataset(
    file_path,
    label_column=None,
    max_rows_per_class=10_000,
    chunksize=25_000,
):
    """Evaluate a labelled CSV using full-file class-aware sampling."""

    if not 100 <= max_rows_per_class <= 50_000:
        raise ValueError("Sample size per class must be between 100 and 50000.")

    rng = random.Random(42)
    class_counts = Counter()
    reservoirs = {}
    feature_columns = None
    columns = None
    rows_read = 0

    reader = pd.read_csv(
        file_path,
        chunksize=chunksize,
        low_memory=False,
    )

    for chunk in reader:
        chunk.columns = [str(c).strip() for c in chunk.columns]

        if columns is None:
            columns = list(chunk.columns)

            if label_column is None:
                label_column = next(
                    (
                        c for c in columns
                        if c.lower() in LABEL_CANDIDATES
                    ),
                    None,
                )

            if label_column not in columns:
                raise ValueError(
                    "Label column not found. Supply the exact target column name."
                )

            feature_columns = [
                c for c in columns if c != label_column
            ]

        elif list(chunk.columns) != columns:
            raise ValueError("CSV columns changed between chunks.")

        chunk[label_column] = (
            chunk[label_column].fillna("").astype(str).str.strip()
        )

        chunk = chunk[chunk[label_column] != ""]
        if chunk.empty:
            continue

        rows_read += len(chunk)

        labels = chunk[label_column].tolist()

        numeric = chunk[feature_columns].copy()

        for col in feature_columns:
            numeric[col] = pd.to_numeric(numeric[col], errors="coerce")

        numeric = numeric.replace([np.inf, -np.inf], np.nan)

        for position, label in enumerate(labels):
            class_counts[label] += 1
            values = numeric.iloc[position].to_dict()
            record = (values, label)

            seen = class_counts[label]
            bucket = reservoirs.setdefault(label, [])

            if len(bucket) < max_rows_per_class:
                bucket.append(record)
            else:
                replacement = rng.randrange(seen)
                if replacement < max_rows_per_class:
                    bucket[replacement] = record

    if not reservoirs:
        raise ValueError("No valid labelled rows were found.")

    sampled_records = [
        record
        for bucket in reservoirs.values()
        for record in bucket
    ]

    frame = pd.DataFrame(
        [record[0] for record in sampled_records]
    )
    y = pd.Series(
        [record[1] for record in sampled_records],
        name=label_column,
    )

    frame = frame.replace([np.inf, -np.inf], np.nan)

    usable_columns = [
        col for col in frame.columns
        if frame[col].notna().any()
        and frame[col].nunique(dropna=True) > 1
    ]

    if len(usable_columns) < 2:
        raise ValueError(
            "At least two usable numeric features are required."
        )

    X = frame[usable_columns].copy()

    valid = y.notna() & y.astype(str).str.strip().ne("")
    X = X.loc[valid]
    y = y.loc[valid].astype(str)

    sampled_class_counts = y.value_counts()

    if len(sampled_class_counts) < 2:
        raise ValueError("At least two label classes are required.")

    if sampled_class_counts.min() < 2:
        raise ValueError(
            "Each evaluated class needs at least two sampled examples."
        )

    test_count = max(
        len(sampled_class_counts),
        int(round(len(X) * 0.2)),
    )

    if len(X) - test_count < len(sampled_class_counts):
        raise ValueError(
            "Not enough sampled rows for a stratified train/test split."
        )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_count,
        random_state=42,
        stratify=y,
    )

    # Fit imputation only on training data to prevent leakage.
    imputer = SimpleImputer(strategy="median")
    X_train = imputer.fit_transform(X_train)
    X_test = imputer.transform(X_test)

    model = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    labels = sorted(y.unique().tolist())

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test,
        predictions,
        labels=labels,
        average="weighted",
        zero_division=0,
    )

    report = classification_report(
        y_test,
        predictions,
        labels=labels,
        output_dict=True,
        zero_division=0,
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=labels,
    )

    total = int(matrix.sum())
    false_positive_rates = {}

    for index, label in enumerate(labels):
        false_positives = int(
            matrix[:, index].sum() - matrix[index, index]
        )
        true_negatives = (
            total
            - int(matrix[index, :].sum())
            - int(matrix[:, index].sum())
            + int(matrix[index, index])
        )
        denominator = false_positives + true_negatives

        false_positive_rates[label] = (
            round(false_positives / denominator, 4)
            if denominator else 0.0
        )

    macro_fpr = (
        sum(false_positive_rates.values()) / len(false_positive_rates)
        if false_positive_rates else 0.0
    )

    sampled_distribution = {
        str(key): int(value)
        for key, value in y.value_counts().items()
    }

    full_distribution = {
        str(key): int(value)
        for key, value in class_counts.items()
    }

    return {
        "status": "completed",
        "label_column": label_column,
        "features_used": usable_columns,
        "rows_read": int(rows_read),
        "valid_rows": int(len(X)),
        "rows_discarded": int(rows_read - len(X)),
        "training_rows": int(len(X_train)),
        "testing_rows": int(len(X_test)),
        "classes": labels,
        "class_distribution": sampled_distribution,
        "metrics": {
            "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
            "weighted_precision": round(float(precision), 4),
            "weighted_recall": round(float(recall), 4),
            "weighted_f1": round(float(f1), 4),
            "macro_false_positive_rate": round(float(macro_fpr), 4),
        },
        "false_positive_rates_by_class": false_positive_rates,
        "classification_report": report,
        "confusion_matrix": matrix.tolist(),
        "evaluation_details": {
            "sampling_method": "Class-aware reservoir sampling",
            "rows_scanned": int(rows_read),
            "sampled_rows": int(len(X)),
            "maximum_rows_per_class": int(max_rows_per_class),
            "full_dataset_class_distribution": full_distribution,
            "removed_constant_or_empty_features": [
                col for col in feature_columns if col not in usable_columns
            ],
            "imputation": "Training-set median",
            "split": "Stratified 80/20",
            "algorithm": "Random Forest",
        },
        "evaluation_note": (
            "Every CSV row was scanned. Model metrics use a class-aware "
            "sample and a held-out stratified split, not the entire dataset. "
            "Results do not establish real-world detection performance."
        ),
    }
