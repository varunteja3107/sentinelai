import hashlib
import json
import sqlite3
import tempfile
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd


LABEL_CANDIDATES = {
    "label", "class", "attack", "attack_type",
    "attack type", "category", "target"
}


def profile_dataset(file_path, chunksize=25_000):
    """Profile every CSV row using bounded-memory chunk processing."""

    if not 1_000 <= chunksize <= 100_000:
        raise ValueError("Chunk size must be between 1000 and 100000.")

    path = Path(file_path)
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError("The CSV file is empty or unavailable.")

    rows = 0
    columns = None
    label_column = None

    missing_counts = Counter()
    infinite_counts = Counter()
    label_counts = Counter()
    categorical_counts = {}
    numeric_stats = {}

    constant_columns = []
    low_variance_columns = []

    duplicate_rows = 0
    hash_db_path = None
    hash_db = None

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".sqlite3", prefix="sentinelai_hashes_", delete=False
        ) as temp:
            hash_db_path = temp.name

        hash_db = sqlite3.connect(hash_db_path)
        hash_db.execute(
            "CREATE TABLE row_hashes (digest BLOB PRIMARY KEY)"
        )

        reader = pd.read_csv(
            path,
            chunksize=chunksize,
            low_memory=False,
        )

        for chunk in reader:
            chunk.columns = [str(c).strip() for c in chunk.columns]

            if columns is None:
                columns = list(chunk.columns)

                label_column = next(
                    (
                        c for c in columns
                        if c.lower() in LABEL_CANDIDATES
                    ),
                    None,
                )

                for col in columns:
                    missing_counts[col] = 0

            elif list(chunk.columns) != columns:
                raise ValueError(
                    "CSV columns changed between chunks. "
                    "Check the file delimiter and header."
                )

            rows += len(chunk)

            missing = chunk.isna().sum()
            for col, count in missing.items():
                missing_counts[str(col)] += int(count)

            # Disk-backed exact duplicate detection.
            for row in chunk.itertuples(index=False, name=None):
                serialized = json.dumps(
                    [None if pd.isna(v) else str(v) for v in row],
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                digest = hashlib.sha256(
                    serialized.encode("utf-8")
                ).digest()

                cursor = hash_db.execute(
                    "INSERT OR IGNORE INTO row_hashes VALUES (?)",
                    (digest,),
                )
                if cursor.rowcount == 0:
                    duplicate_rows += 1

            numeric = chunk.select_dtypes(include="number")

            for col in numeric.columns:
                values = pd.to_numeric(
                    numeric[col], errors="coerce"
                ).to_numpy(dtype=float)

                finite_mask = np.isfinite(values)
                finite = values[finite_mask]

                infinite_counts[col] += int(
                    np.isinf(values).sum()
                )

                stats = numeric_stats.setdefault(
                    col,
                    {
                        "count": 0,
                        "sum": 0.0,
                        "sum_squares": 0.0,
                        "min": None,
                        "max": None,
                        "unique": set(),
                    },
                )

                if len(finite):
                    stats["count"] += int(len(finite))
                    stats["sum"] += float(np.sum(finite))
                    stats["sum_squares"] += float(
                        np.dot(finite, finite)
                    )

                    current_min = float(np.min(finite))
                    current_max = float(np.max(finite))

                    stats["min"] = (
                        current_min if stats["min"] is None
                        else min(stats["min"], current_min)
                    )
                    stats["max"] = (
                        current_max if stats["max"] is None
                        else max(stats["max"], current_max)
                    )

                    stats["unique"].update(
                        float(v) for v in np.unique(finite)
                    )

            if label_column:
                labels = (
                    chunk[label_column]
                    .dropna()
                    .astype(str)
                    .str.strip()
                )
                label_counts.update(labels.value_counts().to_dict())

            for col in chunk.select_dtypes(
                include=["object", "category", "bool"]
            ).columns:
                if col == label_column:
                    continue

                counter = categorical_counts.setdefault(
                    col, Counter()
                )

                # Keep categorical profiling bounded.
                if len(counter) < 20_000:
                    counter.update(
                        chunk[col].dropna().astype(str).value_counts().to_dict()
                    )

            hash_db.commit()

        if rows == 0:
            raise ValueError("The CSV contains no data rows.")

        numeric_profile = {}

        for col, stats in numeric_stats.items():
            count = stats["count"]
            mean = stats["sum"] / count if count else None

            variance = (
                max(
                    0.0,
                    (stats["sum_squares"] / count) - mean ** 2
                )
                if count else 0.0
            )

            std = float(np.sqrt(variance))

            numeric_profile[col] = {
                "valid_values": int(count),
                "missing_values": int(missing_counts[col] + infinite_counts[col]),
                "mean": float(mean) if mean is not None else None,
                "median": None,
                "std": std,
                "min": stats["min"],
                "max": stats["max"],
                "variance": float(variance),
                "unique_values": len(stats["unique"]),
            }

            if len(stats["unique"]) <= 1:
                constant_columns.append(col)
            elif 0 < variance < 0.000001:
                low_variance_columns.append(col)

        label_distribution = dict(
            label_counts.most_common(100)
        )

        imbalance_ratio = None
        imbalance_warning = False

        if len(label_counts) > 1:
            smallest = min(label_counts.values())
            largest = max(label_counts.values())

            if smallest:
                imbalance_ratio = round(largest / smallest, 3)
                imbalance_warning = imbalance_ratio >= 5

        missing_profile = {
            col: {
                "count": int(count),
                "percentage": round(count / rows * 100, 3),
            }
            for col, count in missing_counts.items()
            if count
        }

        categorical_profile = {
            col: {
                "unique_values_observed": len(counter),
                "top_values": dict(counter.most_common(10)),
                "cardinality_note": (
                    "Unique count is capped at 20000 observed values."
                    if len(counter) >= 20_000 else None
                ),
            }
            for col, counter in categorical_counts.items()
        }

        total_missing = sum(missing_counts.values())
        total_infinite = sum(infinite_counts.values())

        leakage_warnings = []

        if label_column:
            for col in columns:
                if col == label_column:
                    continue

                normalized = col.lower().replace(" ", "_")

                if any(
                    term in normalized
                    for term in ("target", "label", "attack_type", "class")
                ):
                    leakage_warnings.append({
                        "column": col,
                        "reason": (
                            "Column name may encode target information. "
                            "Verify before training."
                        ),
                    })

        warnings = []

        if total_missing:
            warnings.append("Missing values detected.")

        if duplicate_rows:
            warnings.append("Duplicate rows detected.")

        if total_infinite:
            warnings.append("Infinite numeric values detected.")

        if constant_columns:
            warnings.append("Constant numeric features detected.")

        if imbalance_warning:
            warnings.append("Potential class imbalance detected.")

        return {
            "status": "completed",
            "rows_analyzed": int(rows),
            "columns_analyzed": len(columns or []),
            "analysis_limit": None,
            "truncated": False,
            "duplicate_rows": int(duplicate_rows),
            "missing_values_total": int(total_missing),
            "missing_by_column": missing_profile,
            "infinite_values_total": int(total_infinite),
            "infinite_by_column": dict(infinite_counts),
            "numeric_features": numeric_profile,
            "categorical_features": categorical_profile,
            "constant_columns": constant_columns,
            "low_variance_columns": low_variance_columns,
            "label_column": label_column,
            "label_distribution": label_distribution,
            "class_imbalance_ratio": imbalance_ratio,
            "class_imbalance_warning": imbalance_warning,
            "potential_leakage_warnings": leakage_warnings,
            "warnings": warnings,
            "note": (
                "All CSV rows were processed in chunks. "
                "Numeric median is not calculated by this streaming profiler. "
                "Categorical cardinality is bounded."
            ),
        }

    finally:
        if hash_db is not None:
            hash_db.close()

        if hash_db_path and Path(hash_db_path).exists():
            Path(hash_db_path).unlink()
