import numpy as np
import pandas as pd
import pytest

from sentinel_x.research_engine import evaluate_research_dataset


def make_dataset(path, benign_count=240, attack_count=160):
    rng = np.random.default_rng(42)

    benign = pd.DataFrame({
        "Flow Duration": rng.normal(1000, 100, benign_count),
        "Total Fwd Packets": rng.normal(10, 2, benign_count),
        "Total Backward Packets": rng.normal(8, 2, benign_count),
        "Flow Bytes/s": rng.normal(500, 50, benign_count),
        "Label": ["BENIGN"] * benign_count,
    })

    attack = pd.DataFrame({
        "Flow Duration": rng.normal(5000, 500, attack_count),
        "Total Fwd Packets": rng.normal(100, 15, attack_count),
        "Total Backward Packets": rng.normal(2, 1, attack_count),
        "Flow Bytes/s": rng.normal(5000, 500, attack_count),
        "Label": ["ATTACK"] * attack_count,
    })

    data = pd.concat([benign, attack], ignore_index=True)
    data = data.sample(frac=1, random_state=42).reset_index(drop=True)
    data.to_csv(path, index=False)


def test_research_engine_returns_separate_experiments(tmp_path):
    csv_path = tmp_path / "research_sample.csv"
    make_dataset(csv_path)

    result = evaluate_research_dataset(csv_path)

    assert result["status"] == "completed"
    assert "random_forest" in result["supervised_classification"]
    assert "isolation_forest" in result["unsupervised_anomaly_detection"]

    rf = result["supervised_classification"]["random_forest"]
    assert rf["status"] == "completed"
    assert 0 <= rf["metrics"]["accuracy"] <= 1
    assert 0 <= rf["metrics"]["weighted_f1"] <= 1
    assert len(rf["metrics"]["confusion_matrix"]) == 2

    isolation = result["unsupervised_anomaly_detection"]["isolation_forest"]
    assert isolation["status"] == "completed"
    assert isolation["task"] == "benign_vs_anomaly"
    assert 0 <= isolation["metrics"]["false_positive_rate"] <= 1


def test_engine_reports_training_and_test_sizes(tmp_path):
    csv_path = tmp_path / "research_sample.csv"
    make_dataset(csv_path)

    result = evaluate_research_dataset(csv_path)

    assert result["training_rows"] + result["testing_rows"] == result["sampled_rows"]
    assert result["training_rows"] > result["testing_rows"]
    assert result["rows_scanned"] == 400


def test_engine_rejects_missing_label_column(tmp_path):
    csv_path = tmp_path / "missing_label.csv"
    pd.DataFrame({
        "feature_a": range(20),
        "feature_b": range(20, 40),
    }).to_csv(csv_path, index=False)

    with pytest.raises(ValueError, match="label column"):
        evaluate_research_dataset(csv_path)


def test_engine_rejects_missing_file(tmp_path):
    with pytest.raises(ValueError, match="unavailable"):
        evaluate_research_dataset(tmp_path / "does_not_exist.csv")


def test_engine_rejects_too_small_class_sample(tmp_path):
    csv_path = tmp_path / "small_class.csv"

    pd.DataFrame({
        "feature_a": [1, 2, 3, 4, 5, 6],
        "feature_b": [10, 20, 30, 40, 50, 60],
        "Label": ["BENIGN", "BENIGN", "BENIGN", "ATTACK", "ATTACK", "ATTACK"],
    }).to_csv(csv_path, index=False)

    with pytest.raises(ValueError, match="max_rows_per_class"):
        evaluate_research_dataset(csv_path, max_rows_per_class=10)


def test_autoencoder_returns_separate_anomaly_metrics(tmp_path):
    from sentinel_x.autoencoder import evaluate_autoencoder
    from sklearn.model_selection import train_test_split

    csv_path = tmp_path / "autoencoder_sample.csv"
    make_dataset(csv_path)

    data = pd.read_csv(csv_path)
    X = data.drop(columns=["Label"])
    y = data["Label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    result = evaluate_autoencoder(
        X_train, X_test, y_train, y_test, epochs=5
    )

    if result["status"] == "completed":
        assert result["task"] == "benign_vs_anomaly"
        assert 0 <= result["metrics"]["accuracy"] <= 1
        assert 0 <= result["metrics"]["false_positive_rate"] <= 1
        assert len(result["metrics"]["confusion_matrix"]) == 2
    else:
        assert result["status"] in {"unavailable", "skipped"}
