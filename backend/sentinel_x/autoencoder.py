"""SentinelAI-X unsupervised neural anomaly detection."""

from __future__ import annotations

import time

import numpy as np
import pandas as pd


BENIGN_LABELS = {"BENIGN", "NORMAL", "LEGITIMATE"}


def evaluate_autoencoder(
    X_train,
    X_test,
    y_train,
    y_test,
    epochs=30,
    batch_size=64,
    threshold_percentile=95,
    random_state=42,
):
    """Train on benign training data and detect anomalies by reconstruction error."""

    try:
        import torch
        from torch import nn
        from torch.utils.data import DataLoader, TensorDataset
    except ImportError:
        return {
            "status": "unavailable",
            "reason": "PyTorch is not installed.",
        }

    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
    )

    if not 1 <= epochs <= 100:
        raise ValueError("epochs must be between 1 and 100.")

    if not 1 <= threshold_percentile <= 99.9:
        raise ValueError("threshold_percentile must be between 1 and 99.9.")

    train_labels = pd.Series(y_train).astype(str).str.strip().str.upper()
    benign_mask = train_labels.isin(BENIGN_LABELS).to_numpy()

    if int(benign_mask.sum()) < 100:
        return {
            "status": "skipped",
            "reason": "At least 100 benign training rows are required.",
        }

    torch.manual_seed(random_state)
    np.random.seed(random_state)
    torch.set_num_threads(1)

    # Fit preprocessing only on benign training rows.
    benign_train = X_train.iloc[np.flatnonzero(benign_mask)].copy()

    imputer = SimpleImputer(strategy="median")
    scaler = StandardScaler()

    train_imputed = imputer.fit_transform(benign_train)
    train_scaled = scaler.fit_transform(train_imputed)

    test_imputed = imputer.transform(X_test)
    test_scaled = scaler.transform(test_imputed)

    device = torch.device("cpu")
    input_size = train_scaled.shape[1]
    hidden_size = max(4, min(32, input_size * 2))
    latent_size = max(2, min(16, input_size))

    class Autoencoder(nn.Module):
        def __init__(self):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(input_size, hidden_size),
                nn.ReLU(),
                nn.Linear(hidden_size, latent_size),
                nn.ReLU(),
            )
            self.decoder = nn.Sequential(
                nn.Linear(latent_size, hidden_size),
                nn.ReLU(),
                nn.Linear(hidden_size, input_size),
            )

        def forward(self, values):
            return self.decoder(self.encoder(values))

    model = Autoencoder().to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    loss_function = nn.MSELoss()

    training_tensor = torch.tensor(
        train_scaled, dtype=torch.float32
    )
    loader = DataLoader(
        TensorDataset(training_tensor),
        batch_size=batch_size,
        shuffle=True,
    )

    started = time.perf_counter()
    model.train()

    for _ in range(epochs):
        for (batch,) in loader:
            optimizer.zero_grad()
            reconstructed = model(batch)
            loss = loss_function(reconstructed, batch)
            loss.backward()
            optimizer.step()

    training_seconds = time.perf_counter() - started

    # Determine threshold from benign training reconstruction errors.
    model.eval()
    with torch.no_grad():
        benign_tensor = torch.tensor(
            train_scaled, dtype=torch.float32, device=device
        )
        benign_reconstructed = model(benign_tensor)
        benign_errors = torch.mean(
            (benign_tensor - benign_reconstructed) ** 2, dim=1
        ).cpu().numpy()

        test_tensor = torch.tensor(
            test_scaled, dtype=torch.float32, device=device
        )
        test_reconstructed = model(test_tensor)
        test_errors = torch.mean(
            (test_tensor - test_reconstructed) ** 2, dim=1
        ).cpu().numpy()

    threshold = float(np.percentile(
        benign_errors, threshold_percentile
    ))

    predictions = (test_errors > threshold).astype(int)

    test_labels = (
        pd.Series(y_test).astype(str).str.strip().str.upper()
    )
    actual = (~test_labels.isin(BENIGN_LABELS)).astype(int).to_numpy()

    matrix = confusion_matrix(actual, predictions, labels=[0, 1])
    tn, fp, fn, tp = [int(value) for value in matrix.ravel()]

    inference_seconds = 0.0
    if len(test_scaled):
        # Measure a separate forward pass for inference timing.
        started = time.perf_counter()
        with torch.no_grad():
            model(test_tensor)
        inference_seconds = time.perf_counter() - started

    return {
        "status": "completed",
        "task": "benign_vs_anomaly",
        "model": "PyTorch Autoencoder",
        "labels": {"0": "BENIGN", "1": "ANOMALY"},
        "metrics": {
            "accuracy": round(float(accuracy_score(actual, predictions)), 6),
            "precision": round(float(
                precision_score(actual, predictions, zero_division=0)
            ), 6),
            "recall": round(float(
                recall_score(actual, predictions, zero_division=0)
            ), 6),
            "f1": round(float(
                f1_score(actual, predictions, zero_division=0)
            ), 6),
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
            len(test_scaled) / inference_seconds, 2
        ) if inference_seconds > 0 else None,
        "training_benign_samples": int(len(benign_train)),
        "threshold": round(threshold, 8),
        "threshold_percentile": threshold_percentile,
        "epochs": epochs,
        "preprocessing": (
            "Median imputation and standard scaling fitted on benign "
            "training data only"
        ),
    }
