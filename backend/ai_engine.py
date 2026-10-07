import numpy as np

from sklearn.ensemble import IsolationForest, RandomForestClassifier


class ThreatDetectionAI:

    def __init__(self):

        # -----------------------------
        # Isolation Forest
        # -----------------------------
        self.anomaly_model = IsolationForest(
            n_estimators=100,
            contamination=0.15,
            random_state=42
        )

        # -----------------------------
        # Training data
        #
        # Features:
        # packets
        # bytes
        # port
        # failed_attempts
        # -----------------------------
        training_data = np.array([
            [20, 5000, 10, 1],
            [30, 8000, 15, 2],
            [25, 6000, 12, 1],
            [40, 10000, 20, 2],
            [35, 9000, 18, 3],
            [50, 12000, 25, 2],
            [45, 11000, 22, 3],
            [30, 7000, 15, 1],
            [55, 13000, 28, 4],
            [40, 9000, 20, 2],

            # Port Scan
            [900, 80000, 3389, 18],
            [850, 75000, 22, 15],

            # DoS
            [2500, 500000, 80, 5],
            [3000, 700000, 443, 4],

            # Brute Force
            [400, 60000, 22, 80],
            [350, 50000, 3389, 65],

            # DDoS-like
            [5000, 900000, 80, 20],
            [6000, 1000000, 443, 25],
        ])

        self.anomaly_model.fit(training_data)

        # -----------------------------
        # Random Forest classifier
        # -----------------------------
        labels = np.array([
            "BENIGN",
            "BENIGN",
            "BENIGN",
            "BENIGN",
            "BENIGN",
            "BENIGN",
            "BENIGN",
            "BENIGN",
            "BENIGN",
            "BENIGN",

            "PORT_SCAN",
            "PORT_SCAN",

            "DOS",
            "DOS",

            "BRUTE_FORCE",
            "BRUTE_FORCE",

            "DDOS",
            "DDOS",
        ])

        self.classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            class_weight="balanced"
        )

        self.classifier.fit(training_data, labels)

    # ---------------------------------
    # Feature preparation
    # ---------------------------------

    def _features(
        self,
        packets,
        bytes_transferred,
        port,
        failed_attempts
    ):

        return np.array([[
            packets,
            bytes_transferred,
            port,
            failed_attempts
        ]])

    # ---------------------------------
    # Main AI analysis
    # ---------------------------------

    def analyze_detailed(
        self,
        packets,
        bytes_transferred,
        port,
        failed_attempts
    ):

        features = self._features(
            packets,
            bytes_transferred,
            port,
            failed_attempts
        )

        # Isolation Forest
        anomaly_prediction = self.anomaly_model.predict(features)

        raw_score = self.anomaly_model.decision_function(
            features
        )[0]

        if anomaly_prediction[0] == -1:

            anomaly_score = min(
                100,
                max(
                    70,
                    int((0.5 - raw_score) * 100)
                )
            )

        else:

            anomaly_score = min(
                45,
                max(
                    5,
                    int((0.5 - raw_score) * 50)
                )
            )

        # Random Forest classification
        probabilities = self.classifier.predict_proba(features)[0]

        class_index = int(np.argmax(probabilities))

        threat_type = self.classifier.classes_[class_index]

        confidence = round(
            float(probabilities[class_index] * 100),
            2
        )

        # Unknown anomaly logic
        if anomaly_prediction[0] == -1 and confidence < 60:

            threat_type = "UNKNOWN_ANOMALY"

        return {
            "threat_type": str(threat_type),
            "confidence": confidence,
            "anomaly_score": float(anomaly_score)
        }

    # ---------------------------------
    # Backward-compatible method
    # ---------------------------------

    def analyze(
        self,
        packets,
        bytes_transferred,
        port,
        failed_attempts
    ):

        result = self.analyze_detailed(
            packets=packets,
            bytes_transferred=bytes_transferred,
            port=port,
            failed_attempts=failed_attempts
        )

        return result["anomaly_score"]
