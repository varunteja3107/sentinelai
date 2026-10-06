import numpy as np

from sklearn.ensemble import IsolationForest


class ThreatDetectionAI:

    def __init__(self):

        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.15,
            random_state=42
        )

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
        ])

        self.model.fit(training_data)

    def analyze(
        self,
        packets,
        bytes_transferred,
        port,
        failed_attempts
    ):

        features = np.array([[
            packets,
            bytes_transferred,
            port,
            failed_attempts
        ]])

        prediction = self.model.predict(features)

        raw_score = self.model.decision_function(features)[0]

        if prediction[0] == -1:

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

        return anomaly_score
