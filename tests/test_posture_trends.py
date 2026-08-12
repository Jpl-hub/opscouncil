from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from backend.app.posture.trends import MetricSample, analyze_metric_trend


class PostureTrendTest(unittest.TestCase):
    def test_forecasts_sustained_root_disk_growth_from_real_sample_times(self) -> None:
        start = datetime(2026, 7, 29, 0, 0, tzinfo=timezone.utc)
        history = [
            MetricSample(
                observed_at=start + timedelta(minutes=index * 5),
                metrics={"root_disk_used_percent": 70.0 + index},
            )
            for index in range(12)
        ]

        trend = analyze_metric_trend(
            "root_disk_used_percent",
            82.0,
            start + timedelta(minutes=60),
            history,
        )

        self.assertEqual(trend["direction"], "rising")
        self.assertAlmostEqual(float(trend["slope_per_hour"]), 12.0, places=1)
        forecast = trend["forecast"]
        self.assertIsInstance(forecast, dict)
        assert isinstance(forecast, dict)
        self.assertEqual(forecast["status"], "critical")
        self.assertAlmostEqual(float(forecast["hours_to_threshold"]), 0.7, places=1)

    def test_single_spike_does_not_claim_a_capacity_forecast(self) -> None:
        start = datetime(2026, 7, 29, 0, 0, tzinfo=timezone.utc)
        history = [
            MetricSample(
                observed_at=start + timedelta(minutes=index * 5),
                metrics={"root_disk_used_percent": value},
            )
            for index, value in enumerate([40.0, 40.2, 39.9, 40.1, 40.0, 40.1, 40.0, 40.2, 39.8, 40.1, 40.0, 40.1])
        ]

        trend = analyze_metric_trend(
            "root_disk_used_percent",
            62.0,
            start + timedelta(minutes=60),
            history,
        )

        self.assertIsNone(trend["forecast"])
        self.assertLess(float(trend["positive_step_ratio"]), 0.67)


if __name__ == "__main__":
    unittest.main()
