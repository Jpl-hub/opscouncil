from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from statistics import median
from typing import Mapping


@dataclass(frozen=True, slots=True)
class MetricSample:
    observed_at: datetime
    metrics: Mapping[str, float]


MINIMUM_EFFECT = {
    "memory_used_percent": 3.0,
    "root_disk_used_percent": 2.0,
    "listener_count": 1.0,
    "top_cpu_percent": 5.0,
}
MINIMUM_RISING_SLOPE_PER_HOUR = {
    "memory_used_percent": 1.0,
    "root_disk_used_percent": 0.25,
    "listener_count": 0.5,
    "top_cpu_percent": 2.0,
}
CAPACITY_THRESHOLD_PERCENT = 90.0
CAPACITY_MINIMUM_SAMPLES = 12
CAPACITY_MINIMUM_SPAN_HOURS = 0.75


def analyze_metric_trend(
    key: str,
    current: float,
    observed_at: datetime,
    history: list[MetricSample],
) -> dict[str, object]:
    points = [
        (_aware(sample.observed_at), float(sample.metrics[key]))
        for sample in history
        if isinstance(sample.metrics.get(key), (int, float))
    ]
    values = [value for _, value in points]
    if not values:
        return {
            "median_absolute_deviation": 0.0,
            "robust_score": None,
            "slope_per_hour": None,
            "direction": "insufficient",
            "persistence_count": 0,
            "sample_span_minutes": 0,
            "positive_step_ratio": None,
            "forecast": None,
        }

    baseline = float(median(values))
    mad = float(median(abs(value - baseline) for value in values))
    scaled_mad = 1.4826 * mad
    robust_score = (
        round((current - baseline) / scaled_mad, 2)
        if scaled_mad > 0
        else None
    )
    all_points = sorted([*points, (_aware(observed_at), float(current))], key=lambda item: item[0])
    slope = _theil_sen_slope_per_hour(all_points)
    span_hours = _span_hours(all_points)
    positive_ratio = _positive_step_ratio(all_points)
    minimum_slope = MINIMUM_RISING_SLOPE_PER_HOUR.get(key, 1.0)
    direction = "stable"
    if slope is not None and slope >= minimum_slope:
        direction = "rising"
    elif slope is not None and slope <= -minimum_slope:
        direction = "falling"

    threshold = baseline + max(
        MINIMUM_EFFECT.get(key, 1.0),
        scaled_mad * 3,
    )
    persistence_count = _trailing_threshold_count(
        [value for _, value in all_points],
        threshold,
    )
    forecast = _capacity_forecast(
        key=key,
        current=current,
        slope_per_hour=slope,
        sample_count=len(all_points),
        span_hours=span_hours,
        positive_step_ratio=positive_ratio,
    )
    return {
        "median_absolute_deviation": round(mad, 3),
        "robust_score": robust_score,
        "slope_per_hour": round(slope, 3) if slope is not None else None,
        "direction": direction,
        "persistence_count": persistence_count,
        "sample_span_minutes": round(span_hours * 60),
        "positive_step_ratio": round(positive_ratio, 3) if positive_ratio is not None else None,
        "forecast": forecast,
    }


def is_robust_positive_outlier(key: str, delta: float, robust_score: object) -> bool:
    return (
        isinstance(robust_score, (int, float))
        and robust_score >= 6.0
        and delta >= MINIMUM_EFFECT.get(key, 1.0)
    )


def _capacity_forecast(
    *,
    key: str,
    current: float,
    slope_per_hour: float | None,
    sample_count: int,
    span_hours: float,
    positive_step_ratio: float | None,
) -> dict[str, object] | None:
    if key != "root_disk_used_percent":
        return None
    if (
        sample_count < CAPACITY_MINIMUM_SAMPLES
        or span_hours < CAPACITY_MINIMUM_SPAN_HOURS
        or slope_per_hour is None
        or slope_per_hour < MINIMUM_RISING_SLOPE_PER_HOUR[key]
        or positive_step_ratio is None
        or positive_step_ratio < 0.67
    ):
        return None
    hours_to_threshold = max(
        0.0,
        (CAPACITY_THRESHOLD_PERCENT - current) / slope_per_hour,
    )
    if hours_to_threshold > 168:
        return None
    status = "critical" if hours_to_threshold <= 6 else "warn" if hours_to_threshold <= 72 else "ok"
    confidence = "high" if sample_count >= 12 and span_hours >= 1 else "medium"
    return {
        "threshold_percent": CAPACITY_THRESHOLD_PERCENT,
        "hours_to_threshold": round(hours_to_threshold, 1),
        "status": status,
        "confidence": confidence,
        "sample_count": sample_count,
        "sample_span_minutes": round(span_hours * 60),
    }


def _theil_sen_slope_per_hour(points: list[tuple[datetime, float]]) -> float | None:
    slopes: list[float] = []
    for left_index, (left_at, left_value) in enumerate(points):
        for right_at, right_value in points[left_index + 1 :]:
            elapsed_hours = (right_at - left_at).total_seconds() / 3600
            if elapsed_hours <= 0:
                continue
            slopes.append((right_value - left_value) / elapsed_hours)
    return float(median(slopes)) if slopes else None


def _positive_step_ratio(points: list[tuple[datetime, float]]) -> float | None:
    if len(points) < 2:
        return None
    steps = [
        right_value - left_value
        for (_, left_value), (_, right_value) in zip(points, points[1:])
    ]
    return sum(step > 0.05 for step in steps) / len(steps)


def _trailing_threshold_count(values: list[float], threshold: float) -> int:
    count = 0
    for value in reversed(values):
        if value < threshold:
            break
        count += 1
    return count


def _span_hours(points: list[tuple[datetime, float]]) -> float:
    if len(points) < 2:
        return 0.0
    return max(0.0, (points[-1][0] - points[0][0]).total_seconds() / 3600)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
