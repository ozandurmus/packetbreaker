import math

MIN_TIMESTAMP = 946684800.0


def timestamp_reason(value, upper):
    if value is None or not math.isfinite(value):
        return "timestamp_missing_or_invalid"
    if value < MIN_TIMESTAMP:
        return "timestamp_before_2000"
    if value > upper:
        return "timestamp_after_now_plus_one_day"
    return None
