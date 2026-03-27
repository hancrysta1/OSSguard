"""Benign: Pure math utility functions."""
import math
from collections import Counter


def mean(values: list[float]) -> float:
    return sum(values) / len(values)


def standard_deviation(values: list[float]) -> float:
    avg = mean(values)
    variance = sum((x - avg) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


def entropy(data: list) -> float:
    counter = Counter(data)
    total = len(data)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in counter.values()
    )
