"""Pure helpers for the S3 spike: line fit, concurrency, timing summaries."""
import statistics


def fit_line(points):
    """Least-squares fit of (n, bytes) -> (baseline, per_instance)."""
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        raise ValueError("need at least two distinct instance counts")
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    return my - slope * mx, slope


def max_concurrency(pool, overhead, workload=0):
    """How many machines fit in a memory pool of `pool` bytes."""
    cost = overhead + workload
    if cost <= 0:
        raise ValueError("per-instance cost must be positive")
    return int(pool // cost)


def summarize(samples):
    s = sorted(samples)
    q = statistics.quantiles(s, n=10, method="inclusive") if len(s) > 1 else [s[0]] * 9
    return {"n": len(s), "median": statistics.median(s), "p90": round(q[8], 6), "max": s[-1]}
