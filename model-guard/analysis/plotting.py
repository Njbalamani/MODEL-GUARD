import io

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def render_importance_plot(feature_importances, method):
    items = list(feature_importances or [])
    if not items:
        return None
    names = [item["feature"] for item in items][::-1]
    values = [float(item["value"]) for item in items][::-1]
    figure, axes = plt.subplots(figsize=(8, 3.6), dpi=140)
    axes.barh(names, values, color="#d4af37")
    axes.set_xlabel("Absolute attribution / importance drop")
    axes.set_title(f"ModelGuard explanation ({method})")
    axes.grid(axis="x", alpha=0.25)
    figure.tight_layout()
    buffer = io.BytesIO()
    figure.savefig(buffer, format="png", bbox_inches="tight")
    plt.close(figure)
    return buffer.getvalue()
