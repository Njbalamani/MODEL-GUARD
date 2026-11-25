from pathlib import Path

import pandas as pd
from django.conf import settings


def load_reference_dataset(reference, features):
    path = Path(reference.file.path)
    if path.stat().st_size > settings.MG_MAX_UPLOAD_BYTES:
        raise ValueError("Reference dataset exceeds the upload size limit.")
    frame = pd.read_csv(path)
    missing = [feature for feature in features if feature not in frame.columns]
    if missing:
        raise ValueError(f"Reference dataset is missing columns: {missing}")
    if len(frame) < 10:
        raise ValueError("Reference dataset must contain at least 10 rows.")
    values = frame[features].apply(pd.to_numeric, errors="coerce")
    if values.isna().to_numpy().mean() > 0.2:
        raise ValueError("Reference dataset contains too many non-numeric values.")
    return values.fillna(values.median()).to_numpy(dtype=float)
