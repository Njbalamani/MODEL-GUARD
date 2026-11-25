import hashlib
import os
import re
import uuid
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.base import File
from django.core.files.storage import default_storage

from analysis.descriptor import parse_descriptor


def sanitize_filename(value):
    name = os.path.basename(str(value or ""))
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return (name or "model.bin")[:200]


def _hash_and_magic(upload):
    digest = hashlib.sha256()
    first = b""
    total = 0
    upload.seek(0)
    for chunk in upload.chunks():
        total += len(chunk)
        if not first:
            first = chunk[:512]
        digest.update(chunk)
    upload.seek(0)
    return digest.hexdigest(), first, total


def _check_magic(extension, first):
    if extension in {".json", ".safetensors"}:
        stripped = first.lstrip()
        if not stripped.startswith(b"{"):
            raise ValidationError(f"{extension} files must contain a JSON object.")
    elif extension == ".npy" and not first.startswith(b"\x93NUMPY"):
        raise ValidationError("NPY files must start with the NumPy array signature.")
    elif extension in {".npz", ".pt", ".pth"} and not (first.startswith(b"PK") or first.startswith(b"\x80")):
        raise ValidationError(f"{extension} files must be ZIP archives or pickle streams.")


def validate_and_store(upload, original_name, model_id, version_label):
    name = sanitize_filename(original_name)
    extension = Path(name).suffix.lower()
    if not extension:
        raise ValidationError("The uploaded file must have an extension.")
    if extension in settings.MG_EXECUTABLE_EXTENSIONS:
        raise ValidationError(f"Executable extension {extension} is not allowed.")
    if extension not in settings.MG_ALLOWED_EXTENSIONS:
        raise ValidationError(f"Unsupported model format: {extension}")

    sha256, first, size = _hash_and_magic(upload)
    if size == 0:
        raise ValidationError("Uploaded files must not be empty.")
    if size > settings.MG_MAX_UPLOAD_BYTES:
        raise ValidationError(f"Uploaded file exceeds the {settings.MG_MAX_UPLOAD_BYTES} byte limit.")
    _check_magic(extension, first)

    safe_label = re.sub(r"[^A-Za-z0-9._-]+", "_", version_label or "v1").strip("._") or "v1"
    relative_path = f"models/{model_id}/{uuid.uuid4().hex[:12]}_{safe_label}_{name}"
    stored_name = default_storage.save(relative_path, File(upload))
    is_descriptor = extension == ".json"

    try:
        descriptor = parse_descriptor(default_storage.path(stored_name)) if is_descriptor else None
    except Exception as exc:
        default_storage.delete(stored_name)
        raise ValidationError(f"Invalid model descriptor: {exc}")

    return {
        "stored_name": stored_name,
        "original_name": name,
        "sha256": sha256,
        "size_bytes": size,
        "file_format": extension,
        "is_descriptor": is_descriptor,
        "metadata": {
            "extension": extension,
            "magic_ok": True,
            "descriptor_model_type": descriptor["model_type"] if descriptor else None,
            "feature_count": len(descriptor["features"]) if descriptor else None,
        },
    }
