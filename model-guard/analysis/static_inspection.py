import io
import math
import os
import zipfile
from collections import Counter
from pathlib import Path

from django.conf import settings

SUSPICIOUS_TOKENS = {
    b"__reduce__": "pickle reduce hook",
    b"os\nsystem": "operating-system command execution",
    b"posix\nsystem": "operating-system command execution",
    b"subprocess": "subprocess execution module",
    b"builtins\neval": "dynamic eval reference",
    b"builtins\nexec": "dynamic exec reference",
    b"torch.load": "unsafe torch.load reference",
    b"pickle.loads": "unsafe pickle.loads reference",
    b"joblib.load": "unsafe joblib.load reference",
}

UNSAFE_FORMATS = {".pkl", ".pickle", ".joblib", ".pt", ".pth", ".h5", ".keras"}
BINARY_ARRAY_FORMATS = {".npy", ".npz"}
ZIP_FORMATS = {".pt", ".pth", ".npz", ".npy"}


def finding(severity, category, title, description, evidence, recommendation, confidence="HIGH", source="static-inspection"):
    return {
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "confidence": confidence,
        "source": source,
    }


def sample_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def inspect_file(path, extension, descriptor=None):
    path = Path(path)
    findings = []
    metadata = {
        "size_bytes": path.stat().st_size,
        "extension": extension,
        "inspection_mode": "static-only",
        "descriptor_validated": bool(descriptor),
    }

    with path.open("rb") as handle:
        head = handle.read(2 * 1024 * 1024)
    sample = head[:65536] or b""
    metadata["entropy"] = round(sample_entropy(sample), 3)
    if metadata["entropy"] > 7.6 and len(sample) >= 4096:
        findings.append(finding(
            "LOW", "Obfuscation", "High sample entropy detected",
            "The sampled byte distribution is unusually uniform and may indicate packed or obfuscated content.",
            {"entropy": metadata["entropy"], "sample_bytes": len(sample)},
            "Confirm the artifact provenance and inspect it in an isolated environment before use.",
            confidence="LOW",
        ))

    if extension in UNSAFE_FORMATS:
        findings.append(finding(
            "HIGH", "Unsafe serialization", "Unsupported or unsafe serialization format",
            "This format commonly relies on arbitrary-object deserialization. ModelGuard inspected the bytes only and did not load the file.",
            {"extension": extension, "safe_loading": False},
            "Prefer safetensors, ONNX, or the validated JSON descriptor format for production workflows.",
        ))

    for token, label in SUSPICIOUS_TOKENS.items():
        index = head.find(token)
        if index >= 0:
            findings.append(finding(
                "CRITICAL", "Unsafe loading pattern", f"Suspicious token: {label}",
                "A token associated with dynamic execution or unsafe deserialization was found in the artifact bytes.",
                {"token": token.decode("latin-1"), "byte_offset": index},
                "Reject this artifact. Do not load it with pickle, torch.load, joblib.load, or similar APIs.",
            ))

    if extension in ZIP_FORMATS or head[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                suspicious_entries = [
                    name for name in names
                    if os.path.splitext(name)[1].lower() in settings.MG_EXECUTABLE_EXTENSIONS
                ]
                metadata["archive_entries"] = len(names)
                metadata["archive_sample"] = names[:40]
                if suspicious_entries:
                    findings.append(finding(
                        "HIGH", "Archive contents", "Executable-looking entries inside model archive",
                        "The archive contains entries with executable extensions. ModelGuard did not extract or run them.",
                        {"entries": suspicious_entries[:20], "count": len(suspicious_entries)},
                        "Reject the artifact and investigate its origin.",
                    ))
        except zipfile.BadZipFile:
            findings.append(finding(
                "MEDIUM", "Format integrity", "File appears to be ZIP but could not be parsed",
                "The file starts with a ZIP signature but the central directory is invalid.",
                {"signature": "PK\\x03\\x04"},
                "Re-export the model artifact and verify the upload.",
                confidence="MEDIUM",
            ))

    if extension == ".onnx":
        signature = head[:2]
        if not (len(signature) == 2 and signature[0] == 0x08 and 1 <= signature[1] <= 20) and head[:4] == b"PK\x03\x04":
            findings.append(finding(
                "MEDIUM", "Format integrity", "ONNX extension does not match content",
                "The file has an .onnx extension but contains a ZIP archive.",
                {"expected_signature": "0x08 0x07", "observed": "ZIP"},
                "Verify the file format before assessment.",
                confidence="MEDIUM",
            ))

    if descriptor:
        findings.append(finding(
            "INFO", "Safe format", "Validated model descriptor",
            "The JSON descriptor passed strict schema validation and is rebuilt only with allow-listed scikit-learn constructors.",
            {"features": len(descriptor["features"]), "model_type": descriptor["model_type"]},
            "Use validated descriptors for reproducible, executable assessments.",
            confidence="HIGH",
            source="descriptor-validator",
        ))

    return metadata, findings
