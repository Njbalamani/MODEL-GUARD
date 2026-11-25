import hashlib
import hmac

from django.conf import settings


def sign_bytes(data):
    key = settings.MG_REPORT_SIGNING_KEY.encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_report(report):
    if not report.file or not report.signature:
        return {"valid": False, "reason": "Report has no signature or file."}
    with report.file.open("rb") as handle:
        data = handle.read()
    digest = hashlib.sha256(data).hexdigest()
    signature = sign_bytes(data)
    valid = digest == report.sha256 and hmac.compare_digest(signature, report.signature)
    return {
        "valid": valid,
        "reason": "Signature and hash match." if valid else "Signature or hash does not match.",
        "digest": digest,
    }
