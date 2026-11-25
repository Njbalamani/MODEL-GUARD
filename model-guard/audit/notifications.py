import hashlib
import hmac
import ipaddress
import json
import logging
import socket
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

from django.conf import settings

from audit.models import WebhookDelivery, WebhookEndpoint

logger = logging.getLogger("modelguard")

WEBHOOK_EVENTS = [
    "assessment.completed",
    "assessment.failed",
    "report.generated",
    "suppression.approved",
    "rescan.due",
]


class WebhookValidationError(ValueError):
    pass


def validate_webhook_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise WebhookValidationError("Webhook URL must be an absolute http(s) URL.")
    if parsed.scheme == "http" and not settings.MG_ALLOW_PRIVATE_WEBHOOKS:
        raise WebhookValidationError("Webhook URL must use HTTPS.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise WebhookValidationError("Webhook URL has an invalid port.") from exc
    if not 1 <= port <= 65535:
        raise WebhookValidationError("Webhook URL has an invalid port.")
    if settings.MG_ALLOW_PRIVATE_WEBHOOKS:
        return url
    try:
        addresses = socket.getaddrinfo(parsed.hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise WebhookValidationError("Webhook hostname could not be resolved.") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise WebhookValidationError("Webhook URL must not target a private address.")
    return url


def send_webhook(endpoint, event, payload):
    delivery = WebhookDelivery.objects.create(
        endpoint=endpoint,
        event=event,
        status="PENDING",
        payload=payload,
    )
    body = json.dumps({
        "event": event,
        "delivery_id": delivery.pk,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": payload,
    }, separators=(",", ":")).encode("utf-8")
    if len(body) > settings.MG_WEBHOOK_MAX_BYTES:
        delivery.status = "FAILED"
        delivery.error = "Payload exceeds the configured size limit."
        delivery.save(update_fields=["status", "error"])
        return delivery
    signature = hmac.new(endpoint.secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        endpoint.url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-ModelGuard-Event": event,
            "X-ModelGuard-Signature": signature,
            "User-Agent": "ModelGuard-Webhook/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=settings.MG_WEBHOOK_TIMEOUT) as response:
            delivery.response_code = response.status
            delivery.status = "DELIVERED" if 200 <= response.status < 300 else "FAILED"
    except Exception as exc:
        delivery.status = "FAILED"
        delivery.error = f"{type(exc).__name__}: {exc}"
        logger.warning("Webhook delivery %s failed: %s", delivery.pk, exc)
    delivery.save(update_fields=["status", "response_code", "error"])
    return delivery


def notify(event, payload):
    if event not in WEBHOOK_EVENTS:
        return []
    deliveries = []
    for endpoint in WebhookEndpoint.objects.filter(active=True):
        events = endpoint.events or []
        if event not in events:
            continue
        deliveries.append(send_webhook(endpoint, event, payload))
    return deliveries
