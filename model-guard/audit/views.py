import csv
from datetime import datetime

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from audit.forms import WebhookEndpointForm
from audit.models import AuditLog, WebhookDelivery, WebhookEndpoint
from audit.notifications import WEBHOOK_EVENTS
from projects.permissions import accessible_project_ids


def _is_admin(user):
    return user.is_superuser or getattr(user, "role", "") == "ADMIN"


def _audit_queryset(request):
    queryset = AuditLog.objects.select_related("user").order_by("-created_at")
    if not _is_admin(request.user):
        queryset = queryset.filter(user=request.user)
    action = request.GET.get("action")
    if action:
        queryset = queryset.filter(action__icontains=action)
    date_from = request.GET.get("date_from")
    if date_from:
        try:
            queryset = queryset.filter(created_at__date__gte=datetime.strptime(date_from, "%Y-%m-%d").date())
        except ValueError:
            pass
    date_to = request.GET.get("date_to")
    if date_to:
        try:
            queryset = queryset.filter(created_at__date__lte=datetime.strptime(date_to, "%Y-%m-%d").date())
        except ValueError:
            pass
    return queryset


@login_required
def audit_export_page(request):
    logs = _audit_queryset(request)[:200]
    return render(request, "audit/export.html", {"logs": logs})


@login_required
def audit_export_csv(request):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="modelguard-audit.csv"'
    writer = csv.writer(response)
    writer.writerow(["id", "created_at", "user", "action", "object_type", "object_id", "detail", "ip_address"])
    for item in _audit_queryset(request).iterator():
        writer.writerow([
            item.pk,
            item.created_at.isoformat(),
            item.user.username if item.user else "",
            item.action,
            item.object_type,
            item.object_id,
            item.detail,
            item.ip_address or "",
        ])
    return response


@login_required
def webhook_list(request):
    if not _is_admin(request.user):
        messages.error(request, "Administrator role required.")
        return redirect("dashboard:home")
    endpoints = WebhookEndpoint.objects.select_related("created_by").order_by("-created_at")
    return render(request, "audit/webhooks.html", {
        "endpoints": endpoints,
        "events": WEBHOOK_EVENTS,
    })


@login_required
def webhook_create(request):
    if not _is_admin(request.user):
        messages.error(request, "Administrator role required.")
        return redirect("dashboard:home")
    if request.method == "POST":
        form = WebhookEndpointForm(request.POST)
        if form.is_valid():
            endpoint = form.save(commit=False)
            endpoint.created_by = request.user
            endpoint.save()
            messages.success(request, "Webhook endpoint created.")
            return redirect("audit:webhook-list")
    else:
        form = WebhookEndpointForm(initial={"events": WEBHOOK_EVENTS[:3], "active": True})
    return render(request, "audit/webhook_form.html", {"form": form})


@login_required
def webhook_edit(request, pk):
    if not _is_admin(request.user):
        messages.error(request, "Administrator role required.")
        return redirect("dashboard:home")
    endpoint = get_object_or_404(WebhookEndpoint, pk=pk)
    if request.method == "POST":
        form = WebhookEndpointForm(request.POST, instance=endpoint)
        if form.is_valid():
            form.save()
            messages.success(request, "Webhook endpoint updated.")
            return redirect("audit:webhook-list")
    else:
        form = WebhookEndpointForm(instance=endpoint)
    return render(request, "audit/webhook_form.html", {"form": form, "endpoint": endpoint})


@login_required
def webhook_delete(request, pk):
    if not _is_admin(request.user):
        messages.error(request, "Administrator role required.")
        return redirect("dashboard:home")
    endpoint = get_object_or_404(WebhookEndpoint, pk=pk)
    endpoint.delete()
    return redirect("audit:webhook-list")


@login_required
def webhook_deliveries(request, pk):
    if not _is_admin(request.user):
        messages.error(request, "Administrator role required.")
        return redirect("dashboard:home")
    endpoint = get_object_or_404(WebhookEndpoint, pk=pk)
    deliveries = WebhookDelivery.objects.filter(endpoint=endpoint).order_by("-created_at")[:200]
    return render(request, "audit/deliveries.html", {"endpoint": endpoint, "deliveries": deliveries})
