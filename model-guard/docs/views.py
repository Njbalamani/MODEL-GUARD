from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView


class DocsHomeView(LoginRequiredMixin, TemplateView):
    template_name = "docs/index.html"


class ArchitectureView(LoginRequiredMixin, TemplateView):
    template_name = "docs/architecture.html"


class ERDiagramView(LoginRequiredMixin, TemplateView):
    template_name = "docs/er_diagram.html"


class APIDocsView(LoginRequiredMixin, TemplateView):
    template_name = "docs/api.html"
