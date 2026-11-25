from django.core.exceptions import PermissionDenied

from projects.models import Project, ProjectMember


def accessible_project_ids(user):
    if not user or not user.is_authenticated:
        return []
    if user.is_superuser or getattr(user, "role", "") == "ADMIN":
        return list(Project.objects.values_list("id", flat=True))
    owned = list(Project.objects.filter(owner=user).values_list("id", flat=True))
    member = list(ProjectMember.objects.filter(user=user).values_list("project_id", flat=True))
    return sorted(set(owned + member))


def project_access(user, project, write=False):
    if not user or not user.is_authenticated:
        raise PermissionDenied("Authentication is required.")
    if user.is_superuser or getattr(user, "role", "") == "ADMIN" or project.owner_id == user.id:
        return
    membership = ProjectMember.objects.filter(project=project, user=user).first()
    if not membership:
        raise PermissionDenied("You are not a member of this project.")
    if write and membership.role == "VIEWER":
        raise PermissionDenied("Viewers cannot modify project data.")
