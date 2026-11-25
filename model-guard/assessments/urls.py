from django.urls import path

from assessments.views import (
    AssessmentDetailView, AssessmentListView, RescanScheduleListView,
    add_comment, approve_suppression, create_rescan_schedule,
    delete_rescan_schedule, revoke_suppression, requeue_assessment,
    request_suppression, toggle_rescan_schedule,
)

app_name = "assessments"

urlpatterns = [
    path("", AssessmentListView.as_view(), name="list"),
    path("<int:pk>/", AssessmentDetailView.as_view(), name="detail"),
    path("<int:pk>/requeue/", requeue_assessment, name="requeue"),
    path("findings/<int:finding_id>/suppress/", request_suppression, name="suppress"),
    path("suppressions/<int:pk>/approve/", approve_suppression, name="approve-suppression"),
    path("suppressions/<int:pk>/revoke/", revoke_suppression, name="revoke-suppression"),
    path("<int:pk>/comment/", add_comment, name="comment"),
    path("schedules/", RescanScheduleListView.as_view(), name="schedules"),
    path("schedules/<int:version_id>/create/", create_rescan_schedule, name="schedule-create"),
    path("schedules/<int:pk>/toggle/", toggle_rescan_schedule, name="schedule-toggle"),
    path("schedules/<int:pk>/delete/", delete_rescan_schedule, name="schedule-delete"),
]
