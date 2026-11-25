from django.core.management.base import BaseCommand

from analysis.rescan import run_due_rescans


class Command(BaseCommand):
    help = "Queue assessments for enabled rescan schedules that are due."

    def handle(self, *args, **options):
        processed = run_due_rescans()
        self.stdout.write(self.style.SUCCESS(f"Queued {processed} rescan assessment(s)."))
