import datetime
from django.contrib.sessions.models import Session
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from vault.models import IssuedCode, LoginAttempt


class Command(BaseCommand):
    help = "Remove expired sessions and technical caches; never touches vaults, items, versions, audit or the recycle bin."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        now = timezone.now()
        queries = {"sessions": Session.objects.filter(expire_date__lt=now),
            "issued_code_cache": IssuedCode.objects.filter(expires_at__lt=now-datetime.timedelta(days=1)),
            "login_attempts": LoginAttempt.objects.filter(started_at__lt=now-datetime.timedelta(days=1))}
        with transaction.atomic():
            counts = {name: query.count() for name, query in queries.items()}
            if not options["dry_run"]:
                for query in queries.values():
                    query.delete()
        self.stdout.write(str({"dry_run": options["dry_run"], **counts}))
