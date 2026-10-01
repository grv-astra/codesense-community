from datetime import datetime, timezone
from django.test import TestCase
from local.api_app.models.orm import ScanEvent


class ScanEventModelTests(TestCase):
    def test_row_persists_and_is_queryable_by_type_and_time(self):
        now = datetime.now(timezone.utc)
        ScanEvent.objects.create(scan_type="code", completed_at=now)
        ScanEvent.objects.create(scan_type="sbom", completed_at=now)
        self.assertEqual(ScanEvent.objects.filter(scan_type="code").count(), 1)
        self.assertEqual(ScanEvent.objects.filter(completed_at__gte=now).count(), 2)
