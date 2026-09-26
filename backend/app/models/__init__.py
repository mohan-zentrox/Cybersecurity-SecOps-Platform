"""
SQLAlchemy models for Project Aegis.

Importing this package registers all model classes on the shared
declarative Base's metadata, which is required for Base.metadata.create_all()
(used by tests and by local `docker-compose up` bootstrapping) to see every
table. Alembic's env.py also imports this package for autogenerate support.
"""

from app.models.user import User  # noqa: F401
from app.models.audit import AuditEvent  # noqa: F401
from app.models.event import NormalizedEvent, DeadLetterEvent  # noqa: F401
from app.models.rule import DetectionRule  # noqa: F401
from app.models.alert import Alert  # noqa: F401
from app.models.case import Case, CaseAlertLink, CaseTimelineEvent  # noqa: F401
from app.models.ioc import IOC, ThreatIntelFeed  # noqa: F401
from app.models.vulnerability import Asset, ScanImport, Vulnerability  # noqa: F401
from app.models.compliance import ComplianceControl, ComplianceReport  # noqa: F401
from app.models.notification import NotificationChannel, NotificationDelivery  # noqa: F401
