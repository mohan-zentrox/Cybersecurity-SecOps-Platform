"""
Database seeding.

Run with::

    python -m app.seed                # users, rules, channels, controls, IOCs, demo data
    python -m app.seed --minimal      # users + detection rules + channels only
    python -m app.seed --reset        # DROP every table first, then seed

This exists because the platform previously had no way to create an
operator: a fresh deployment had an empty `users` table and no endpoint to
populate it, so nobody could log in and every other feature was
unreachable. Seeding is idempotent — re-running adds only what is missing.

The seeded passwords are DEVELOPMENT CREDENTIALS. They are printed at the
end of the run and are documented in the README. Rotate or disable these
accounts before any deployment that is reachable by anyone else.
"""

import argparse
import logging
import random
import sys
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.security import hash_password
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models.alert import Alert
from app.models.case import Case
from app.models.compliance import ComplianceControl
from app.models.event import NormalizedEvent
from app.models.ioc import IOC, IOCType, ThreatIntelFeed
from app.models.notification import ChannelType, NotificationChannel
from app.models.rule import DetectionRule, Severity
from app.models.user import AppRole, User
from app.models.vulnerability import Asset, Vulnerability
from app.services.compliance import seed_default_controls
from app.services.enrichment import upsert_ioc
from app.services.normalizer import process_raw_batch
from app.services.rule_engine import run_all_enabled_rules

log = logging.getLogger("aegis.seed")

# --------------------------------------------------------------------------
# Development credentials. Documented in the README; rotate before exposure.
# --------------------------------------------------------------------------
SEED_USERS: list[dict[str, str]] = [
    {
        "username": "admin",
        "email": "admin@aegis.example.com",
        "password": "AegisAdmin!2024",
        "role": AppRole.ADMIN,
    },
    {
        "username": "analyst",
        "email": "analyst@aegis.example.com",
        "password": "AegisAnalyst!2024",
        "role": AppRole.ANALYST,
    },
    {
        "username": "detector",
        "email": "detector@aegis.example.com",
        "password": "AegisDetect!2024",
        "role": AppRole.DETECTION_ENGINEER,
    },
    {
        "username": "auditor",
        "email": "auditor@aegis.example.com",
        "password": "AegisAudit!2024",
        "role": AppRole.COMPLIANCE,
    },
]


SEED_RULES: list[dict] = [
    {
        "name": "Brute force: repeated failed logons from one source",
        "description": (
            "Five or more failed authentication attempts from the same source IP within five "
            "minutes. The classic password-spray / credential-stuffing signature."
        ),
        "severity": Severity.HIGH,
        "mitre_technique_id": "T1110",
        "logic": {
            "match": "all",
            "conditions": [{"field": "event.action", "operator": "eq", "value": "logon_failed"}],
            "threshold": {"count": 5, "window_seconds": 300, "group_by": "source.ip"},
        },
    },
    {
        "name": "Successful logon from a known-malicious IP",
        "description": (
            "Authentication succeeded from an address present in the threat-intel indicator "
            "set. Depends on enrichment having annotated the event (FRD-TI-03)."
        ),
        "severity": Severity.CRITICAL,
        "mitre_technique_id": "T1078",
        "logic": {
            "match": "all",
            "conditions": [
                {"field": "event.action", "operator": "eq", "value": "logon_success"},
                {"field": "threat.indicator.matched", "operator": "eq", "value": True},
            ],
        },
    },
    {
        "name": "Privilege escalation: user added to administrators",
        "description": "A principal was granted membership of a privileged group.",
        "severity": Severity.HIGH,
        "mitre_technique_id": "T1098",
        "logic": {
            "match": "all",
            "conditions": [
                {"field": "event.action", "operator": "eq", "value": "group_member_added"},
                {"field": "group.name", "operator": "contains", "value": "admin"},
            ],
        },
    },
    {
        "name": "Suspicious PowerShell encoded command",
        "description": "PowerShell invoked with -EncodedCommand, a common obfuscation wrapper.",
        "severity": Severity.HIGH,
        "mitre_technique_id": "T1059",
        "logic": {
            "match": "all",
            "conditions": [
                {"field": "process.name", "operator": "eq", "value": "powershell.exe"},
                {"field": "process.command_line", "operator": "regex", "value": "(?i)-e(nc|ncoded)?\\s"},
            ],
        },
    },
    {
        "name": "Mass file deletion by a single user",
        "description": (
            "Fifty or more file-deletion events from one user inside ten minutes — consistent "
            "with ransomware staging or insider data destruction."
        ),
        "severity": Severity.CRITICAL,
        "mitre_technique_id": "T1485",
        "logic": {
            "match": "all",
            "conditions": [{"field": "event.action", "operator": "eq", "value": "file_deleted"}],
            "threshold": {"count": 50, "window_seconds": 600, "group_by": "user.name"},
        },
    },
    {
        "name": "Outbound connection to a threat-intel indicator",
        "description": "An internal host contacted an address or domain on an active indicator feed.",
        "severity": Severity.HIGH,
        "mitre_technique_id": "T1071",
        "logic": {
            "match": "all",
            "conditions": [
                {"field": "event.category", "operator": "eq", "value": "network"},
                {"field": "threat.indicator.max_confidence", "operator": "gte", "value": 70},
            ],
        },
    },
    {
        "name": "Account lockout burst",
        "description": "Three or more account lockouts in fifteen minutes across the estate.",
        "severity": Severity.MEDIUM,
        "mitre_technique_id": "T1110",
        "logic": {
            "match": "all",
            "conditions": [{"field": "event.action", "operator": "eq", "value": "account_locked"}],
            "threshold": {"count": 3, "window_seconds": 900},
        },
    },
    {
        "name": "Security log cleared",
        "description": "Audit log clearing is a near-universal anti-forensics step.",
        "severity": Severity.CRITICAL,
        "mitre_technique_id": "T1070",
        "logic": {
            "match": "any",
            "conditions": [
                {"field": "event.action", "operator": "eq", "value": "log_cleared"},
                {"field": "event.action", "operator": "eq", "value": "audit_log_cleared"},
            ],
        },
    },
]


SEED_IOCS: list[dict] = [
    {"type": IOCType.IP, "value": "203.0.113.66", "confidence": 90, "severity": "critical",
     "description": "Known credential-stuffing infrastructure", "tags": ["bruteforce", "c2"]},
    {"type": IOCType.IP, "value": "198.51.100.23", "confidence": 80, "severity": "high",
     "description": "Cobalt Strike team server", "tags": ["c2", "cobaltstrike"]},
    {"type": IOCType.IP, "value": "192.0.2.150", "confidence": 75, "severity": "high",
     "description": "Scanning and exploitation source", "tags": ["scanner"]},
    {"type": IOCType.DOMAIN, "value": "malicious-update.example", "confidence": 85, "severity": "high",
     "description": "Fake software-update distribution domain", "tags": ["malware", "dropper"]},
    {"type": IOCType.DOMAIN, "value": "exfil-node.example", "confidence": 95, "severity": "critical",
     "description": "Observed data-exfiltration endpoint", "tags": ["exfiltration"]},
    {"type": IOCType.FILE_HASH,
     "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     "confidence": 70, "severity": "medium", "description": "Known dropper sample", "tags": ["malware"]},
    {"type": IOCType.URL, "value": "http://malicious-update.example/payload.bin", "confidence": 88,
     "severity": "high", "description": "Second-stage payload URL", "tags": ["dropper"]},
]


SEED_CHANNELS: list[dict] = [
    {
        "name": "soc-log",
        "type": ChannelType.LOG,
        "min_severity": "low",
        "config": {},
    },
    {
        "name": "soc-oncall-webhook",
        "type": ChannelType.WEBHOOK,
        "min_severity": "high",
        "enabled": False,  # disabled until an operator supplies a real URL
        "config": {"url": ""},
    },
]


SEED_ASSETS: list[dict] = [
    {"hostname": "web-prod-01", "ip_address": "10.10.1.11", "environment": "production",
     "criticality": "critical", "internet_facing": True, "owner": "platform-team"},
    {"hostname": "db-prod-01", "ip_address": "10.10.2.21", "environment": "production",
     "criticality": "critical", "internet_facing": False, "owner": "data-team"},
    {"hostname": "jump-01", "ip_address": "10.10.0.5", "environment": "production",
     "criticality": "high", "internet_facing": True, "owner": "infra-team"},
    {"hostname": "dev-build-03", "ip_address": "10.20.3.33", "environment": "development",
     "criticality": "low", "internet_facing": False, "owner": "dev-team"},
]


SEED_VULNS: list[dict] = [
    {"hostname": "web-prod-01", "cve_id": "CVE-2024-3094", "title": "xz-utils backdoor (liblzma)",
     "severity": "critical", "cvss_score": 10.0, "solution": "Downgrade xz-utils to 5.4.6 or earlier.",
     "description": "Malicious code in upstream xz releases enables SSH authentication bypass."},
    {"hostname": "web-prod-01", "cve_id": "CVE-2023-44487", "title": "HTTP/2 Rapid Reset",
     "severity": "high", "cvss_score": 7.5, "solution": "Patch the HTTP/2 server and rate-limit streams.",
     "description": "Stream cancellation floods enable a low-cost denial of service."},
    {"hostname": "db-prod-01", "cve_id": "CVE-2024-1597", "title": "PostgreSQL JDBC SQL injection",
     "severity": "critical", "cvss_score": 9.8, "solution": "Upgrade pgjdbc to 42.7.2.",
     "description": "PreferQueryMode=SIMPLE permits injection via a crafted parameter."},
    {"hostname": "jump-01", "cve_id": "CVE-2024-6387", "title": "OpenSSH regreSSHion RCE",
     "severity": "critical", "cvss_score": 8.1, "solution": "Upgrade OpenSSH to 9.8p1.",
     "description": "Signal handler race in sshd allows unauthenticated remote code execution."},
    {"hostname": "dev-build-03", "cve_id": "CVE-2023-38545", "title": "curl SOCKS5 heap overflow",
     "severity": "high", "cvss_score": 8.8, "solution": "Upgrade curl to 8.4.0.",
     "description": "Heap buffer overflow during SOCKS5 proxy handshake."},
]


def _ensure_users(db: Session) -> int:
    created = 0
    for spec in SEED_USERS:
        if db.query(User).filter(User.username == spec["username"]).first():
            continue
        db.add(
            User(
                username=spec["username"],
                email=spec["email"],
                hashed_password=hash_password(spec["password"]),
                role=spec["role"],
                is_active=True,
            )
        )
        created += 1
    db.commit()
    return created


def _ensure_rules(db: Session, author: User | None) -> int:
    created = 0
    for spec in SEED_RULES:
        if db.query(DetectionRule).filter(DetectionRule.name == spec["name"]).first():
            continue
        db.add(
            DetectionRule(
                name=spec["name"],
                description=spec["description"],
                severity=spec["severity"],
                mitre_technique_id=spec["mitre_technique_id"],
                logic=spec["logic"],
                enabled=True,
                created_by=author.id if author else None,
            )
        )
        created += 1
    db.commit()
    return created


def _ensure_channels(db: Session) -> int:
    created = 0
    for spec in SEED_CHANNELS:
        if db.query(NotificationChannel).filter(NotificationChannel.name == spec["name"]).first():
            continue
        db.add(NotificationChannel(**spec))
        created += 1
    db.commit()
    return created


def _ensure_threat_intel(db: Session) -> int:
    feed = db.query(ThreatIntelFeed).filter(ThreatIntelFeed.name == "seed-indicators").first()
    if feed is None:
        feed = ThreatIntelFeed(
            name="seed-indicators", kind="manual", enabled=True, default_confidence=75
        )
        db.add(feed)
        db.commit()
        db.refresh(feed)

    created = 0
    for spec in SEED_IOCS:
        _, was_created = upsert_ioc(
            db,
            ioc_type=spec["type"],
            value=spec["value"],
            confidence=spec["confidence"],
            severity=spec["severity"],
            description=spec["description"],
            tags=spec["tags"],
            source="seed-indicators",
            feed_id=feed.id,
        )
        created += int(was_created)
    return created


def _ensure_assets_and_vulns(db: Session) -> tuple[int, int]:
    assets_created = 0
    for spec in SEED_ASSETS:
        existing = db.query(Asset).filter(Asset.hostname == spec["hostname"]).first()
        if existing:
            continue
        db.add(Asset(**spec))
        assets_created += 1
    db.commit()

    vulns_created = 0
    now = datetime.now(timezone.utc)
    for spec in SEED_VULNS:
        asset = db.query(Asset).filter(Asset.hostname == spec["hostname"]).first()
        if asset is None:
            continue
        exists = (
            db.query(Vulnerability)
            .filter(Vulnerability.asset_id == asset.id, Vulnerability.cve_id == spec["cve_id"])
            .first()
        )
        if exists:
            continue
        db.add(
            Vulnerability(
                asset_id=asset.id,
                cve_id=spec["cve_id"],
                title=spec["title"],
                description=spec["description"],
                severity=spec["severity"],
                cvss_score=spec["cvss_score"],
                solution=spec["solution"],
                scanner="seed",
                discovered_at=now - timedelta(days=3),
                last_seen_at=now,
            )
        )
        vulns_created += 1
    db.commit()
    return assets_created, vulns_created


def _demo_events() -> list[dict]:
    """Raw events shaped to trigger several of the seeded rules."""
    now = datetime.now(timezone.utc)
    events: list[dict] = []

    # Brute force burst: 8 failures from one IP inside two minutes.
    for i in range(8):
        events.append(
            {
                "action": "logon_failed",
                "category": "authentication",
                "outcome": "failure",
                "src_ip": "203.0.113.66",
                "username": "svc_backup",
                "hostname": "web-prod-01",
                "timestamp": (now - timedelta(minutes=30, seconds=15 * i)).isoformat(),
            }
        )

    # ...followed by a success from the same (known-malicious) address.
    events.append(
        {
            "action": "logon_success",
            "category": "authentication",
            "outcome": "success",
            "src_ip": "203.0.113.66",
            "username": "svc_backup",
            "hostname": "web-prod-01",
            "timestamp": (now - timedelta(minutes=28)).isoformat(),
        }
    )

    # Privilege escalation.
    events.append(
        {
            "action": "group_member_added",
            "category": "iam",
            "outcome": "success",
            "username": "svc_backup",
            "hostname": "web-prod-01",
            "group": {"name": "Domain Admins"},
            "timestamp": (now - timedelta(minutes=26)).isoformat(),
        }
    )

    # Encoded PowerShell.
    events.append(
        {
            "action": "process_started",
            "category": "process",
            "outcome": "success",
            "username": "svc_backup",
            "hostname": "web-prod-01",
            "process": {
                "name": "powershell.exe",
                "command_line": "powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4A",
            },
            "timestamp": (now - timedelta(minutes=25)).isoformat(),
        }
    )

    # Audit log cleared.
    events.append(
        {
            "action": "log_cleared",
            "category": "configuration",
            "outcome": "success",
            "username": "svc_backup",
            "hostname": "web-prod-01",
            "timestamp": (now - timedelta(minutes=20)).isoformat(),
        }
    )

    # Outbound traffic to a malicious domain.
    for i in range(3):
        events.append(
            {
                "action": "network_connection",
                "category": "network",
                "outcome": "success",
                "src_ip": "10.10.1.11",
                "dst_ip": "198.51.100.23",
                "hostname": "web-prod-01",
                "dns": {"question": {"name": "exfil-node.example"}},
                "timestamp": (now - timedelta(minutes=18 - i)).isoformat(),
            }
        )

    # Routine background noise so the console is not all red.
    rng = random.Random(1337)
    for i in range(40):
        events.append(
            {
                "action": "logon_success",
                "category": "authentication",
                "outcome": "success",
                "src_ip": f"10.10.{rng.randint(1, 3)}.{rng.randint(10, 60)}",
                "username": rng.choice(["alice", "bob", "carol", "dave"]),
                "hostname": rng.choice(["web-prod-01", "db-prod-01", "jump-01"]),
                "timestamp": (now - timedelta(hours=rng.randint(1, 48))).isoformat(),
            }
        )

    # A few malformed payloads, to populate the dead-letter queue.
    events.append({"nothing": "useful"})
    events.append({"action": "logon_failed", "timestamp": "not-a-real-timestamp"})

    return events


def _seed_demo_activity(db: Session) -> dict[str, int]:
    if db.query(NormalizedEvent).count() > 0:
        return {"events": 0, "alerts": 0}
    summary = process_raw_batch(db, _demo_events())
    alerts = run_all_enabled_rules(db, notify=False)
    return {
        "events": summary.accepted,
        "dead_lettered": summary.dead_lettered,
        "threat_matches": summary.threat_matches,
        "alerts": len(alerts),
    }


def seed(*, minimal: bool = False, reset: bool = False) -> dict[str, object]:
    settings = get_settings()
    configure_logging(settings.LOG_LEVEL, as_json=False)

    if reset:
        log.warning("dropping all tables before seeding")
        Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        stats: dict[str, object] = {}
        stats["users_created"] = _ensure_users(db)

        admin = db.query(User).filter(User.username == "admin").first()
        stats["rules_created"] = _ensure_rules(db, admin)
        stats["channels_created"] = _ensure_channels(db)
        stats["controls_created"] = seed_default_controls(db)

        if not minimal:
            stats["iocs_created"] = _ensure_threat_intel(db)
            assets, vulns = _ensure_assets_and_vulns(db)
            stats["assets_created"] = assets
            stats["vulnerabilities_created"] = vulns
            stats["demo"] = _seed_demo_activity(db)

        stats["totals"] = {
            "users": db.query(User).count(),
            "rules": db.query(DetectionRule).count(),
            "iocs": db.query(IOC).count(),
            "alerts": db.query(Alert).count(),
            "cases": db.query(Case).count(),
            "assets": db.query(Asset).count(),
            "vulnerabilities": db.query(Vulnerability).count(),
            "compliance_controls": db.query(ComplianceControl).count(),
        }
        return stats
    finally:
        db.close()


def _print_report(stats: dict[str, object]) -> None:
    print("\n" + "=" * 68)
    print("  Project Aegis - database seeded")
    print("=" * 68)
    for key, value in stats.items():
        if key != "totals":
            print(f"  {key:<26} {value}")
    print("-" * 68)
    for key, value in (stats.get("totals") or {}).items():  # type: ignore[union-attr]
        print(f"  total {key:<20} {value}")
    print("=" * 68)
    print("  LOGIN CREDENTIALS (development only - rotate before exposure)")
    print("-" * 68)
    print(f"  {'USERNAME':<12} {'PASSWORD':<22} ROLE")
    for spec in SEED_USERS:
        print(f"  {spec['username']:<12} {spec['password']:<22} {spec['role']}")
    print("=" * 68 + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the Project Aegis database.")
    parser.add_argument(
        "--minimal", action="store_true", help="Users, rules, channels and controls only (no demo data)"
    )
    parser.add_argument(
        "--reset", action="store_true", help="DROP ALL TABLES before seeding (destructive)"
    )
    args = parser.parse_args()

    stats = seed(minimal=args.minimal, reset=args.reset)
    _print_report(stats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
