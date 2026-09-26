"""Initial schema for Project Aegis.

Creates every table: users, audit chain, event store and dead letters,
detection rules, alerts, cases and timeline, threat-intel feeds and IOCs,
assets and vulnerabilities, compliance controls and reports, notification
channels and deliveries.

Revision ID: 0001_initial
Revises: 
Create Date: 2026-09-26 19:14:45.322143

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app.db.base import PortableJSON

revision: str = '0001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('assets',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('hostname', sa.String(length=255), nullable=False),
    sa.Column('ip_address', sa.String(length=64), nullable=True),
    sa.Column('owner', sa.String(length=128), nullable=True),
    sa.Column('environment', sa.String(length=32), nullable=False),
    sa.Column('criticality', sa.String(length=16), nullable=False),
    sa.Column('internet_facing', sa.Boolean(), nullable=False),
    sa.Column('tags', PortableJSON, nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('hostname', 'ip_address', name='uq_asset_hostname_ip')
    )
    op.create_index(op.f('ix_assets_hostname'), 'assets', ['hostname'], unique=False)
    op.create_index(op.f('ix_assets_ip_address'), 'assets', ['ip_address'], unique=False)
    op.create_table('audit_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
    sa.Column('actor', sa.String(length=64), nullable=False),
    sa.Column('action', sa.String(length=128), nullable=False),
    sa.Column('resource', sa.String(length=255), nullable=False),
    sa.Column('details', PortableJSON, nullable=False),
    sa.Column('prev_hash', sa.String(length=64), nullable=False),
    sa.Column('content_hash', sa.String(length=64), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('content_hash')
    )
    op.create_table('compliance_controls',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('framework', sa.String(length=32), nullable=False),
    sa.Column('control_id', sa.String(length=32), nullable=False),
    sa.Column('title', sa.String(length=512), nullable=False),
    sa.Column('description', sa.String(length=2000), nullable=False),
    sa.Column('evidence_collector', sa.String(length=64), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('framework', 'control_id', name='uq_control_framework_id')
    )
    op.create_index(op.f('ix_compliance_controls_framework'), 'compliance_controls', ['framework'], unique=False)
    op.create_table('compliance_reports',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('framework', sa.String(length=32), nullable=False),
    sa.Column('period_start', sa.DateTime(timezone=True), nullable=False),
    sa.Column('period_end', sa.DateTime(timezone=True), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('controls_total', sa.Integer(), nullable=False),
    sa.Column('controls_passed', sa.Integer(), nullable=False),
    sa.Column('controls_failed', sa.Integer(), nullable=False),
    sa.Column('results', PortableJSON, nullable=False),
    sa.Column('rendered_html', sa.Text(), nullable=True),
    sa.Column('error_message', sa.String(length=2000), nullable=True),
    sa.Column('generated_by', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_compliance_reports_framework'), 'compliance_reports', ['framework'], unique=False)
    op.create_table('dead_letter_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('raw_payload', PortableJSON, nullable=False),
    sa.Column('error_message', sa.String(length=1024), nullable=False),
    sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('replayed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('replay_status', sa.String(length=32), nullable=True),
    sa.Column('resolved', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_dead_letter_events_resolved'), 'dead_letter_events', ['resolved'], unique=False)
    op.create_table('normalized_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('event_action', sa.String(length=128), nullable=True),
    sa.Column('event_category', sa.String(length=64), nullable=True),
    sa.Column('event_outcome', sa.String(length=32), nullable=True),
    sa.Column('source_ip', sa.String(length=64), nullable=True),
    sa.Column('destination_ip', sa.String(length=64), nullable=True),
    sa.Column('user_name', sa.String(length=128), nullable=True),
    sa.Column('host_name', sa.String(length=128), nullable=True),
    sa.Column('event_timestamp', sa.DateTime(timezone=True), nullable=False),
    sa.Column('ingested_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('ecs', PortableJSON, nullable=False),
    sa.Column('raw', PortableJSON, nullable=False),
    sa.Column('enrichment', PortableJSON, nullable=False),
    sa.Column('threat_matched', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_normalized_events_event_action'), 'normalized_events', ['event_action'], unique=False)
    op.create_index(op.f('ix_normalized_events_event_category'), 'normalized_events', ['event_category'], unique=False)
    op.create_index(op.f('ix_normalized_events_event_timestamp'), 'normalized_events', ['event_timestamp'], unique=False)
    op.create_index(op.f('ix_normalized_events_source_ip'), 'normalized_events', ['source_ip'], unique=False)
    op.create_index(op.f('ix_normalized_events_threat_matched'), 'normalized_events', ['threat_matched'], unique=False)
    op.create_index(op.f('ix_normalized_events_user_name'), 'normalized_events', ['user_name'], unique=False)
    op.create_table('notification_channels',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('type', sa.String(length=16), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('min_severity', sa.String(length=16), nullable=False),
    sa.Column('config', PortableJSON, nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('notification_deliveries',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('channel_id', sa.Integer(), nullable=True),
    sa.Column('channel_name', sa.String(length=128), nullable=False),
    sa.Column('channel_type', sa.String(length=16), nullable=False),
    sa.Column('subject_type', sa.String(length=32), nullable=False),
    sa.Column('subject_id', sa.Integer(), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('detail', sa.String(length=2000), nullable=False),
    sa.Column('payload', PortableJSON, nullable=False),
    sa.Column('attempted_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_notification_deliveries_attempted_at'), 'notification_deliveries', ['attempted_at'], unique=False)
    op.create_index(op.f('ix_notification_deliveries_channel_id'), 'notification_deliveries', ['channel_id'], unique=False)
    op.create_index(op.f('ix_notification_deliveries_status'), 'notification_deliveries', ['status'], unique=False)
    op.create_index(op.f('ix_notification_deliveries_subject_id'), 'notification_deliveries', ['subject_id'], unique=False)
    op.create_table('scan_imports',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('filename', sa.String(length=512), nullable=False),
    sa.Column('scanner', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=24), nullable=False),
    sa.Column('findings_imported', sa.Integer(), nullable=False),
    sa.Column('findings_failed', sa.Integer(), nullable=False),
    sa.Column('assets_touched', sa.Integer(), nullable=False),
    sa.Column('error_message', sa.String(length=2000), nullable=True),
    sa.Column('imported_by', sa.String(length=64), nullable=False),
    sa.Column('imported_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('threat_intel_feeds',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('kind', sa.String(length=32), nullable=False),
    sa.Column('url', sa.String(length=1024), nullable=True),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('default_confidence', sa.Integer(), nullable=False),
    sa.Column('last_polled_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_poll_status', sa.String(length=512), nullable=True),
    sa.Column('last_poll_indicator_count', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('hashed_password', sa.String(length=255), nullable=False),
    sa.Column('role', sa.String(length=32), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    op.create_table('cases',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('assigned_to', sa.Integer(), nullable=True),
    sa.Column('sla_due_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('sla_breached', sa.Boolean(), nullable=False),
    sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('resolution', sa.String(length=32), nullable=True),
    sa.Column('resolution_summary', sa.String(length=4000), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['assigned_to'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_cases_sla_breached'), 'cases', ['sla_breached'], unique=False)
    op.create_index(op.f('ix_cases_sla_due_at'), 'cases', ['sla_due_at'], unique=False)
    op.create_table('detection_rules',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('description', sa.String(length=2000), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('mitre_technique_id', sa.String(length=16), nullable=True),
    sa.Column('logic', PortableJSON, nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('eval_watermark', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_evaluated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('alert_count', sa.Integer(), nullable=False),
    sa.Column('created_by', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('iocs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('type', sa.String(length=16), nullable=False),
    sa.Column('value', sa.String(length=1024), nullable=False),
    sa.Column('value_normalized', sa.String(length=1024), nullable=False),
    sa.Column('confidence', sa.Integer(), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('description', sa.String(length=2000), nullable=False),
    sa.Column('tags', PortableJSON, nullable=False),
    sa.Column('feed_id', sa.Integer(), nullable=True),
    sa.Column('source', sa.String(length=128), nullable=False),
    sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('match_count', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['feed_id'], ['threat_intel_feeds.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('type', 'value_normalized', name='uq_ioc_type_value')
    )
    op.create_index(op.f('ix_iocs_active'), 'iocs', ['active'], unique=False)
    op.create_index(op.f('ix_iocs_type'), 'iocs', ['type'], unique=False)
    op.create_index(op.f('ix_iocs_value_normalized'), 'iocs', ['value_normalized'], unique=False)
    op.create_table('alerts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('rule_id', sa.Integer(), nullable=True),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('dedup_key', sa.String(length=128), nullable=False),
    sa.Column('assigned_to', sa.Integer(), nullable=True),
    sa.Column('matched_event_ids', PortableJSON, nullable=False),
    sa.Column('enrichment', PortableJSON, nullable=False),
    sa.Column('first_event_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('sla_due_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('sla_breached', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['assigned_to'], ['users.id'], ),
    sa.ForeignKeyConstraint(['rule_id'], ['detection_rules.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_alerts_dedup_key'), 'alerts', ['dedup_key'], unique=True)
    op.create_index(op.f('ix_alerts_sla_breached'), 'alerts', ['sla_breached'], unique=False)
    op.create_index(op.f('ix_alerts_sla_due_at'), 'alerts', ['sla_due_at'], unique=False)
    op.create_table('case_timeline_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('case_id', sa.Integer(), nullable=False),
    sa.Column('type', sa.String(length=32), nullable=False),
    sa.Column('content', PortableJSON, nullable=False),
    sa.Column('actor', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_case_timeline_events_case_id'), 'case_timeline_events', ['case_id'], unique=False)
    op.create_table('vulnerabilities',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('cve_id', sa.String(length=32), nullable=True),
    sa.Column('title', sa.String(length=512), nullable=False),
    sa.Column('description', sa.String(length=4000), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('cvss_score', sa.Float(), nullable=True),
    sa.Column('cvss_vector', sa.String(length=128), nullable=True),
    sa.Column('solution', sa.String(length=4000), nullable=False),
    sa.Column('port', sa.Integer(), nullable=True),
    sa.Column('protocol', sa.String(length=16), nullable=True),
    sa.Column('scanner', sa.String(length=64), nullable=False),
    sa.Column('remediation_status', sa.String(length=24), nullable=False),
    sa.Column('case_id', sa.Integer(), nullable=True),
    sa.Column('discovered_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('remediated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('raw', PortableJSON, nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('asset_id', 'cve_id', 'title', name='uq_vuln_asset_cve_title')
    )
    op.create_index(op.f('ix_vulnerabilities_asset_id'), 'vulnerabilities', ['asset_id'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_cve_id'), 'vulnerabilities', ['cve_id'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_remediation_status'), 'vulnerabilities', ['remediation_status'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_severity'), 'vulnerabilities', ['severity'], unique=False)
    op.create_table('case_alert_links',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('case_id', sa.Integer(), nullable=False),
    sa.Column('alert_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_case_alert_links_alert_id'), 'case_alert_links', ['alert_id'], unique=False)
    op.create_index(op.f('ix_case_alert_links_case_id'), 'case_alert_links', ['case_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_case_alert_links_case_id'), table_name='case_alert_links')
    op.drop_index(op.f('ix_case_alert_links_alert_id'), table_name='case_alert_links')
    op.drop_table('case_alert_links')
    op.drop_index(op.f('ix_vulnerabilities_severity'), table_name='vulnerabilities')
    op.drop_index(op.f('ix_vulnerabilities_remediation_status'), table_name='vulnerabilities')
    op.drop_index(op.f('ix_vulnerabilities_cve_id'), table_name='vulnerabilities')
    op.drop_index(op.f('ix_vulnerabilities_asset_id'), table_name='vulnerabilities')
    op.drop_table('vulnerabilities')
    op.drop_index(op.f('ix_case_timeline_events_case_id'), table_name='case_timeline_events')
    op.drop_table('case_timeline_events')
    op.drop_index(op.f('ix_alerts_sla_due_at'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_sla_breached'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_dedup_key'), table_name='alerts')
    op.drop_table('alerts')
    op.drop_index(op.f('ix_iocs_value_normalized'), table_name='iocs')
    op.drop_index(op.f('ix_iocs_type'), table_name='iocs')
    op.drop_index(op.f('ix_iocs_active'), table_name='iocs')
    op.drop_table('iocs')
    op.drop_table('detection_rules')
    op.drop_index(op.f('ix_cases_sla_due_at'), table_name='cases')
    op.drop_index(op.f('ix_cases_sla_breached'), table_name='cases')
    op.drop_table('cases')
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
    op.drop_table('threat_intel_feeds')
    op.drop_table('scan_imports')
    op.drop_index(op.f('ix_notification_deliveries_subject_id'), table_name='notification_deliveries')
    op.drop_index(op.f('ix_notification_deliveries_status'), table_name='notification_deliveries')
    op.drop_index(op.f('ix_notification_deliveries_channel_id'), table_name='notification_deliveries')
    op.drop_index(op.f('ix_notification_deliveries_attempted_at'), table_name='notification_deliveries')
    op.drop_table('notification_deliveries')
    op.drop_table('notification_channels')
    op.drop_index(op.f('ix_normalized_events_user_name'), table_name='normalized_events')
    op.drop_index(op.f('ix_normalized_events_threat_matched'), table_name='normalized_events')
    op.drop_index(op.f('ix_normalized_events_source_ip'), table_name='normalized_events')
    op.drop_index(op.f('ix_normalized_events_event_timestamp'), table_name='normalized_events')
    op.drop_index(op.f('ix_normalized_events_event_category'), table_name='normalized_events')
    op.drop_index(op.f('ix_normalized_events_event_action'), table_name='normalized_events')
    op.drop_table('normalized_events')
    op.drop_index(op.f('ix_dead_letter_events_resolved'), table_name='dead_letter_events')
    op.drop_table('dead_letter_events')
    op.drop_index(op.f('ix_compliance_reports_framework'), table_name='compliance_reports')
    op.drop_table('compliance_reports')
    op.drop_index(op.f('ix_compliance_controls_framework'), table_name='compliance_controls')
    op.drop_table('compliance_controls')
    op.drop_table('audit_events')
    op.drop_index(op.f('ix_assets_ip_address'), table_name='assets')
    op.drop_index(op.f('ix_assets_hostname'), table_name='assets')
    op.drop_table('assets')
