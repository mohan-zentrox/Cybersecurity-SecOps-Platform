
from pydantic import BaseModel


class AlertMetrics(BaseModel):
    total: int
    open: int
    closed: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    sla_breached: int
    sla_breach_rate: float
    mttd_minutes: float | None
    mtta_minutes: float | None
    mttr_minutes: float | None
    mttr_p95_minutes: float | None


class CaseMetrics(BaseModel):
    total: int
    open: int
    closed: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_resolution: dict[str, int]
    sla_breached: int
    sla_breach_rate: float
    mttr_minutes: float | None
    mttr_p95_minutes: float | None


class IngestionMetrics(BaseModel):
    events_normalized: int
    events_dead_lettered: int
    dead_letter_rate: float
    events_with_threat_match: int


class DetectionCoverage(BaseModel):
    rules_total: int
    rules_enabled: int
    rules_disabled: int
    mitre_techniques_covered: list[str]
    mitre_technique_count: int


class RuleVolume(BaseModel):
    rule_id: int
    rule_name: str
    severity: str
    alert_count: int


class VolumePoint(BaseModel):
    date: str
    low: int
    medium: int
    high: int
    critical: int
    total: int


class WorkloadEntry(BaseModel):
    user_id: int
    username: str
    role: str
    open_alerts: int
    open_cases: int
    breached_cases: int


class KPISummary(BaseModel):
    window: str
    window_start: str
    window_end: str
    alerts: AlertMetrics
    cases: CaseMetrics
    ingestion: IngestionMetrics
    detection: DetectionCoverage
    top_rules: list[RuleVolume]
    volume_series: list[VolumePoint]
    workload: list[WorkloadEntry]
