"""
SCAFFOLD ONLY — SOC KPI dashboards (backend data-aggregation endpoints).

FRD ref: FRD-KPI-01/02 (SOC operational metrics).

TODO(FRD-KPI-01): Implement aggregation queries for standard SOC metrics:
    mean time to detect (MTTD), mean time to respond/resolve (MTTR),
    alert volume by severity/rule, SLA breach rate (using
    Case.sla_due_at vs actual close time — see app/models/case.py), and
    analyst workload (open cases by assigned_to).
TODO(FRD-KPI-02): Expose GET /api/v1/kpis/summary?window=7d (and similar)
    returning pre-aggregated series the frontend/src/pages dashboard can
    render directly — avoid shipping raw row-level data to the client.
TODO(FRD-KPI-03): Consider a materialized view or a scheduled aggregation
    job (rather than computing MTTD/MTTR on every request) once event
    volume makes live aggregation queries expensive; the queue abstraction
    in services/queue.py is a reasonable place to hang a periodic job.
"""

# Intentionally no implementation — see TODOs above.
