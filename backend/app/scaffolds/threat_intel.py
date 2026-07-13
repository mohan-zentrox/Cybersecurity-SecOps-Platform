"""
SCAFFOLD ONLY — Threat-intel IOC enrichment service.

FRD ref: FRD-TI-01/02/03 (threat intelligence enrichment).

TODO(FRD-TI-01): Define an `IOC` model (indicator value, type — ip/domain/
    hash/url, source feed, confidence, first_seen/last_seen, tags) and a
    migration for it. Consider STIX/TAXII 2.1 as the interchange format
    for external feed ingestion.
TODO(FRD-TI-02): Implement feed pollers (e.g. MISP, AlienVault OTX,
    commercial feeds) behind a `ThreatIntelFeed` interface, mirroring the
    repository-pattern approach used by services/normalizer.py's
    EventStoreRepository, so feeds can be swapped/added independently.
TODO(FRD-TI-03): Implement an enrichment step in the detection pipeline
    (services/rule_engine.py or a new services/enrichment.py) that looks
    up NormalizedEvent.source_ip / destination_ip / hashes against stored
    IOCs and annotates matching events/alerts with `threat.indicator.*`
    ECS fields before/alongside rule evaluation.
TODO(FRD-TI-04): Expose GET /api/v1/threat-intel/iocs and a manual IOC
    upload/import endpoint, role-gated to detection-engineer/admin.
"""

# Intentionally no implementation — see TODOs above.
