"""
Shared SQLAlchemy declarative base and portable JSON column type.

FRD ref: FRD-DATA-02 — relational metadata lives in PostgreSQL; several
tables (normalized events, rule logic, audit details) store semi-structured
JSON. In production this maps to native PostgreSQL JSONB; in tests
(SQLite, see backend/tests/conftest.py) it transparently falls back to
SQLAlchemy's generic JSON type so the exact same model/table definitions
run against both engines without special-casing.
"""

from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


# Use JSONB on PostgreSQL, plain JSON everywhere else (e.g. SQLite in tests).
PortableJSON = JSON().with_variant(JSONB(none_as_null=True), "postgresql")
