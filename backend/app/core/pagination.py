"""
Shared pagination primitives.

FRD ref: NFR-API-02 — list endpoints must never return an unbounded result
set. Every collection endpoint takes `limit`/`offset` and returns a
`Page[T]` envelope carrying the total row count so the console can render
pager controls without a second round trip.
"""

from typing import Generic, TypeVar

from fastapi import Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Query as OrmQuery
from sqlalchemy.orm import Session

from app.core.config import get_settings

T = TypeVar("T")

_settings = get_settings()


class PageParams(BaseModel):
    limit: int
    offset: int


def page_params(
    limit: int = Query(default=_settings.DEFAULT_PAGE_SIZE, ge=1, le=_settings.MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
) -> PageParams:
    """FastAPI dependency supplying validated limit/offset."""
    return PageParams(limit=limit, offset=offset)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


def paginate(db: Session, query: OrmQuery, params: PageParams) -> tuple[list, int]:
    """Return (rows, total) for an ORM query, applying limit/offset to the rows only."""
    total = db.execute(select(func.count()).select_from(query.order_by(None).subquery())).scalar_one()
    rows = query.limit(params.limit).offset(params.offset).all()
    return rows, total
