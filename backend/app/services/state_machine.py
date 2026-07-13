"""
Shared status state machine for Alerts and Cases.

FRD ref: FRD-ALERT-03 / FRD-CASE-03 — status transitions must follow
new -> investigating -> (closed | escalated), with escalated allowed to
return to investigating or move to closed. `closed` is terminal. Any
transition not present in ALLOWED_TRANSITIONS is rejected; callers turn
InvalidTransitionError into an HTTP 400.
"""

NEW = "new"
INVESTIGATING = "investigating"
CLOSED = "closed"
ESCALATED = "escalated"

ALL_STATUSES = (NEW, INVESTIGATING, CLOSED, ESCALATED)

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    NEW: {INVESTIGATING},
    INVESTIGATING: {CLOSED, ESCALATED},
    ESCALATED: {INVESTIGATING, CLOSED},
    CLOSED: set(),
}


class InvalidTransitionError(Exception):
    def __init__(self, current: str, target: str):
        self.current = current
        self.target = target
        super().__init__(f"Invalid status transition: '{current}' -> '{target}'")


def validate_transition(current_status: str, target_status: str) -> None:
    if current_status not in ALLOWED_TRANSITIONS:
        raise InvalidTransitionError(current_status, target_status)
    if target_status not in ALLOWED_TRANSITIONS[current_status]:
        raise InvalidTransitionError(current_status, target_status)
