import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from ..models import AuditEvent, ChangeEvent

_SENSITIVE = ("password", "token", "secret", "cookie", "authorization", "api_key")


def scrub(data: dict | None) -> dict:
    """Never persist credentials or other secrets into audit metadata."""
    out = {}
    for key, value in (data or {}).items():
        if any(s in key.lower() for s in _SENSITIVE):
            continue
        out[key] = scrub(value) if isinstance(value, dict) else _jsonable(value)
    return out


def _jsonable(v):
    if isinstance(v, (uuid.UUID,)):
        return str(v)
    if isinstance(v, datetime):
        return v.isoformat()
    if hasattr(v, "isoformat"):
        return v.isoformat()
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return v


def record(
    db: Session,
    org_id: uuid.UUID,
    event_type: str,
    *,
    actor=None,
    object_type: str = "",
    object_id=None,
    metadata: dict | None = None,
) -> AuditEvent:
    """Append an audit event in the caller's transaction (so it commits or rolls back with the action)."""
    event = AuditEvent(
        organization_id=org_id,
        actor_id=getattr(actor, "id", None),
        actor_label=getattr(actor, "email", None) or "system",
        event_type=event_type,
        object_type=object_type,
        object_id=str(object_id) if object_id else "",
        occurred_at=datetime.now(UTC),
        event_metadata=scrub(metadata),
    )
    db.add(event)
    return event


def track_change(db: Session, org_id: uuid.UUID, object_type: str, object_id, action: str, actor, changes: dict) -> None:
    db.add(
        ChangeEvent(
            organization_id=org_id,
            object_type=object_type,
            object_id=object_id,
            action=action,
            actor_id=getattr(actor, "id", None),
            changes=scrub(changes),
        )
    )


def diff(obj, new_values: dict) -> dict:
    """Before/after values for the fields that actually change."""
    changes = {}
    for key, new in new_values.items():
        old = getattr(obj, key, None)
        if _jsonable(old) != _jsonable(new):
            changes[key] = {"from": _jsonable(old), "to": _jsonable(new)}
    return changes
