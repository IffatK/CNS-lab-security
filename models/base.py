from datetime import datetime, timezone


def utcnow():
    """Naive UTC datetime (SQLite stores naive values)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
