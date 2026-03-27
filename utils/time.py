from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))

def get_ist_time():
    """Return current time in IST (ISO format)."""
    return datetime.now(IST).isoformat()
