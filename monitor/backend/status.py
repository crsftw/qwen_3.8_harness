def compute_status(last_activity_ms, now_ms, active_window_s, idle_window_s, last_error, has_open_alert):
    if last_error or has_open_alert:
        return "ERROR"
    if last_activity_ms is None:
        return "COMPLETED"
    age_s = (now_ms - last_activity_ms)/1000.0
    if age_s <= active_window_s: return "ACTIVE"
    if age_s <= idle_window_s: return "IDLE"
    return "COMPLETED"
