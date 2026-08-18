"""Single-instance guard.

The monitor runs one collector that ingests from the Goose sessions DB and the
gateway audit log. Running several copies at once (as happened when
``run-monitor.sh`` was launched repeatedly without stopping the previous one)
multiplies CPU/DB contention and races on the shared ingest cursor. This module
enforces exactly one live instance per events-db, regardless of how the process
was started (``run-monitor.sh``, a bare ``uvicorn`` invocation, ``--workers``).

The lock is an ``flock`` on a lockfile; the kernel releases it automatically when
the holding process dies, so a crash never leaves a stale lock behind.
"""
import fcntl, os, sys

class AlreadyRunning(Exception):
    """Raised when another process already holds the instance lock."""

# Hold acquired fds for the whole process lifetime so the lock is never released
# early by garbage collection.
_held = []

def acquire(lockfile):
    """Take the exclusive instance lock. Raise AlreadyRunning if held elsewhere."""
    fd = os.open(lockfile, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as e:
        os.close(fd)
        raise AlreadyRunning(lockfile) from e
    try:
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
    except OSError:
        pass  # pid stamp is informational only
    _held.append(fd)
    return fd

def acquire_or_exit(lockfile):
    """Take the lock or terminate the process with a clear message."""
    try:
        return acquire(lockfile)
    except AlreadyRunning:
        print(f"[monitor] another instance is already running (lock: {lockfile}); "
              f"refusing to start.", file=sys.stderr)
        os._exit(1)
