import multiprocessing, os, time
import pytest
from backend import single_instance as si

def test_second_acquire_raises(tmp_path):
    lock = str(tmp_path/"m.lock")
    si.acquire(lock)                      # first holder (this process)
    with pytest.raises(si.AlreadyRunning):
        si.acquire(lock)                  # same process, independent open -> conflicts

def _hold(lock, ready, release):
    si.acquire(lock)
    ready.set()
    release.wait(5)

def test_lock_released_when_holder_dies(tmp_path):
    lock = str(tmp_path/"m.lock")
    ready = multiprocessing.Event(); release = multiprocessing.Event()
    p = multiprocessing.Process(target=_hold, args=(lock, ready, release))
    p.start()
    assert ready.wait(5)
    with pytest.raises(si.AlreadyRunning):   # held by the child
        si.acquire(lock)
    release.set(); p.join(5)
    si.acquire(lock)                          # child gone -> lock is free again
