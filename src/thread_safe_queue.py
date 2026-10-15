"""
Thread-safe bounded queue with timeout and shutdown semantics.
File name: thread_safe_queue.py
"""
import queue
from typing import Generic, Optional, TypeVar

T = TypeVar("T")


class ThreadSafeQueue(Generic[T]):
    def __init__(self, max_size: int = 10000):
        self._max_size = max_size
        self._queue: queue.Queue = queue.Queue(maxsize=max_size)
        self._shutdown = False

    def push(self, item: T) -> None:
        if self._shutdown:
            return
        self._queue.put(item)

    def try_push(self, item: T) -> bool:
        if self._shutdown:
            return False
        try:
            self._queue.put_nowait(item)
            return True
        except queue.Full:
            return False

    def pop(self) -> Optional[T]:
        try:
            return self._queue.get()
        except queue.Empty:
            return None

    def pop_with_timeout(self, timeout_sec: float) -> Optional[T]:
        try:
            return self._queue.get(timeout=timeout_sec)
        except queue.Empty:
            return None

    def empty(self) -> bool:
        return self._queue.empty()

    def size(self) -> int:
        return self._queue.qsize()

    def shutdown(self) -> None:
        self._shutdown = True

    def is_shutdown(self) -> bool:
        return self._shutdown