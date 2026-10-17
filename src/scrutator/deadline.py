import time
from collections.abc import Callable


DEFAULT_DEADLINE_S = 600.0  # what `scan` and `watch` allow a scan unless told otherwise


class Deadline:
    """A wall-clock budget for a whole scan. Everything that waits (module calls, the planner,
    the summary) is given the time that is left, never more."""

    def __init__(self, seconds: float, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.seconds = float(seconds)
        self._clock = clock
        self._end = clock() + self.seconds

    def remaining(self) -> float:
        return max(0.0, self._end - self._clock())

    @property
    def expired(self) -> bool:
        return self._clock() >= self._end
