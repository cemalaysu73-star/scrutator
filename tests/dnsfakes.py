"""A status-aware resolver for tests: it knows why an answer is empty. It lives in the package (scrutator.benchlab),
where `scrutator bench` uses it too."""

from scrutator.benchlab.fakes import StatusResolver

__all__ = ["StatusResolver"]
