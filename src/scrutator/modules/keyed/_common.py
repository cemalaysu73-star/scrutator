import os

from scrutator.modules.base import Module, ModuleError, http_failure


def api_key(module: Module) -> str:
    """The key from the environment, at the moment of the lookup. Never stored, never in a message."""
    key = os.environ.get(module.needs_key or "", "").strip()
    if not key:
        raise ModuleError(f"{module.name} has no key: set {module.needs_key}")
    return key


def failure(source: str, status: int) -> ModuleError:
    """A rejected key is a statement about the key, not a source that is down."""
    if status in (401, 403):
        return ModuleError(f"{source} rejected the key (HTTP {status}): check the environment variable and the plan")
    return http_failure(source, status)
