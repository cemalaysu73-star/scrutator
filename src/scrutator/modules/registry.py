import importlib
import pkgutil

from scrutator.model import EntityType
from scrutator.modules.base import Mode, Module

_REGISTRY: dict[str, Module] = {}
_SKIP = {"base", "registry"}


def register(cls: type[Module]) -> type[Module]:
    if cls.name in _REGISTRY:
        raise ValueError(f"duplicate module name: {cls.name}")
    _REGISTRY[cls.name] = cls()
    return cls


def registered() -> list[Module]:
    return list(_REGISTRY.values())


def select_modules(
    modules: list[Module], entity_type: EntityType, *, allow_active: bool = False
) -> list[Module]:
    return [
        m
        for m in modules
        if entity_type in m.accepts and (allow_active or m.mode is Mode.PASSIVE)
    ]


def load_builtin_modules() -> list[Module]:
    """Import every module file in the package (each registers itself), then list them."""
    package = importlib.import_module("scrutator.modules")
    for info in pkgutil.iter_modules(package.__path__):
        if info.name.startswith("_") or info.name in _SKIP:
            continue
        importlib.import_module(f"scrutator.modules.{info.name}")
    return registered()
