"""`audit.yaml`: the auditor's brand on the deliverable.

    auditor: Example Security Consulting      # shown on the cover and in the executive summary
    contact: audits@example.com · +90 212 000 00 00
    logo: logo.png                            # PNG or JPEG, at most 512 KiB; SVG is refused (it can carry script)
    colours: {primary: "#1f3a5f", accent: "#2f7d5b"}
    language: en                              # or tr
    client: Example Corp                      # optional; the engagement's organisation is used when there is one

Everything in this file is treated as hostile input to the HTML: text is escaped where it is placed, colours must be
#rrggbb, the logo must be a PNG or JPEG by its first bytes and is embedded as a base64 data URI. Nothing from it is ever
placed inside the style sheet except the two validated colours.
"""

import base64
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

MAX_YAML = 32 * 1024
MAX_LOGO = 512 * 1024
_HEX = re.compile(r"^#[0-9a-fA-F]{6}$")
DEFAULT_PRIMARY = "#1f3a5f"
DEFAULT_ACCENT = "#2f6f4f"


class BrandingError(ValueError):
    """audit.yaml is unreadable or invalid."""


class Colours(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    primary: str = DEFAULT_PRIMARY
    accent: str = DEFAULT_ACCENT

    @field_validator("primary", "accent")
    @classmethod
    def _hex(cls, value: str) -> str:
        if not _HEX.match(str(value)):
            raise ValueError("a colour must look like #1f3a5f")
        return str(value).lower()


class BrandingFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    auditor: str = Field(default="", max_length=120)
    contact: str = Field(default="", max_length=240)
    logo: str = Field(default="", max_length=400)
    colours: Colours = Colours()
    language: str = "en"
    client: str = Field(default="", max_length=200)

    @field_validator("language")
    @classmethod
    def _language(cls, value: str) -> str:
        if value not in ("en", "tr"):
            raise ValueError("language must be en or tr")
        return value


@dataclass(frozen=True)
class Branding:
    auditor: str = ""
    contact: str = ""
    client: str = ""
    language: str = "en"
    primary: str = DEFAULT_PRIMARY
    accent: str = DEFAULT_ACCENT
    logo_data_uri: str = ""  # data:image/png;base64,... or ""
    logo_sha256: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "auditor": self.auditor, "contact": self.contact, "client": self.client, "language": self.language,
            "primary": self.primary, "accent": self.accent, "logo_data_uri": self.logo_data_uri, "logo_sha256": self.logo_sha256,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Branding":
        """Rebuild from an audit's embedded record, validating it again (audit-check reads untrusted HTML)."""
        if not isinstance(data, dict):
            raise BrandingError("branding record is not an object")
        checked = BrandingFile.model_validate({k: data.get(k, "") for k in ("auditor", "contact", "client")} | {
            "colours": {"primary": data.get("primary", DEFAULT_PRIMARY), "accent": data.get("accent", DEFAULT_ACCENT)},
            "language": data.get("language", "en"),
        })
        uri = str(data.get("logo_data_uri") or "")
        if uri and not re.fullmatch(r"data:image/(png|jpeg);base64,[A-Za-z0-9+/=]+", uri):
            raise BrandingError("the embedded logo is not a PNG or JPEG data URI")
        return cls(checked.auditor, checked.contact, checked.client, checked.language, checked.colours.primary,
                   checked.colours.accent, uri, str(data.get("logo_sha256") or "")[:64])


def _clean(text: str) -> str:
    """Control and bidirectional-override characters dropped; the rest is escaped where it is placed."""
    return "".join(ch for ch in str(text) if ch in "\n\t" or (ord(ch) >= 32 and ch not in "‪‫‬‭‮⁦⁧⁨⁩‎‏")).strip()


def _logo(path: Path) -> tuple[str, str]:
    import hashlib

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise BrandingError(f"cannot read the logo {path}: {exc.strerror or exc}") from exc
    if len(data) > MAX_LOGO:
        raise BrandingError("the logo is larger than 512 KiB")
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        kind = "png"
    elif data.startswith(b"\xff\xd8\xff"):
        kind = "jpeg"
    else:
        raise BrandingError("the logo must be a PNG or JPEG file (SVG is refused: it can carry script)")
    return f"data:image/{kind};base64," + base64.b64encode(data).decode("ascii"), hashlib.sha256(data).hexdigest()


def load_branding(path: str | Path | None, *, language: str | None = None) -> Branding:
    """Read audit.yaml (or the defaults when there is none). `language` overrides the file's."""
    if path is None:
        return Branding(language=language or "en")
    target = Path(path)
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise BrandingError(f"cannot read {target}: {exc.strerror or exc}") from exc
    if len(raw) > MAX_YAML:
        raise BrandingError(f"{target.name} is larger than 32 KiB")
    try:
        document = yaml.safe_load(raw.decode("utf-8")) or {}
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise BrandingError(f"{target.name} is not readable YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise BrandingError(f"{target.name} must be a mapping")
    try:
        parsed = BrandingFile.model_validate(document)
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(str(p) for p in e['loc']) or 'file'}: {e['msg']}" for e in exc.errors()[:5])
        raise BrandingError(f"{target.name} is not valid: {problems}") from exc
    uri, digest = "", ""
    if parsed.logo:
        logo = Path(parsed.logo)
        uri, digest = _logo(logo if logo.is_absolute() else target.parent / logo)
    lang = language or parsed.language
    if lang not in ("en", "tr"):
        raise BrandingError("language must be en or tr")
    return Branding(_clean(parsed.auditor), _clean(parsed.contact), _clean(parsed.client), lang,
                    parsed.colours.primary, parsed.colours.accent, uri, digest)
