"""`scrutator audit`: a client deliverable made from a signed scan.

The audit is a document a consultant hands to a client: a cover, the authorisation it rests on, an executive summary in
plain language, the risks in priority order with remediation, the asset inventory, what was not tested, the
methodology, a glossary and an evidence appendix that tells the client (or their auditor) how to check the report
offline. Every statement about the client's infrastructure cites evidence records of the signed bundle, and
`scrutator audit-check` re-derives the whole document from that bundle.
"""

from scrutator.audit.content import AuditError, build_audit
from scrutator.audit.render import render_audit

__all__ = ["AuditError", "build_audit", "render_audit"]
