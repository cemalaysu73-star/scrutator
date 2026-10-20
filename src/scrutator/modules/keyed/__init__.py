"""Sources that need an API key. Off unless the environment variable named by `needs_key` is set (see
`scrutator.keys` for the rules), and not replayable: a replay would need your key.

Implemented against each service's documented API, NOT live-verified: the author had no keys and, by rule,
did not create accounts to get one. Their tests use a fake HTTP transport that returns the documented
response shapes. Treat the first real run as the real test.

Censys is not here: its search API is being replaced by a new platform API, so there is no stable,
documented shape to implement against yet."""

from scrutator.modules.keyed import securitytrails, shodan, virustotal  # noqa: F401  (each registers itself)
