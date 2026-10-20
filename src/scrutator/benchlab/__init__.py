"""OSINT-Bench v0: the offline labs and the benchmark behind `scrutator bench`.

Everything here runs without a network: lab zones answered by a status-aware fake resolver, and the public sources
answered by an httpx MockTransport with the shapes the real services use. The same labs back the test suite
(tests/labfix.py, tests/attrlab.py), so a number `scrutator bench` prints is the number the tests assert.

Only reserved names and addresses are used: example.com, example.net and example.org, names under `.test`,
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, and AS numbers from the documentation range."""
