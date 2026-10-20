# MCP

`scrutator mcp` serves Scrutator to an MCP client such as Claude Desktop over stdio, using the official
[MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk).

```bash
pip install "scrutator[mcp]"
scrutator mcp --db scrutator-out/scrutator.db                           # read-only tools only
scrutator mcp --db scrutator-out/scrutator.db --scope scope.yaml --allow-scan
scrutator mcp --db scrutator-out/scrutator.db --scope scope.yaml --allow-promote
```

## Tools

| Tool | Offered | What it does |
|---|---|---|
| `list_candidates` | always | names outside the scope that may belong to the organisation, with band and score |
| `attribution` | always | every signal and the evidence behind it, and what could make it wrong |
| `risk` | always | configuration risks of a scan, each citing evidence |
| `verify_bundle` | always | the checks of `scrutator verify` for a `.scrutator` file |
| `scan` | `--allow-scan` | a passive scan of a seed inside your scope file; a seed outside it is refused before anything is looked up; no AI, no active modules |
| `promote_candidate` | `--allow-promote` | accept a candidate into scope; changes nothing unless called with `confirm=true` |

`scan` and `promote_candidate` are not even listed unless you start the server with the flag, and both need `--scope`:
the scope file is the only thing that decides what a scan may touch. All tools carry MCP annotations (`readOnlyHint`,
`destructiveHint`).

## Claude Desktop

Adapt the paths; use the full path to `scrutator` if it is not on `PATH`:

```json
{
  "mcpServers": {
    "scrutator": {
      "command": "scrutator",
      "args": ["mcp", "--db", "C:\\scans\\scrutator.db", "--scope", "C:\\scans\\scope.yaml", "--allow-scan"]
    }
  }
}
```

## What is checked, and what is not

The test suite starts the server as a real subprocess and speaks to it in raw JSON-RPC frames over stdio: the
handshake, the tool list, every tool, refusals, and that stdout carries nothing but protocol frames. The installed
wheel is smoke-tested the same way (initialize, tools/list, `verify_bundle`). It has **not** been run against Claude
Desktop itself; the roadmap criterion "Claude Desktop drives a scan via MCP" needs a manual run.

Security properties, each with a test:

- **Results are untrusted data.** They contain names and text from the investigated organisation's public records.
  Each result says so, and the server instructions tell the client to treat them as data. A client that shows you
  every tool call before it runs is also the human in the loop for `promote_candidate`, which Scrutator cannot check.
- **Scan seeds are checked against the scope before any lookup**: look-alike characters, suffix tricks, userinfo,
  fragments, wildcards, NUL bytes and an IP outside the scope are all refused.
- **`verify_bundle` takes local paths only.** UNC paths (`\\host\share\x.scrutator`) are refused before the file system
  is touched, because on Windows opening one connects to that host with the user's credentials, at the request of a
  client that target data may be steering.
- **No secret reaches the client or its log.** Keyed-source keys are redacted from request logs and errors; the server
  keeps target URLs out of its stderr (the SDK points the root logger at stderr, which clients keep in files).
- **A tool that raises** is reported as an error result with the refusal text; any other exception text stays on the
  server.

## Limits

- The server speaks stdio to one client; there is no authentication layer because there is no network listener.
- A client can still be steered by text in results into calling a tool it was allowed to call. That is why
  `scan` is scope-bound, `promote_candidate` needs `confirm=true`, and neither is on by default.
