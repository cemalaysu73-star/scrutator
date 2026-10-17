"""A minimal MCP client for the tests: it starts `python -m scrutator mcp` as a real subprocess and
speaks to it in newline-delimited JSON-RPC frames over stdio, the way Claude Desktop does. Nothing
here uses the MCP SDK, so a server bug cannot hide behind a client that shares it."""

import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import scrutator

SRC = Path(scrutator.__file__).parents[1]


class Client:
    def __init__(self, *args, cwd=None):
        env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, [str(SRC), os.environ.get("PYTHONPATH", "")]))}
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "scrutator", "mcp", *[str(a) for a in args]],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=str(cwd) if cwd else None,
        )
        self.frames: queue.Queue = queue.Queue()
        self.raw: list[str] = []  # every line the server wrote to stdout
        self.errors = b""
        self._next = 1
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._drain, daemon=True).start()

    def _read(self):
        for line in self.proc.stdout:
            text = line.decode("utf-8").strip()
            if text:
                self.raw.append(text)
                self.frames.put(text)
        self.frames.put(None)

    def _drain(self):
        self.errors = self.proc.stderr.read()

    def send(self, message: dict) -> None:
        self.proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def notify(self, method: str, params: dict | None = None) -> None:
        self.send({"jsonrpc": "2.0", "method": method, **({"params": params} if params is not None else {})})

    def request(self, method: str, params: dict | None = None, *, timeout: float = 40.0) -> dict:
        ident = self._next
        self._next += 1
        self.send({"jsonrpc": "2.0", "id": ident, "method": method, **({"params": params} if params is not None else {})})
        while True:
            try:
                text = self.frames.get(timeout=timeout)
            except queue.Empty:
                raise TimeoutError(f"no answer to {method} within {timeout}s; stderr so far: {self.errors[-500:]!r}") from None
            if text is None:
                raise EOFError(f"the server closed stdout during {method}; stderr: {self.errors[-800:]!r}")
            message = json.loads(text)
            if message.get("id") == ident:
                return message

    def initialize(self) -> dict:
        answer = self.request(
            "initialize",
            {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "scrutator-tests", "version": "0"}},
        )
        self.notify("notifications/initialized")
        return answer["result"]

    def tools(self) -> dict[str, dict]:
        return {tool["name"]: tool for tool in self.request("tools/list")["result"]["tools"]}

    def call(self, name: str, arguments: dict | None = None) -> dict:
        """The raw reply to tools/call: `result` (with isError) or a JSON-RPC `error`."""
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})

    def data(self, name: str, arguments: dict | None = None) -> dict:
        """A successful tool call, parsed: the JSON the tool returned."""
        reply = self.call(name, arguments)
        result = reply["result"]
        assert result["isError"] is False, result
        return json.loads(result["content"][0]["text"])

    def close(self, timeout: float = 20.0) -> int:
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            raise
