"""A tiny local HTTP server that plays an LLM provider, for the BYO tests.

Queue canned replies with ``server.reply(...)``; every request it receives is kept
in ``server.requests`` (path, headers, parsed JSON body) so tests can assert on
exactly what was sent. When the queue is empty it answers 500.
"""
from __future__ import annotations

import json
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeLLMServer:
    def __init__(self):
        self.requests: list[dict] = []
        self._replies: deque = deque()
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):        # keep test output quiet
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw) if raw else None
                except ValueError:
                    body = None
                with outer._lock:
                    outer.requests.append({
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "json": body,
                    })
                    status, headers, payload, delay = (
                        outer._replies.popleft() if outer._replies else (500, {}, b"{}", 0)
                    )
                if delay:
                    time.sleep(delay)
                try:
                    self.send_response(status)
                    for k, v in headers.items():
                        self.send_header(k, v)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    # -- lifecycle ---------------------------------------------------------
    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    # -- scripting ---------------------------------------------------------
    def reply(self, status=200, body=None, *, headers=None, raw: bytes | None = None, delay=0):
        payload = raw if raw is not None else json.dumps(body if body is not None else {}).encode()
        with self._lock:
            self._replies.append((status, headers or {}, payload, delay))

    def reply_openai(self, text='{"verdict":"TP"}', prompt_tokens=11, completion_tokens=7):
        self.reply(200, {
            "choices": [{"message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
        })

    def reply_anthropic(self, text='{"verdict":"TP"}', input_tokens=11, output_tokens=7):
        self.reply(200, {
            "content": [{"type": "text", "text": text}],
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
        })
