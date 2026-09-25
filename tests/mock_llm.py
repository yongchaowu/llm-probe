#!/usr/bin/env python3
"""OpenAI 兼容端点 mock，用于 llm_probe 的分支测试。

MOCK_MODE:
  ok           正常（密钥必须是 sk-good）
  unauthorized 所有请求 401
  badpath      /models 与 /chat/completions 都 404
  badmodel     /models 正常，/chat 返回 400（模型不存在）
  ratelimit    /models 正常，/chat 返回 429
  noreduce     /models 404，/chat 正常（模拟不实现 models 的中转站）
  checkmaxtokens /chat 只接受 max_tokens=7（用来验证"命令行 > 环境变量 > 配置"
                的优先级真的上了线，而不是只改了本地变量）
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = os.environ.get("MOCK_MODE", "ok")
PORT = int(os.environ.get("MOCK_PORT", "18923"))
GOOD_KEY = "sk-good"


class Handler(BaseHTTPRequestHandler):
    server_version = "MockLLM/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[mock:%s] %s\n" % (MODE, fmt % args))

    def _send(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        return self.headers.get("Authorization") == f"Bearer {GOOD_KEY}"

    def do_GET(self):
        path = self.path.split("?")[0]
        if MODE == "badpath" or (MODE == "noreduce" and path.endswith("/models")):
            return self._send(404, {"error": {"message": "no such path", "type": "not_found"}})
        if path.endswith("/models"):
            if MODE == "unauthorized" or not self._authed():
                return self._send(401, {"error": {"message": "无效的令牌", "type": "auth"}})
            return self._send(200, {
                "object": "list",
                "data": [
                    {"id": "mock-a", "object": "model"},
                    {"id": "mock-b", "object": "model"},
                    {"id": "mock-c", "object": "model"},
                ],
            })
        return self._send(404, {"error": {"message": "no such path"}})

    def do_POST(self):
        path = self.path.split("?")[0]
        if not path.endswith("/chat/completions"):
            return self._send(404, {"error": {"message": "no such path"}})
        if MODE == "badpath":
            return self._send(404, {"error": {"message": "no such path"}})
        if MODE == "unauthorized" or not self._authed():
            return self._send(401, {"error": {"message": "无效的令牌", "type": "auth"}})
        if MODE == "ratelimit":
            return self._send(429, {"error": {"message": "rate limit exceeded", "type": "rate"}})
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw)
        except Exception:
            req = {}
        model = req.get("model", "?")
        if MODE == "badmodel":
            return self._send(400, {"error": {
                "message": f"model `{model}` does not exist", "type": "invalid_request"}})
        if MODE == "checkmaxtokens" and req.get("max_tokens") != 7:
            return self._send(400, {"error": {
                "message": f"max_tokens 期望 7，实际 {req.get('max_tokens')!r}",
                "type": "invalid_request"}})
        prompt = ""
        for msg in req.get("messages", []):
            if msg.get("role") == "user":
                prompt = msg.get("content", "")
        return self._send(200, {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant",
                            "content": f"mock 回复：收到「{prompt}」"},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 7, "completion_tokens": 11, "total_tokens": 18},
        })


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"mock listening 127.0.0.1:{PORT} mode={MODE}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
