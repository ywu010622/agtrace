"""agtrace event emitter for LangChain / LangGraph.

A ~60-line callback handler: append it to your agent's callbacks and point
agtrace at the file it writes:

    from langchain_callback import AgtraceCallbackHandler
    handler = AgtraceCallbackHandler("/tmp/agtrace-events.jsonl")
    agent = create_react_agent(model, tools, callbacks=[handler])

    # in another terminal (the agent's PID):
    sudo agtrace --adapter jsonl -S /tmp/agtrace-events.jsonl -p <pid> -f

For LangGraph, the same handler works via ``graph.with_config({"callbacks": [handler]})``.
For the input schema, see ``src/adapter/jsonl.rs``.

Run ``python3 langchain_callback.py --self-test`` to emit a fake session without
installing langchain (useful to check the JSONL shape).
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import uuid

DEFAULT_PATH = "/tmp/agtrace-events.jsonl"


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class AgtraceCallbackHandler:
    """LangChain callback handler that emits agtrace JSONL events.

    Only the methods below are needed; everything else is a no-op. All methods
    are defensive about missing fields -- a callback must never break the agent.
    """

    def __init__(self, path: str = DEFAULT_PATH, session_id: str | None = None):
        self.path = path
        self.session_id = session_id or uuid.uuid4().hex[:8]
        self._f = open(path, "a", buffering=1)

    def _emit(self, obj: dict) -> None:
        try:
            obj.setdefault("ts", _now_iso())
            obj.setdefault("session_id", self.session_id)
            self._f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        except Exception:
            pass  # never break the agent

    def on_chat_model_start(self, serialized, messages, *, run_id, **kw):
        self.on_llm_start(serialized, messages, run_id=run_id, **kw)

    def on_llm_start(self, serialized, prompts, *, run_id, **kw):
        ser = serialized or {}
        name = ser.get("name") or (ser.get("id") or ["?"])[-1]
        self._emit({"type": "model.request", "model": str(name)})

    def on_llm_end(self, response, *, run_id, **kw):
        text, usage, model_name = "", {}, None
        try:
            gens = (response.generations or [[]])[0]
            text = gens[0].text if gens else ""
            out = response.llm_output or {}
            usage = out.get("token_usage", {}) or {}
            model_name = out.get("model_name")
        except Exception:
            pass
        if text:
            self._emit({"type": "model.text", "text": text[:4000]})
        if usage:
            self._emit({
                "type": "model.usage",
                "model": model_name,
                "input_tokens": usage.get("prompt_tokens"),
                "output_tokens": usage.get("completion_tokens"),
            })

    def on_tool_start(self, serialized, input_str, *, run_id, **kw):
        name = (serialized or {}).get("name", "?")
        self._emit({
            "type": "tool.call",
            "id": str(run_id),
            "tool": str(name),
            "command": self._shell_command(str(name), input_str),
            "input": str(input_str)[:4000],
        })

    def on_tool_end(self, output, *, run_id, **kw):
        self._emit({
            "type": "tool.result",
            "id": str(run_id),
            "status": "error" if kw.get("error") else "success",
            "output": str(output)[:4000],
        })

    def on_chain_start(self, serialized, inputs, *, run_id, **kw):
        name = (serialized or {}).get("name", "")
        if "agent" in name.lower():
            text = inputs.get("input", "") if isinstance(inputs, dict) else str(inputs)
            if text:
                self._emit({"type": "prompt", "text": str(text)[:4000]})

    @staticmethod
    def _shell_command(tool_name: str, input_str: str):
        """Extract the shell command so agtrace can bind tool.call <-> exec."""
        if "shell" not in tool_name.lower() and "bash" not in tool_name.lower():
            return None
        try:
            obj = json.loads(input_str)
            if isinstance(obj, dict):
                for k in ("command", "cmd", "input"):
                    if obj.get(k):
                        return str(obj[k])
        except Exception:
            pass
        return input_str or None


def _self_test(path: str) -> None:
    """Emit a fake session without langchain -- checks the JSONL shape."""
    h = AgtraceCallbackHandler.__new__(AgtraceCallbackHandler)
    h.path, h.session_id = path, "selftest"
    h._f = open(path, "w", buffering=1)
    rid = uuid.uuid4()
    h._emit({"type": "prompt", "text": "list /tmp and report disk usage"})
    h.on_llm_start({"name": "gpt-4o"}, ["list /tmp"], run_id=rid)
    h.on_tool_start({"name": "ShellTool"}, '{"command": "ls /tmp"}', run_id=rid)
    h.on_tool_end("a\nb\nc", run_id=rid)
    bad = uuid.uuid4()
    h.on_tool_start({"name": "ShellTool"}, '{"command": "foobarxyz --version"}', run_id=bad)
    h.on_tool_end("command not found", run_id=bad, error=True)
    print("wrote " + path)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--path", default=DEFAULT_PATH)
    args = ap.parse_args()
    if args.self_test:
        _self_test(args.path)
    else:
        try:
            from langchain_core.callbacks import BaseCallbackHandler  # noqa
        except ImportError:
            sys.exit("pip install langchain-core  (or run with --self-test)")
        print("import AgtraceCallbackHandler from this file and add it to your callbacks")
