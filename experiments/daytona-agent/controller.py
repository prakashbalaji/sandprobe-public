"""RUN-10: trusted protocol adapter; never executes generated code on the host."""
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("coding", ROOT / "experiments/eks-agent/coding.py")
coding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coding)

def main():
    mode = sys.argv[1]
    model = sys.argv[2] if len(sys.argv) == 3 else "mistral.ministral-3-3b-instruct"
    if len(sys.argv) not in (2, 3) or model not in {"mistral.ministral-3-3b-instruct", "mistral.ministral-3-8b-instruct"}:
        raise ValueError()
    raw = sys.stdin.buffer.read(131073)
    if len(raw) > 131072:
        raise ValueError()
    value = coding.strict(raw.decode(), 131072) if raw else {}
    if mode == "request":
        messages = [{"role": "user", "content": [{"text": coding.PROMPT}]}]
        if value:
            if set(value) != {"previous", "verification"} or not isinstance(value["previous"], str) or len(value["previous"].encode()) > 16384:
                raise ValueError()
            feedback = coding.repair_feedback(value["verification"])
            messages.extend([{"role": "assistant", "content": [{"text": value["previous"]}]},
                             {"role": "user", "content": [{"text": feedback}]}])
        return coding.converse_request(model, messages)
    if mode == "diagnostic":
        return coding.validated_verification_diagnostic(value)
    if mode == "parse":
        blocks = value["output"]["message"]["content"]
        if len(blocks) != 1 or set(blocks[0]) != {"text"}:
            raise ValueError()
        text = blocks[0]["text"]
        doc = coding.model_document(text)
        if set(doc) != {"solution.py"} or not isinstance(doc["solution.py"], str) or not doc["solution.py"] or len(doc["solution.py"].encode()) > 16384:
            raise ValueError()
        return {"source": doc["solution.py"], "previous": text}
    raise ValueError()

if __name__ == "__main__":
    try:
        print(json.dumps(main()))
    except Exception:
        print('{"error":"controller_protocol_failed"}')
        raise SystemExit(1)
