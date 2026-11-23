"""Fixed child harness. Production executes only in the disposable container."""
import hashlib
import os
import types
import json
import sys

class ArtifactError(Exception):
    pass

try:
    fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as artifact:
        source = artifact.read(16385)
    if len(source) > 16384 or hashlib.sha256(source).hexdigest() != sys.argv[2]:
        raise ArtifactError()
    solution = types.ModuleType("agent_solution")
    # Compile the exact parent-verified source; never reuse workspace bytecode.
    exec(compile(source, sys.argv[1], "exec"), solution.__dict__)
    inputs = json.loads(sys.stdin.read(16385))
    results = []
    for source in inputs:
        try:
            results.append({"ok": solution.summarize_csv(source)})
        except ValueError:
            results.append({"error": "ValueError"})
    print(json.dumps(results, allow_nan=False, sort_keys=True))
except ArtifactError:
    sys.exit(20)
except ImportError:
    sys.exit(21)
except SyntaxError:
    sys.exit(22)
except MemoryError:
    sys.exit(23)
except Exception:
    sys.exit(24)
