"""
PatchVerify — behavioral probe framework
Tests Python and Node.js packages for fix effectiveness at runtime.
Only applies to importable/runnable packages, not compiled binaries.
"""
import subprocess
import sys
import tempfile
import os
import tracemalloc
from cli.config import C
from cli.streamer import emit

# Probe templates per bug class
PROBES = {
    "buffer_overflow": {
        "description": "Sending oversized input (10,000 chars) to common parsing functions",
        "python_code": """
import sys
import importlib
import traceback

pkg = sys.argv[1]
try:
    mod = importlib.import_module(pkg)
except ImportError:
    print("IMPORT_ERROR")
    sys.exit(0)

oversized = "A" * 10000
crashed = False
for attr_name in dir(mod):
    if attr_name.startswith('_'):
        continue
    attr = getattr(mod, attr_name, None)
    if callable(attr):
        try:
            attr(oversized)
        except (TypeError, ValueError, AttributeError):
            pass  # graceful handling
        except Exception as e:
            crashed = True
            print(f"CRASH:{attr_name}:{type(e).__name__}")
            break

if not crashed:
    print("HANDLED")
""",
    },
    "memory_leak": {
        "description": "Running 500 iterations and monitoring memory growth via tracemalloc",
        "python_code": """
import sys
import importlib
import tracemalloc
import gc

pkg = sys.argv[1]
try:
    mod = importlib.import_module(pkg)
except ImportError:
    print("IMPORT_ERROR")
    sys.exit(0)

tracemalloc.start()
snap1 = tracemalloc.take_snapshot()

callables = [getattr(mod, a) for a in dir(mod) if not a.startswith('_') and callable(getattr(mod, a, None))]
for i in range(500):
    for fn in callables[:3]:
        try:
            fn()
        except Exception:
            pass
gc.collect()
snap2 = tracemalloc.take_snapshot()
tracemalloc.stop()

stats = snap2.compare_to(snap1, 'lineno')
total_increase = sum(s.size_diff for s in stats if s.size_diff > 0)

# More than 10MB growth = potential leak
if total_increase > 10 * 1024 * 1024:
    print(f"LEAK:{total_increase}")
else:
    print(f"STABLE:{total_increase}")
""",
    },
    "input_validation": {
        "description": "Testing with boundary inputs: empty string, null bytes, SQL patterns",
        "python_code": """
import sys
import importlib

pkg = sys.argv[1]
try:
    mod = importlib.import_module(pkg)
except ImportError:
    print("IMPORT_ERROR")
    sys.exit(0)

malicious_inputs = [
    "",
    "\\x00" * 100,
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "\\n\\r\\t" * 100,
]

unhandled = []
callables = [getattr(mod, a) for a in dir(mod) if not a.startswith('_') and callable(getattr(mod, a, None))]

for inp in malicious_inputs:
    for fn in callables[:5]:
        try:
            result = fn(inp)
            # If it returned without error, check if it sanitized
            if isinstance(result, str) and ("<script>" in result or "OR '1'='1" in result):
                unhandled.append(f"{fn.__name__}:passthrough")
        except (TypeError, ValueError, AttributeError):
            pass  # Properly rejecting
        except Exception as e:
            unhandled.append(f"{fn.__name__}:{type(e).__name__}")

if unhandled:
    print(f"UNHANDLED:{','.join(unhandled[:3])}")
else:
    print("VALIDATED")
""",
    },
    "integer_overflow": {
        "description": "Testing with MAX_INT and boundary values",
        "python_code": """
import sys
import importlib

pkg = sys.argv[1]
try:
    mod = importlib.import_module(pkg)
except ImportError:
    print("IMPORT_ERROR")
    sys.exit(0)

MAX_INT = 2**31 - 1
boundary_inputs = [MAX_INT, MAX_INT + 1, -MAX_INT - 1, 0, -1]

overflows = []
callables = [getattr(mod, a) for a in dir(mod) if not a.startswith('_') and callable(getattr(mod, a, None))]

for val in boundary_inputs:
    for fn in callables[:5]:
        try:
            result = fn(val)
            if isinstance(result, int) and result < 0 and val > 0:
                overflows.append(f"{fn.__name__}:wrapped")
        except (TypeError, ValueError, OverflowError, AttributeError):
            pass  # Properly handled
        except Exception as e:
            overflows.append(f"{fn.__name__}:{type(e).__name__}")

if overflows:
    print(f"OVERFLOW:{','.join(overflows[:3])}")
else:
    print("HANDLED")
""",
    },
    "denial_of_service": {
        "description": "Testing with inputs designed to cause hangs or excessive computation",
        "python_code": """
import sys
import importlib
import signal

pkg = sys.argv[1]
try:
    mod = importlib.import_module(pkg)
except ImportError:
    print("IMPORT_ERROR")
    sys.exit(0)

# Nested/recursive inputs
dos_inputs = [
    "A" * 100000,
    "(" * 1000 + ")" * 1000,
    "{" * 500 + "}" * 500,
]

issues = []
callables = [getattr(mod, a) for a in dir(mod) if not a.startswith('_') and callable(getattr(mod, a, None))]

for inp in dos_inputs:
    for fn in callables[:3]:
        try:
            fn(inp)
        except (TypeError, ValueError, RecursionError, AttributeError):
            pass
        except Exception as e:
            issues.append(f"{fn.__name__}:{type(e).__name__}")

if issues:
    print(f"ISSUE:{','.join(issues[:3])}")
else:
    print("HANDLED")
""",
    },
}


def run_probe(package_name: str, version: str, bug_class: str, ecosystem: str) -> dict:
    """
    Run a behavioral probe for a specific bug class against a package version.
    Installs the package version in a temp venv and runs the probe script.
    Only works for PyPI packages.
    """
    if ecosystem != "PyPI":
        return {
            "ran":    False,
            "reason": f"Behavioral probing only supported for PyPI packages (ecosystem: {ecosystem})."
        }

    probe = PROBES.get(bug_class)
    if not probe:
        return {
            "ran":    False,
            "reason": f"No probe defined for bug class '{bug_class}'."
        }

    emit(f"    {C.GRAY}→ Probe: {probe['description']}{C.RESET}")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write probe script
        probe_script = os.path.join(tmpdir, "probe.py")
        with open(probe_script, 'w') as f:
            f.write(probe["python_code"])

        # Install the specific version in temp dir
        install_result = subprocess.run(
            [sys.executable, "-m", "pip", "install",
             f"{package_name}=={version}",
             "--target", tmpdir, "--quiet", "--break-system-packages"],
            capture_output=True, text=True, timeout=120
        )

        if install_result.returncode != 0:
            return {
                "ran":    False,
                "reason": f"Could not install {package_name}=={version} for probing."
            }

        # Run probe with timeout
        env = os.environ.copy()
        env["PYTHONPATH"] = tmpdir

        try:
            result = subprocess.run(
                [sys.executable, probe_script, package_name],
                capture_output=True, text=True,
                timeout=30, env=env
            )
            output = result.stdout.strip()
            return _interpret_probe_output(output, bug_class, version)
        except subprocess.TimeoutExpired:
            return {
                "ran":     True,
                "result":  "TIMEOUT",
                "message": "Probe timed out (>30s) — possible hang or DoS vulnerability.",
                "passed":  False,
            }
        except Exception as e:
            return {
                "ran":    False,
                "reason": f"Probe execution error: {e}"
            }


def _interpret_probe_output(output: str, bug_class: str, version: str) -> dict:
    """Interpret probe script output into a structured result."""
    if output == "IMPORT_ERROR":
        return {"ran": False, "reason": "Package could not be imported (may be a CLI tool, not a library)."}

    if bug_class == "buffer_overflow":
        if output.startswith("CRASH:"):
            return {"ran": True, "result": "CRASH", "message": f"Crashed on oversized input: {output}", "passed": False}
        elif output == "HANDLED":
            return {"ran": True, "result": "HANDLED", "message": "Handled oversized input gracefully.", "passed": True}

    elif bug_class == "memory_leak":
        if output.startswith("LEAK:"):
            size = output.split(":")[1] if ":" in output else "?"
            return {"ran": True, "result": "LEAK", "message": f"Memory grew by {int(size)//1024//1024}MB — possible leak.", "passed": False}
        elif output.startswith("STABLE:"):
            return {"ran": True, "result": "STABLE", "message": "Memory remained stable across 500 iterations.", "passed": True}

    elif bug_class == "input_validation":
        if output.startswith("UNHANDLED:"):
            return {"ran": True, "result": "UNHANDLED", "message": f"Unhandled malicious input: {output}", "passed": False}
        elif output == "VALIDATED":
            return {"ran": True, "result": "VALIDATED", "message": "Malicious inputs handled correctly.", "passed": True}

    elif bug_class == "integer_overflow":
        if output.startswith("OVERFLOW:"):
            return {"ran": True, "result": "OVERFLOW", "message": f"Integer overflow detected: {output}", "passed": False}
        elif output == "HANDLED":
            return {"ran": True, "result": "HANDLED", "message": "Boundary integers handled correctly.", "passed": True}

    elif bug_class == "denial_of_service":
        if output.startswith("ISSUE:"):
            return {"ran": True, "result": "ISSUE", "message": f"DoS-like behavior detected: {output}", "passed": False}
        elif output == "HANDLED":
            return {"ran": True, "result": "HANDLED", "message": "Large inputs handled without hanging.", "passed": True}

    return {"ran": True, "result": "UNKNOWN", "message": f"Probe output: {output}", "passed": None}
