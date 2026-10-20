"""Installs tests/records_audit.py's audit hook in every Python process started with this
directory on PYTHONPATH and AGENTOS_RECORD_LOG set (CI-PATHS). A failed install is logged, so the
check fails rather than missing reads."""
import os

if os.environ.get("AGENTOS_RECORD_LOG"):
    try:
        import importlib.util
        import sys

        _path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "records_audit.py")
        _spec = importlib.util.spec_from_file_location("records_audit", _path)
        _module = importlib.util.module_from_spec(_spec)
        sys.modules["records_audit"] = _module
        _spec.loader.exec_module(_module)
        _module.install()
    except Exception as e:  # noqa: BLE001
        with open(os.environ["AGENTOS_RECORD_LOG"], "a") as f:
            f.write(f"error\tsitecustomize: {e!r}\n")
