import json
import os
import subprocess
import tempfile
from typing import Any


def run(target_url: str, config: dict | None = None) -> dict[str, Any]:
    cfg = config or {}
    timeout_seconds = int(cfg.get("timeout_seconds", 600))
    maxtime_seconds = max(30, timeout_seconds - 15)

    fd, output_path = tempfile.mkstemp(suffix=".json", prefix="nikto-")
    os.close(fd)

    args = [
        "nikto",
        "-h",
        target_url,
        "-Format",
        "json",
        "-output",
        output_path,
        "-nointeractive",
        "-maxtime",
        f"{maxtime_seconds}s",
    ]

    if cfg.get("ssl"):
        args.append("-ssl")

    if cfg.get("timeout"):
        args.extend(["-timeout", str(cfg["timeout"])])

    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout_seconds
        )

        parsed: Any = {}
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            with open(output_path, "r") as f:
                file_content = f.read().strip()
            try:
                parsed = json.loads(file_content) if file_content else {}
            except json.JSONDecodeError:
                parsed = {"raw": file_content, "exit_code": result.returncode}
        else:
            parsed = {
                "raw": (result.stdout or result.stderr or "").strip(),
                "exit_code": result.returncode,
            }
    finally:
        if os.path.exists(output_path):
            os.unlink(output_path)

    return {
        "scanner": "nikto",
        "target": target_url,
        "raw": parsed,
        "config": cfg,
    }
