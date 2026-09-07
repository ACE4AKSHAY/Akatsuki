"""M3 public entrypoint.

`scan_path(path, scan_target_id, *, image_ref=None) -> list[RawFinding]`
dispatches by file extension/path. If `image_ref` is passed, routes to
`scan_container_image` (NotImplementedError per the plan / roadmap §17).
"""
from __future__ import annotations

from pathlib import Path

from backend.scanners._finding import RawFinding
from backend.scanners.infra.certs import scan_certificates
from backend.scanners.infra.configs import scan_configs
from backend.scanners.infra.container import scan_container_image, scan_dockerfile
from backend.scanners.infra.iac import scan_iac

DOCKERFILE_NAMES = {"dockerfile", "dockerfile.dev", "dockerfile.prod"}


def scan_path(path: str | Path, scan_target_id: str, *, image_ref: str | None = None) -> list[RawFinding]:
    root = Path(path)
    if image_ref:
        scan_container_image(image_ref)  # raises NotImplementedError

    if not root.exists():
        return []

    out: list[RawFinding] = []

    # If path is a directory, walk & dispatch; if a single file, run only that scanner.
    if root.is_file():
        name = root.name.lower()
        if name.startswith("dockerfile") or root.suffix.lower() == ".dockerfile":
            return scan_dockerfile(root, scan_target_id)
        if root.suffix.lower() == ".tf":
            return scan_iac(root, scan_target_id)
        if root.suffix.lower() in (".pem", ".crt", ".cer"):
            return scan_certificates(root, scan_target_id)
        # Fall through: run all scanners — the sub-scanners each filter by their own glob.
    out.extend(scan_dockerfile(root, scan_target_id))
    out.extend(scan_configs(root, scan_target_id))
    out.extend(scan_iac(root, scan_target_id))
    out.extend(scan_certificates(root, scan_target_id))
    return out
