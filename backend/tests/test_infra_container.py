"""M3 container sub-scanner — Dockerfile & image_ref."""
import pytest

from backend.scanners.infra.container import scan_container_image, scan_dockerfile

DOCKERFILE = """# EXPECTED_FINDINGS: [{"primitive":"pyca/cryptography","category":"key-management","line":3},{"primitive":"node-forge","category":"key-management","line":4}]
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y openssl
RUN pip install pyca/cryptography
RUN npm install node-forge
"""


def test_dockerfile_finds_installed_crypto_libs(tmp_path, scan_target_id):
    p = tmp_path / "Dockerfile"
    p.write_text(DOCKERFILE, encoding="utf-8")
    findings = scan_dockerfile(p, scan_target_id)
    libs = {f.library for f in findings}
    assert "pyca/cryptography" in libs
    assert "node-forge" in libs


def test_dockerfile_reports_base_image(tmp_path, scan_target_id):
    p = tmp_path / "Dockerfile"
    p.write_text("FROM ubuntu:22.04\n", encoding="utf-8")
    findings = scan_dockerfile(p, scan_target_id)
    assert any(f.detectedPrimitive == "base-image" for f in findings)


def test_scan_container_image_raises_not_implemented():
    with pytest.raises(NotImplementedError):
        scan_container_image("alpine:3.18")
