"""M2 manifest parsers — 4 ecosystems."""
from pathlib import Path

from backend.scanners.binary_deps.manifests import (
    parse_go_mod,
    parse_package_json,
    parse_pom_xml,
    parse_requirements_txt,
)

SEED = Path(__file__).resolve().parents[2] / "seed_corpus" / "manifests"


def test_requirements_txt(scan_target_id):
    f = parse_requirements_txt(SEED / "requirements.txt", scan_target_id)
    libs = {x.library for x in f}
    assert "pyca/cryptography" in libs
    assert "PyCryptodome" in libs


def test_package_json(scan_target_id):
    f = parse_package_json(SEED / "package.json", scan_target_id)
    libs = {x.library for x in f}
    assert "node-forge" in libs
    assert "jsonwebtoken" in libs


def test_go_mod(scan_target_id):
    f = parse_go_mod(SEED / "go.mod", scan_target_id)
    libs = {x.library for x in f}
    assert "golang.org/x/crypto" in libs


def test_pom_xml(scan_target_id):
    f = parse_pom_xml(SEED / "pom.xml", scan_target_id)
    libs = {x.library for x in f}
    assert "Bouncy Castle" in libs


def test_harmless_libs_ignored(scan_target_id):
    """`requests`, `lodash`, `guava`, `echo` are in the registry with empty
    `algorithms` — they must NOT produce findings (precision gate)."""
    req = parse_requirements_txt(SEED / "requirements.txt", scan_target_id)
    pj = parse_package_json(SEED / "package.json", scan_target_id)
    gm = parse_go_mod(SEED / "go.mod", scan_target_id)
    px = parse_pom_xml(SEED / "pom.xml", scan_target_id)
    libs = {x.library for x in req + pj + gm + px}
    assert "harmless-requests" not in libs
    assert "harmless-lodash" not in libs
    assert "harmless-echo" not in libs
    assert "harmless-guava" not in libs
