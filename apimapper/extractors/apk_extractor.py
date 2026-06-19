"""
Static extraction of API endpoints and secrets from Android APKs.

Decompiles via jadx (must be installed — apt install jadx, or grab from
https://github.com/skylot/jadx) into Java source, then re-uses the same
string-pattern extraction logic as the JS extractor since the underlying
patterns (URLs, API keys) look the same in decompiled Java strings.

Pure static analysis — no device/emulator interaction, no network calls.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from apimapper.core.models import Endpoint, SecretFinding, Source
from apimapper.extractors.js_extractor import extract_endpoints_from_js, extract_secrets_from_js


class JadxNotFoundError(Exception):
    pass


def _require_jadx() -> str:
    jadx_path = shutil.which("jadx")
    if not jadx_path:
        raise JadxNotFoundError(
            "jadx not found on PATH. Install it first:\n"
            "  Kali/Debian: sudo apt install jadx\n"
            "  or download: https://github.com/skylot/jadx/releases"
        )
    return jadx_path


def decompile_apk(apk_path: str | Path, out_dir: str | Path | None = None, timeout: int = 600) -> Path:
    """Run jadx to decompile an APK to Java source + resources. Returns output dir."""
    jadx = _require_jadx()
    apk_path = Path(apk_path)
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    out_dir = Path(out_dir) if out_dir else Path(tempfile.mkdtemp(prefix="apimapper_jadx_"))
    cmd = [jadx, "-d", str(out_dir), "--show-bad-code", str(apk_path)]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0 and not out_dir.exists():
        raise RuntimeError(f"jadx failed:\n{result.stderr[-2000:]}")

    return out_dir


def parse_android_manifest(decompiled_dir: Path) -> dict:
    """Pull package name, exported components, and permissions — useful recon context."""
    manifest_path = decompiled_dir / "resources" / "AndroidManifest.xml"
    if not manifest_path.exists():
        manifest_path = decompiled_dir / "AndroidManifest.xml"
    if not manifest_path.exists():
        return {}

    info = {"package": None, "permissions": [], "exported_components": []}
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        info["package"] = root.attrib.get("package")

        for perm in root.findall("uses-permission"):
            name = perm.attrib.get(f"{{{ns['android']}}}name")
            if name:
                info["permissions"].append(name)

        for tag in ("activity", "service", "receiver", "provider"):
            for el in root.iter(tag):
                exported = el.attrib.get(f"{{{ns['android']}}}exported")
                name = el.attrib.get(f"{{{ns['android']}}}name")
                if exported == "true" and name:
                    info["exported_components"].append({"type": tag, "name": name})
    except ET.ParseError:
        pass

    return info


def scan_apk(apk_path: str | Path, keep_decompiled: bool = False) -> tuple[list[Endpoint], list[SecretFinding], dict]:
    """
    Full pipeline: decompile, walk Java sources + string resources, extract
    endpoints/secrets. Returns (endpoints, secrets, manifest_info).
    """
    out_dir = decompile_apk(apk_path)

    endpoints: list[Endpoint] = []
    secrets: list[SecretFinding] = []

    # Java sources
    sources_dir = out_dir / "sources"
    search_dir = sources_dir if sources_dir.exists() else out_dir
    for f in search_dir.rglob("*.java"):
        try:
            content = f.read_text(errors="ignore")
        except Exception:
            continue
        eps = extract_endpoints_from_js(content, str(f))  # same string patterns apply
        for e in eps:
            e.source = Source.APK_STATIC
        secs = extract_secrets_from_js(content, str(f))
        for s in secs:
            s.source = Source.APK_STATIC
        endpoints.extend(eps)
        secrets.extend(secs)

    # strings.xml and other resource files often hold base URLs / keys directly
    res_dir = out_dir / "resources"
    if res_dir.exists():
        for f in res_dir.rglob("*.xml"):
            try:
                content = f.read_text(errors="ignore")
            except Exception:
                continue
            eps = extract_endpoints_from_js(content, str(f))
            for e in eps:
                e.source = Source.APK_STATIC
            secs = extract_secrets_from_js(content, str(f))
            for s in secs:
                s.source = Source.APK_STATIC
            endpoints.extend(eps)
            secrets.extend(secs)

    manifest_info = parse_android_manifest(out_dir)

    if not keep_decompiled:
        import shutil as _shutil
        _shutil.rmtree(out_dir, ignore_errors=True)

    return endpoints, secrets, manifest_info
