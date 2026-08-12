#!/usr/bin/env python3
"""Build deterministic AgentTeams packages with deployment-scoped identities."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
PACKAGES_DIR = ROOT / "packages"
SHARED_DIR = ROOT / "shared"
DIST_DIR = ROOT / "dist"
ROLE_BY_AGENT = {
    "incident-commander": "incident_commander",
    "signal-correlator": "signal_correlator",
    "rca-investigator": "rca_investigator",
    "remediation-planner": "remediation_planner",
    "recovery-verifier": "recovery_verifier",
}
MCP_SERVER_BY_AGENT = {
    "signal-correlator": "opscouncil-signal",
    "rca-investigator": "opscouncil-investigation",
    "remediation-planner": "opscouncil-planning",
    "recovery-verifier": "opscouncil-verification",
}
REQUIRED_PATHS = ("manifest.json", "config/SOUL.md", "config/AGENTS.md")
FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)


def derive_token(secret: str, subject: str) -> str:
    if not secret:
        raise ValueError("callback secret is required")
    message = f"opscouncil-callback:{subject}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def validate_source_package(package_dir: Path) -> None:
    missing = [item for item in REQUIRED_PATHS if not (package_dir / item).is_file()]
    skills = list((package_dir / "skills").glob("*/SKILL.md"))
    if not skills:
        missing.append("skills/<skill>/SKILL.md")
    if missing:
        raise ValueError(f"{package_dir.name} is missing: {', '.join(missing)}")
    manifest = json.loads((package_dir / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("type") != "worker" or manifest.get("version") != 1:
        raise ValueError(f"{package_dir.name} must use the AgentTeams worker package v1 schema")
    suggested_name = str(manifest.get("worker", {}).get("suggested_name", ""))
    if suggested_name != package_dir.name:
        raise ValueError(
            f"{package_dir.name} manifest suggests unexpected worker {suggested_name!r}"
        )


def _zip_directory(source_dir: Path, destination: Path) -> None:
    with ZipFile(destination, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(item for item in source_dir.rglob("*") if item.is_file()):
            relative = path.relative_to(source_dir).as_posix()
            info = ZipInfo(relative, date_time=FIXED_ZIP_TIME)
            if relative == "config/callback-client.mjs":
                mode = 0o755
            elif relative == "config/opscouncil-runtime.json" or relative.endswith(
                "/mcporter.json"
            ):
                mode = 0o600
            else:
                mode = 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())


def build_packages(
    *,
    api_url: str,
    model: str,
    callback_secret: str,
    output_dir: Path = DIST_DIR,
) -> dict[str, object]:
    api_url = api_url.rstrip("/")
    if not api_url.startswith(("http://", "https://")):
        raise ValueError("OPSCOUNCIL_API_URL must be an absolute HTTP(S) URL")
    if not model.strip():
        raise ValueError("agent model is required")

    package_output = output_dir / "packages"
    if output_dir.exists():
        shutil.rmtree(output_dir)
    package_output.mkdir(parents=True, mode=0o700)

    artifacts: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="opscouncil-agentteams-") as temp_root:
        temp_root_path = Path(temp_root)
        for agent_name, role in ROLE_BY_AGENT.items():
            source = PACKAGES_DIR / agent_name
            validate_source_package(source)
            staged = temp_root_path / agent_name
            shutil.copytree(source, staged)

            manifest_path = staged / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["worker"]["model"] = model
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

            callback_token = derive_token(callback_secret, f"agent:{agent_name}")
            shutil.copy2(
                SHARED_DIR / "callback-client.mjs",
                staged / "config/callback-client.mjs",
            )
            runtime_config = {
                "api_url": api_url,
                "agent_name": agent_name,
                "role": role,
                "token": callback_token,
            }
            runtime_path = staged / "config/opscouncil-runtime.json"
            runtime_path.write_text(
                json.dumps(runtime_config, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

            server_name = MCP_SERVER_BY_AGENT.get(agent_name)
            if server_name is not None:
                mcporter_path = staged / "config/config/mcporter.json"
                mcporter_path.parent.mkdir(parents=True, exist_ok=True)
                mcporter_path.write_text(
                    json.dumps(
                        {
                            "mcpServers": {
                                server_name: {
                                    "url": f"{api_url}/mcp/agents/{agent_name}",
                                    "transport": "http",
                                    "headers": {
                                        "X-OpsCouncil-Agent-Token": callback_token,
                                    },
                                }
                            }
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n",
                    encoding="utf-8",
                )

            destination = package_output / f"{agent_name}.zip"
            _zip_directory(staged, destination)
            artifacts[agent_name] = destination.name

    build_manifest: dict[str, object] = {
        "api_url": api_url,
        "model": model,
        "packages": artifacts,
    }
    build_path = output_dir / "build.json"
    build_path.write_text(
        json.dumps(build_manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    build_path.chmod(0o600)
    return build_manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", default=os.environ.get("OPSCOUNCIL_API_URL", ""))
    parser.add_argument("--model", default=os.environ.get("OPSCOUNCIL_AGENT_MODEL", "qwen3.6-plus"))
    args = parser.parse_args()
    callback_secret = os.environ.get("AGENTTEAMS_CALLBACK_SECRET", "")
    if not callback_secret:
        parser.error("AGENTTEAMS_CALLBACK_SECRET must be set in the environment")
    if not args.api_url:
        parser.error("OPSCOUNCIL_API_URL or --api-url is required")
    result = build_packages(
        api_url=args.api_url,
        model=args.model,
        callback_secret=callback_secret,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
