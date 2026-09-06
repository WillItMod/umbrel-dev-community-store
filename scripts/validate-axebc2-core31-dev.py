#!/usr/bin/env python3
from pathlib import Path
import datetime
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import argparse
from axebc2_release_state import validate as validate_release_state, validate_rendered_binds


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "willitmod-dev-bc2"
APP_DIGEST = "sha256:23a7962e223da5549eba52697c6f4cfa16ab74cba935c68c48148a4c515302b4"
DEV_STORE_REVISION = "249ab61506dc09c2151d39e2b210f5f18d75ff21"
DEV_COMPOSE_SHA256 = "93ceba92069947f47d650a5fb32205836fe070d83707f36912a2e0e83beb1244"
DEV_STORE_COMMITTED_AT = datetime.datetime.fromisoformat("2026-09-04T17:11:52+00:00")


def require(condition, message):
    if not condition:
        raise SystemExit(message)


compose_path = APP / "docker-compose.yml"
compose_bytes = compose_path.read_bytes()
compose = compose_bytes.decode("utf-8")
parser = argparse.ArgumentParser()
parser.add_argument("--phase", required=True, choices=("prefinalization", "finalized"))
phase = parser.parse_args().phase
try:
    validate_release_state(compose, phase)
except ValueError as exc:
    raise SystemExit(str(exc))
manifest = (APP / "umbrel-app.yml").read_text(encoding="utf-8")
node_config = (APP / "data/templates/bitcoinII.conf.template").read_text(encoding="utf-8")
evidence = json.loads((APP / "DEV-ACCEPTANCE-EVIDENCE.json").read_text(encoding="utf-8"))

# Hash the exact finalized recipe in either lifecycle phase. In prefinalization
# there is exactly one sentinel; in finalization this replacement is a no-op.
finalized_compose_bytes = compose_bytes.replace(
    b"APP_CANDIDATE_DIGEST_REQUIRED", APP_DIGEST.removeprefix("sha256:").encode()
)
computed_compose_sha256 = hashlib.sha256(finalized_compose_bytes).hexdigest()
require(
    computed_compose_sha256 == DEV_COMPOSE_SHA256,
    "DEV Compose content differs from the recipe accepted on 10.10.10.235",
)

# Package revision; the unchanged runtime evidence below remains 0.1.11-dev.
require('version: "0.1.12-dev"' in manifest, "manifest must be 0.1.12-dev")
require(evidence.get("app_version") == "0.1.11-dev", "evidence must name the 0.1.11 DEV app version")
require(
    evidence.get("app_image")
    == "ghcr.io/willitmod/axebc2-app-umbrel-dev:0.1.11-candidate.ecf6e2c8cfd0",
    "evidence must name the exact application candidate tag",
)
require(
    evidence.get("source_revision") == "ecf6e2c8cfd0e42ea53d3cc146b18cd6d4c4b563",
    "evidence must name the exact application source revision",
)
require(
    evidence.get("app_digest")
    == APP_DIGEST,
    "evidence must name the exact application index digest",
)
require(evidence.get("app_candidate_run") == 33895447789, "evidence must name the application candidate workflow run")
require(
    evidence.get("core_image") == "ghcr.io/willitmod/bitcoinii-core:31.1.0-rc.cdf44542dde2"
    and evidence.get("core_digest")
    == "sha256:8875917ece57668fe9925d40a256ce8d429a3071511bb555d4ace1fa4370afc6"
    and evidence.get("core_source_revision") == "cdf44542dde255648008249d187fafc15f3a2f09"
    and evidence.get("core_candidate_run") == 33675068951,
    "evidence must retain the accepted Core 31 tag, digest, source revision, and candidate run",
)
require("on 5tratumOS, version 0.7.12 or newer is required" in manifest, "OS prerequisite must be disclosed")
require(evidence.get("tested_os_version") == "v0.7.12-dev", "evidence must name the tested DEV OS release")
require(
    evidence.get("tested_os_bundle_sha256")
    == "11a35e68ab169eb0446485992a57b33fae018a92020b7d86bbf9a005571377af",
    "evidence must be bound to the exact verified v0.7.12-dev bundle",
)
require(
    evidence.get("dev_store_revision") == DEV_STORE_REVISION,
    "evidence must name the exact corrected DEV store revision",
)
require(
    evidence.get("dev_compose_sha256") == DEV_COMPOSE_SHA256
    and evidence.get("dev_compose_sha256") == computed_compose_sha256,
    "evidence must be bound to the exact corrected DEV Compose recipe",
)


def parse_utc_timestamp(value, label):
    try:
        parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise SystemExit(f"{label} must be an ISO-8601 timestamp")
    require(parsed.tzinfo is not None, f"{label} must include a timezone")
    return parsed.astimezone(datetime.timezone.utc)


if phase == "finalized":
    require(type(evidence.get("schema")) is int and evidence["schema"] == 1, "finalized DEV evidence schema must be 1")
    require(evidence.get("result") == "passed", "finalized DEV evidence must have passed")
    require(evidence.get("tested_on") == "10.10.10.235", "finalized DEV evidence must name the test node")
    tested_at = parse_utc_timestamp(evidence.get("tested_at"), "tested_at")
    acceptance = evidence.get("acceptance")
    require(isinstance(acceptance, dict), "finalized DEV evidence requires structured acceptance observations")
    observed_at = parse_utc_timestamp(acceptance.get("observed_at"), "acceptance observed_at")
    require(
        tested_at >= DEV_STORE_COMMITTED_AT and observed_at >= DEV_STORE_COMMITTED_AT,
        "finalized DEV acceptance must post-date the corrected store recipe",
    )
    require(observed_at == tested_at, "tested_at and acceptance observed_at must identify the same run")

    true_gates = (
        "migration_required_marker_absent",
        "migration_started_marker_valid",
        "migration_complete_marker_valid",
        "verifychain_passed",
        "payout_configured",
        "payout_preserved",
        "app_ui_privacy_passed",
        "payout_validation_passed",
        "invalid_payout_rejected_without_mutation",
        "rpc_unavailable_rejected_without_mutation",
        "pending_payout_revalidation_passed",
        "main_payout_banner_hidden",
        "ckpool_sharelog_ownership_repaired",
        "pool_config_directory_writable",
        "telemetry_disabled",
        "p2p_port_unpublished",
        "natpmp_disabled",
        "post_completion_restart_passed",
        "reindex_not_repeated",
        "app_rollback_rejected",
        "os_rollback_rejected",
    )
    missing_true_gates = [key for key in true_gates if acceptance.get(key) is not True]
    require(not missing_true_gates, "required acceptance gates are not true: " + ", ".join(missing_true_gates))
    require(
        acceptance.get("chain") == "main"
        and type(acceptance.get("competing_valid_tips")) is int
        and acceptance["competing_valid_tips"] == 0,
        "main chain must have no competing valid tips",
    )
    require(acceptance.get("core_version") == 310100, "exact Core 31.1.0 version was not observed")
    require(
        acceptance.get("checkpoint_height") == 57752
        and acceptance.get("checkpoint_hash")
        == "000000000000000013ceffe797280c57f75a5b9f1d9e70c3503584058c322576",
        "official ShockWave checkpoint observation is invalid",
    )
    hex64 = lambda value: isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))
    minimum_chainwork = "0000000000000000000000000000000000000000000000959028194ff1139272"
    require(
        hex64(acceptance.get("chainwork")) and acceptance["chainwork"] >= minimum_chainwork,
        "observed chainwork is below the accepted minimum",
    )
    progress = acceptance.get("verification_progress")
    require(
        acceptance.get("ibd") is False
        and isinstance(progress, (int, float))
        and not isinstance(progress, bool)
        and progress >= 0.999999,
        "node synchronization evidence is incomplete",
    )
    blocks = acceptance.get("blocks")
    require(
        type(blocks) is int
        and blocks >= 57752
        and blocks == acceptance.get("headers")
        and blocks == acceptance.get("explorer_common_height"),
        "node and explorer heights must match at or beyond the checkpoint",
    )
    require(
        hex64(acceptance.get("best_block_hash"))
        and acceptance.get("best_block_hash") == acceptance.get("explorer_common_hash"),
        "node and explorer hashes must match",
    )
    require(
        type(acceptance.get("outbound_core31_peers")) is int
        and acceptance["outbound_core31_peers"] >= 3,
        "fewer than three outbound Core 31 peers were observed",
    )
    require(acceptance.get("verifychain_level") == 4, "verifychain level 4 was not recorded")
    require(acceptance.get("pool_stratum_result") == "passed", "pool/Stratum acceptance did not pass")
else:
    require(
        evidence.get("result") == "RECORD_passed_AFTER_LIVE_DEV_ACCEPTANCE",
        "prefinalization evidence must remain an explicit acceptance template",
    )
    acceptance = evidence.get("acceptance")
    require(isinstance(acceptance, dict), "prefinalization evidence template requires acceptance fields")
    require(
        acceptance.get("pool_config_directory_writable") == "RECORD_BOOLEAN",
        "prefinalization evidence must prompt for the uid-1000 pool-config write probe",
    )
require('"2345:3333/tcp"' in compose, "Stratum host port 2345 must be retained")
require("SUPPORT_CHECKIN_ENABLED: \"false\"" in compose, "telemetry must default off")
require("create_host_path: false" in compose, "build metadata bind must fail closed")
require("/etc/5tratumos/build.json" in compose, "build metadata must be mounted")
require('JWT_SECRET: "${JWT_SECRET}"' in compose, "init must receive the platform JWT secret")
require(
    "chown -R 1000:1000 /data/pool/config" in compose
    and compose.index("chown -R 1000:1000 /data/pool/config")
    < compose.index("exec /bin/sh /opt/axebc2/init.sh"),
    "versioned Compose init must keep fresh and preserved CKPool config writable",
)
require(
    "chown -R 1000:1000 /data/pool/www" in compose
    and compose.count("$$(stat -c '%u:%g' /data/pool/www") == 3,
    "versioned Compose init must repair the persistent CKPool sharelog tree",
)
require(
    "previously seeded init script" in compose,
    "ownership repair must document why it cannot live only in seeded app data",
)
require(
    ".5tratumos-rollback-policy.json" in (APP / "data/init/init.sh").read_text(encoding="utf-8"),
    "init must use the policy filename consumed by AxeBC2 and 5tratumOS",
)
require(
    'chown -R 1000:1000 "${data_dir}/pool/config"' in (APP / "data/init/init.sh").read_text(encoding="utf-8"),
    "seeded init must retain targeted CKPool config ownership repair",
)
require(
    "alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"
    in compose,
    "init image must be pinned",
)
require(
    "ghcr.io/willitmod/docker-ckpool-solo:590fb2a@sha256:8a9a7f10c8138d0f55533132ee7710a06715a42a49f75efb39be3350ada4fa6e"
    in compose,
    "CKPool image must retain its exact pin",
)
require("natpmp=0" in node_config and "upnp=1" not in node_config, "NAT-PMP must be off")
require(not re.search(r'^\s+-\s+"?8338:', compose, re.MULTILINE), "P2P must not be published")

require(
    compose.count("create_host_path: false") == 9,
    "every AxeBC2 host bind must disable implicit source-path creation",
)


def yaml_python():
    candidates = [os.environ.get("YAML_PYTHON"), "/usr/bin/python3", sys.executable]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            check = subprocess.run(
                [candidate, "-c", "import yaml"], capture_output=True, check=False
            )
            if check.returncode == 0:
                return candidate
    raise SystemExit("PyYAML-capable Python is required for merged Compose validation")


def validate_platform_merged_compose():
    docker = shutil.which("docker")
    require(docker is not None, "Docker Compose is required for merged Compose validation")
    with tempfile.TemporaryDirectory(prefix="axebc2-compose-") as raw_temp:
        temp = Path(raw_temp)
        app_data = temp / "state/apps/axebc2"
        for relative in (
            "data/templates",
            "data/init",
            "data/node",
            "data/pool/config",
            "data/pool/www",
        ):
            (app_data / relative).mkdir(parents=True, exist_ok=True)
        (app_data / "data/init/init.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        source = temp / "docker-compose.yml"
        build_metadata = temp / "build.json"
        build_metadata.write_text('{"tag":"v0.7.12-dev"}\n', encoding="utf-8")
        source.write_text(
            compose.replace("APP_CANDIDATE_DIGEST_REQUIRED", "b" * 64)
            .replace("/etc/5tratumos/build.json", str(build_metadata)),
            encoding="utf-8",
        )
        parsed = temp / "parsed-compose.json"
        merged = temp / "platform-merged-compose.json"
        transform = """
import json, sys, yaml
with open(sys.argv[1], encoding='utf-8') as handle:
    config = yaml.safe_load(handle)
with open(sys.argv[2], 'w', encoding='utf-8') as handle:
    json.dump(config, handle)
"""
        subprocess.run([yaml_python(), "-c", transform, source, parsed], check=True)
        contract_path = ROOT / "tests/fixtures/5tratumos_contract_4f979cb.py"
        spec = importlib.util.spec_from_file_location("pinned_5tratumos_contract", contract_path)
        contract = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(contract)
        rendered_contract = contract.materialize_compose(
            json.loads(parsed.read_text(encoding="utf-8")), 21219
        )
        merged.write_text(json.dumps(rendered_contract), encoding="utf-8")
        env = os.environ.copy()
        env.update(
            {
                "APP_DATA_DIR": str(app_data),
                "APP_PASSWORD": "validation-only",
                "JWT_SECRET": "validation-only",
                "NETWORK_IP": "10.21.0.0",
            }
        )
        result = subprocess.run(
            [docker, "compose", "-f", str(merged), "config", "--format", "json"],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        require(result.returncode == 0, f"merged Compose is invalid: {result.stderr}")
        rendered = json.loads(result.stdout)
        services = rendered["services"]
        require("app_proxy" not in services, "platform merge must remove legacy app_proxy")
        require(
            services["init"]["environment"]["JWT_SECRET"] == "validation-only",
            "platform-merged init service must receive JWT_SECRET",
        )
        require(
            services["app"]["ports"] == [{"mode": "ingress", "target": 3000, "published": "21219", "protocol": "tcp"}],
            "platform merge must materialize the app-proxy host port on the app service",
        )
        require(
            "umbrel_main_network" not in rendered.get("networks", {}),
            "platform merge must remove the legacy shared network",
        )
        require(
            services["app"]["restart"] == "unless-stopped"
            and services["ckpool"]["restart"] == "unless-stopped",
            "platform merge must normalize service restart policies",
        )
        require(
            services["btc2d"]["depends_on"]["init"]["condition"]
            == "service_completed_successfully",
            "Core must wait for successful init completion",
        )
        try:
            validate_rendered_binds(rendered_contract, rendered, {"APP_DATA_DIR": str(app_data)})
        except ValueError as exc:
            raise SystemExit(str(exc))


validate_platform_merged_compose()

subprocess.run(["sh", "-n", str(APP / "data/init/init.sh")], check=True)
suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_axebc2_*.py")
result = unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
