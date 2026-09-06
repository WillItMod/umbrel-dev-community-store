import json
import hashlib
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/finalize-axebc2-0.1.11-dev.sh"
COMPOSE = ROOT / "willitmod-dev-bc2/docker-compose.yml"
APP_DIGEST = "sha256:23a7962e223da5549eba52697c6f4cfa16ab74cba935c68c48148a4c515302b4"
CORE_DIGEST = "sha256:8875917ece57668fe9925d40a256ce8d429a3071511bb555d4ace1fa4370afc6"
CORE_TAG = "31.1.0-rc.cdf44542dde2"
OS_BUNDLE_SHA256 = "11a35e68ab169eb0446485992a57b33fae018a92020b7d86bbf9a005571377af"
DEV_STORE_REVISION = "249ab61506dc09c2151d39e2b210f5f18d75ff21"
DEV_COMPOSE_SHA256 = "93ceba92069947f47d650a5fb32205836fe070d83707f36912a2e0e83beb1244"

class AxeBC2DevFinalizerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="axebc2-dev-finalizer-")
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir(); (self.root / "willitmod-dev-bc2").mkdir()
        shutil.copy2(SCRIPT, self.root / "scripts" / SCRIPT.name)
        # This finalizer belongs to 0.1.11. Restore that exact UI pin/stage
        # before exercising its historical acceptance workflow.
        fixture = COMPOSE.read_text(encoding="utf-8")
        fixture = fixture.replace(
            "ghcr.io/willitmod/axebc2-app-umbrel-dev:0.1.12-candidate.3b893173de7b@sha256:5defc8ac3c1d6e188959ed5c0642165e66108701c5ce3881e909c0994c8e3189",
            "ghcr.io/willitmod/axebc2-app-umbrel-dev:0.1.11-candidate.ecf6e2c8cfd0@" + APP_DIGEST,
        ).replace('APP_CHANNEL: "BETA"', 'APP_CHANNEL: "ALPHA"')
        fixture = re.sub(r"(ghcr\.io/willitmod/axebc2-app-umbrel-dev:0\.1\.11-candidate\.ecf6e2c8cfd0@sha256:)[0-9a-f]{64}", r"\1APP_CANDIDATE_DIGEST_REQUIRED", fixture)
        (self.root / "willitmod-dev-bc2/docker-compose.yml").write_text(fixture, encoding="utf-8")
        self.assertEqual(fixture.count("APP_CANDIDATE_DIGEST_REQUIRED"), 1)
        self.assertEqual(fixture.count(CORE_DIGEST), 2)
        self.original = (self.root / "willitmod-dev-bc2/docker-compose.yml").read_bytes()
        self.log = self.root / "docker.log"
        self.fake = self.root / "docker"
        self.fake.write_text("""#!/bin/sh
set -eu
printf '%s\\n' "$*" >>"$FAKE_DOCKER_LOG"
host="$2"; config="$4"; [ "$1" = --host ]; [ "$3" = --config ]; [ -n "$host" ]; [ "$(cat "$config/config.json")" = '{"auths":{}}' ]; shift 4
if [ "$1 $2" = 'buildx imagetools' ]; then
 case "$4" in
  ghcr.io/willitmod/axebc2-app-umbrel-dev:0.1.11-candidate.ecf6e2c8cfd0) printf 'Digest: %s\\n' "$APP_DIGEST" ;;
  ghcr.io/willitmod/bitcoinii-core:31.1.0-rc.cdf44542dde2) printf 'Digest: %s\\n' "$CORE_DIGEST" ;;
  *) exit 2 ;;
 esac
elif [ "$1 $2" = 'manifest inspect' ]; then
 printf '%s\\n' '{"manifests":[{"platform":{"os":"linux","architecture":"amd64"}},{"platform":{"os":"linux","architecture":"arm64"}}]}'
elif [ "$1" = pull ]; then exit 0
else exit 3
fi
""", encoding="utf-8")
        self.fake.chmod(0o755)
        self.curl_log = self.root / "curl.log"
        self.fake_curl = self.root / "curl"
        self.fake_curl.write_text("""#!/bin/sh
set -eu
printf '%s\\n' "$*" >>"$FAKE_CURL_LOG"
for arg in "$@"; do url="$arg"; done
case "$url" in
 *'/token?'*) printf '%s\\n' '{"token":"anonymous-test-token"}' ;;
 *)
  case "${CURL_DIGEST_MODE:-correct}" in
   correct) case "$url" in *axebc2-app-umbrel-dev*) digest="$APP_DIGEST";; *) digest="$CORE_DIGEST";; esac ;;
   wrong) digest="sha256:$(printf '%064d' 0)" ;;
   missing) printf 'HTTP/2 200\\r\\n\\r\\n'; exit 0 ;;
   malformed) digest='sha256:not-a-digest' ;;
  esac
  printf 'HTTP/2 200\\r\\ndocker-content-digest: %s\\r\\n\\r\\n' "$digest"
 ;;
esac
""", encoding="utf-8")
        self.fake_curl.chmod(0o755)

    def tearDown(self): self.temp.cleanup()

    def run_it(self, curl_mode="correct"):
        env=os.environ.copy(); env.update({"DOCKER_BIN":str(self.fake),"DOCKER_HOST":"unix:///tmp/test-colima.sock","CURL_BIN":str(self.fake_curl),"FAKE_DOCKER_LOG":str(self.log),"FAKE_CURL_LOG":str(self.curl_log),"CURL_DIGEST_MODE":curl_mode,"APP_DIGEST":APP_DIGEST,"CORE_DIGEST":CORE_DIGEST})
        return subprocess.run([str(self.root/"scripts"/SCRIPT.name),APP_DIGEST],env=env,text=True,capture_output=True,check=False)

    def test_anonymous_candidate_checks_finalize_and_emit_evidence(self):
        result=self.run_it(); self.assertEqual(result.returncode,0,result.stderr)
        compose=(self.root/"willitmod-dev-bc2/docker-compose.yml").read_text(encoding="utf-8")
        self.assertNotIn("_DIGEST_REQUIRED",compose)
        self.assertEqual(hashlib.sha256(compose.encode()).hexdigest(),DEV_COMPOSE_SHA256)
        core_ref="ghcr.io/willitmod/bitcoinii-core:"+CORE_TAG+"@"+CORE_DIGEST
        self.assertEqual(compose.count(core_ref),2)
        evidence=json.loads((self.root/"willitmod-dev-bc2/DEV-ACCEPTANCE-EVIDENCE.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence["source_revision"],"ecf6e2c8cfd0e42ea53d3cc146b18cd6d4c4b563")
        self.assertEqual(evidence["app_version"],"0.1.11-dev")
        self.assertEqual(evidence["app_candidate_run"],33895447789)
        self.assertEqual(evidence["core_source_revision"],"cdf44542dde255648008249d187fafc15f3a2f09")
        self.assertEqual(evidence["core_candidate_run"],33675068951)
        self.assertEqual(evidence["tested_os_version"],"v0.7.12-dev")
        self.assertEqual(evidence["tested_os_bundle_sha256"],OS_BUNDLE_SHA256)
        self.assertEqual(evidence["dev_store_revision"],DEV_STORE_REVISION)
        self.assertEqual(evidence["dev_compose_sha256"],DEV_COMPOSE_SHA256)
        self.assertEqual(evidence["acceptance"]["pool_config_directory_writable"],"RECORD_BOOLEAN")
        self.assertEqual(evidence["app_digest"],APP_DIGEST); self.assertEqual(evidence["core_digest"],CORE_DIGEST)
        calls=self.log.read_text(encoding="utf-8")
        self.assertEqual(calls.count("--platform linux/amd64"),2); self.assertEqual(calls.count("--platform linux/arm64"),2)
        self.assertNotIn("buildx", calls)
        self.assertTrue(all("--host unix:///tmp/test-colima.sock --config" in line for line in calls.splitlines()))

    def test_recipe_drift_fails_before_compose_or_evidence_mutation(self):
        compose=self.root/"willitmod-dev-bc2/docker-compose.yml"
        compose.write_bytes(compose.read_bytes()+b"\n# unexpected recipe drift\n")
        original=compose.read_bytes()
        result=self.run_it()
        self.assertNotEqual(result.returncode,0)
        self.assertIn("finalized DEV Compose SHA-256 differs",result.stderr)
        self.assertEqual(compose.read_bytes(),original)
        self.assertFalse((self.root/"willitmod-dev-bc2/DEV-ACCEPTANCE-EVIDENCE.json").exists())

    def test_bad_explicit_docker_host_fails_before_registry_or_mutation(self):
        env=os.environ.copy(); env.update({"DOCKER_BIN":str(self.fake),"DOCKER_HOST":"not-an-endpoint","CURL_BIN":str(self.fake_curl),"FAKE_DOCKER_LOG":str(self.log),"FAKE_CURL_LOG":str(self.curl_log),"APP_DIGEST":APP_DIGEST,"CORE_DIGEST":CORE_DIGEST})
        result=subprocess.run([str(self.root/"scripts"/SCRIPT.name),APP_DIGEST],env=env,text=True,capture_output=True,check=False)
        self.assertNotEqual(result.returncode,0); self.assertFalse(self.log.exists()); self.assertFalse(self.curl_log.exists())
        self.assertEqual((self.root/"willitmod-dev-bc2/docker-compose.yml").read_bytes(),self.original)

    def test_bad_registry_digest_headers_fail_without_docker_or_mutation(self):
        for mode in ("wrong", "missing", "malformed"):
            if self.log.exists(): self.log.unlink()
            result=self.run_it(curl_mode=mode); self.assertNotEqual(result.returncode,0)
            self.assertFalse(self.log.exists())
            self.assertEqual((self.root/"willitmod-dev-bc2/docker-compose.yml").read_bytes(),self.original)

    def test_unexpected_extra_argument_fails_before_registry_and_mutation(self):
        env=os.environ.copy(); env.update({"DOCKER_BIN":str(self.fake),"DOCKER_HOST":"unix:///tmp/test-colima.sock","CURL_BIN":str(self.fake_curl),"FAKE_DOCKER_LOG":str(self.log),"FAKE_CURL_LOG":str(self.curl_log),"APP_DIGEST":APP_DIGEST,"CORE_DIGEST":CORE_DIGEST})
        result=subprocess.run([str(self.root/"scripts"/SCRIPT.name),APP_DIGEST,"evidence.json","unexpected"],env=env,text=True,capture_output=True,check=False)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.log.exists())
        self.assertEqual((self.root/"willitmod-dev-bc2/docker-compose.yml").read_bytes(),self.original)

if __name__ == "__main__": unittest.main()
