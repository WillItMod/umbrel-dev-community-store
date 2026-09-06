from pathlib import Path

APP_TAG = "ghcr.io/willitmod/axebc2-app-umbrel-dev:0.1.12-candidate.3b893173de7b"
APP_DIGEST = "sha256:5defc8ac3c1d6e188959ed5c0642165e66108701c5ce3881e909c0994c8e3189"
CORE_TAG = "ghcr.io/willitmod/bitcoinii-core:31.1.0-rc.cdf44542dde2"
CORE_DIGEST = "sha256:8875917ece57668fe9925d40a256ce8d429a3071511bb555d4ace1fa4370afc6"

def validate(compose, phase):
    if phase not in {"prefinalization", "finalized"}:
        raise ValueError("phase must be prefinalization or finalized")
    app_sentinel = APP_TAG + "@sha256:APP_CANDIDATE_DIGEST_REQUIRED"
    core_pin = CORE_TAG + "@" + CORE_DIGEST
    if phase == "prefinalization":
        if compose.count(app_sentinel) != 1 or compose.count(core_pin) != 2:
            raise ValueError("prefinalization requires one app sentinel and two exact Core pins")
        if compose.count("_DIGEST_REQUIRED") != 1:
            raise ValueError("unknown or partial digest sentinel state")
        return
    if "_DIGEST_REQUIRED" in compose:
        raise ValueError("finalized release contains a digest sentinel")
    app_pin = APP_TAG + "@" + APP_DIGEST
    if compose.count(app_pin) != 1 or compose.count(core_pin) != 2:
        raise ValueError("finalized release requires the exact app pin and two exact Core pins")

def validate_rendered_binds(contract, rendered, environment=None):
    environment = environment or {}
    def expand(value):
        if not isinstance(value, str): return value
        for name, replacement in environment.items():
            value = value.replace("${" + name + "}", replacement)
        return value
    def binds(document):
        for service, config in document.get("services", {}).items():
            for volume in config.get("volumes", []):
                if volume.get("type") == "bind":
                    yield service, volume
    expected = {}
    for service, volume in binds(contract):
        key = (service, expand(volume.get("source")), volume.get("target"))
        if volume.get("bind", {}).get("create_host_path") is not False:
            raise ValueError(f"contract bind is not fail-closed: service={service} source={key[1]} target={key[2]}")
        expected[key] = volume
    actual = {}
    for service, volume in binds(rendered):
        key = (service, volume.get("source"), volume.get("target"))
        if key not in expected:
            raise ValueError(f"unexpected rendered bind: service={service} source={key[1]} target={key[2]}")
        if volume.get("bind", {}).get("create_host_path") is True:
            raise ValueError(f"rendered bind enables host-path creation: service={service} source={key[1]} target={key[2]}")
        if not isinstance(key[1], str) or not Path(key[1]).exists():
            raise ValueError(f"rendered bind source was not pre-staged: service={service} source={key[1]} target={key[2]}")
        actual[key] = volume
    missing = set(expected) - set(actual)
    if missing:
        service, source, target = sorted(missing)[0]
        raise ValueError(f"rendered bind disappeared: service={service} source={source} target={target}")
