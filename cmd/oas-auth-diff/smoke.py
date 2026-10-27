"""Exercise the built CLI as a subprocess; no compiler or registry orchestration."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    root = Path(__file__).resolve().parents[2]
    if len(sys.argv) > 1:
        binary = Path(sys.argv[1]).resolve()
    else:
        build = root / "_build/native/debug/build/cmd/oas-auth-diff"
        binary = next((path for path in (build / "oas-auth-diff.exe", build / "oas-auth-diff") if path.is_file()), None)
        if binary is None:
            raise SystemExit("build cmd/oas-auth-diff --target native before running smoke.py")
    cases = root / "cases"
    checks = 0

    def invoke(arguments, expected, *, format=None):
        nonlocal checks
        args = [str(binary), *map(str, arguments)]
        if format:
            args.extend(["--format", format])
        result = subprocess.run(args, capture_output=True, encoding="utf-8", timeout=30)
        assert result.returncode == expected, (args, result.returncode, result.stdout, result.stderr)
        if expected == 2:
            assert result.stderr.strip(), (args, "missing diagnostic")
        elif not result.stderr:
            pass
        else:
            raise AssertionError((args, result.stderr))
        checks += 1
        if format in {"json", "sarif"}:
            return json.loads(result.stdout)
        return result.stdout

    assert "0.1.0" in invoke(["--version"], 0)
    assert "compare BEFORE AFTER" in invoke(["--help"], 0)
    before = cases / "orders.before.yaml"
    after = cases / "orders.after.json"
    unchanged = invoke(["compare", before, before], 0, format="json")
    assert unchanged["complete"] is True
    assert unchanged["changes"][0]["kind"] == "equivalent"

    report = invoke(["compare", before, after], 1, format="json")
    assert report["schema_version"] == 1 and report["exit_code"] == 1
    change = report["changes"][0]
    assert change["kind"] == "weakened" and change["operation_id"] == "listOrders"
    assert change["location"]["uri"].startswith("file://")
    assert change["location"]["pointer"] == "/security"
    assert {atom.get("name") for atom in change["witness"]} == {None, "orders:read"}
    assert "strengthened" in invoke(["compare", after, before], 0)

    sarif = invoke(["compare", before, after], 1, format="sarif")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["results"][0]["ruleId"] == "auth-regression"
    location = run["results"][0]["locations"][0]
    assert location["properties"]["jsonPointer"] == "/security"
    assert "region" not in location["physicalLocation"]

    petstore = invoke(["compare", cases / "petstore.protected.yaml", cases / "petstore.public.yaml"], 1, format="json")
    assert len(petstore["changes"]) == 3
    assert all(change["witness"] == [] for change in petstore["changes"])

    with tempfile.TemporaryDirectory(prefix="oas-auth-diff-") as directory:
        directory = Path(directory)
        bad = directory / "bad.json"
        bad.write_text('{"openapi":"3.1.1","openapi":"3.0.3"}', encoding="utf-8")
        failure = invoke(["compare", before, bad], 2, format="json")
        assert failure["complete"] is False and failure["diagnostics"]
        fatal_sarif = invoke(["compare", before, bad], 2, format="sarif")
        invocation = fatal_sarif["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False
        assert invocation["toolExecutionNotifications"]

        invalid_yaml = directory / "bad.yaml"
        invalid_yaml.write_text("openapi: 3.1.1\npaths: &paths {}\n", encoding="utf-8")
        invoke(["compare", before, invalid_yaml], 2, format="json")
        invalid_utf8 = directory / "bad-encoding.json"
        invalid_utf8.write_bytes(b"\xff\xfe\x00")
        invoke(["compare", before, invalid_utf8], 2, format="json")
        oversized = directory / "oversized.json"
        oversized.write_bytes(b" " * (17 * 1024 * 1024))
        oversized_report = invoke(["compare", before, oversized], 2, format="json")
        assert "16 MiB" in oversized_report["diagnostics"][0]["message"]
        at_limit = directory / "exact-limit.json"
        minimal = b'{"openapi":"3.1.1","paths":{}}'
        at_limit.write_bytes(minimal + b" " * (16 * 1024 * 1024 - len(minimal)))
        invoke(["compare", at_limit, at_limit], 0, format="json")
        if hasattr(os, "mkfifo"):
            pipe = directory / "pipe.json"
            os.mkfifo(pipe)
            pipe_report = invoke(["compare", before, pipe], 2, format="json")
            assert "regular file" in pipe_report["diagnostics"][0]["message"]
        unicode_path = directory / "接口 résumé 🦉.json"
        unicode_path.write_bytes(after.read_bytes())
        unicode_report = invoke(["compare", before, unicode_path], 1, format="json")
        assert unicode_report["changes"][0]["location"]["uri"].endswith("%E6%8E%A5%E5%8F%A3%20r%C3%A9sum%C3%A9%20%F0%9F%A6%89.json")
        invoke(["compare", before, directory / "missing.json"], 2, format="json")
        invoke(["compare", before, directory / "wrong.txt"], 2, format="json")
        invoke(["compare", before], 2, format="json")
        argument_sarif = invoke(["compare", before], 2, format="sarif")
        notification = argument_sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]
        assert notification["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "oas-auth-diff:arguments"

        # Keep a verified finding when a different path cannot be resolved.
        partial = json.loads(after.read_text(encoding="utf-8"))
        partial["paths"]["/external"] = {"$ref": "other.yaml#/paths/~1external"}
        partial_file = directory / "partial.json"
        partial_file.write_text(json.dumps(partial), encoding="utf-8")
        partial_report = invoke(["compare", before, partial_file], 2, format="json")
        assert partial_report["complete"] is False
        assert any(change["kind"] == "weakened" and change["witness"] for change in partial_report["changes"])

        relative_url = json.loads(after.read_text(encoding="utf-8"))
        relative_url["components"]["securitySchemes"]["account"]["flows"]["clientCredentials"]["tokenUrl"] = "/token"
        relative_file = directory / "relative.json"
        relative_file.write_text(json.dumps(relative_url), encoding="utf-8")
        relative_report = invoke(["compare", before, relative_file], 2, format="json")
        assert any(item["code"] == "auth.url" for item in relative_report["diagnostics"])

    print(f"CLI smoke: {checks} subprocess checks passed")


if __name__ == "__main__":
    main()
