"""Exercise the built CLI as a subprocess; no compiler or registry orchestration."""

import copy
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

    assert "0.4.0" in invoke(["--version"], 0)
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

    relative_before = cases / "oauth-relative.before.yaml"
    relative_after = cases / "oauth-relative.after.json"
    relative_sample = invoke(["compare", relative_before, relative_after], 1, format="json")
    assert relative_sample["changes"][0]["witness"] == [
        {"kind": "credential", "scheme": "warehouse"},
        {"kind": "scope", "scheme": "warehouse", "name": "stock:read"},
    ]
    invoke(["compare", relative_before, relative_before], 0, format="sarif")
    invoke(["compare", relative_after, relative_before], 0)

    with tempfile.TemporaryDirectory(prefix="oas-auth-diff-urls-") as directory:
        directory = Path(directory)
        old = directory / "before.json"
        new = directory / "after.json"
        baseline = json.loads(relative_after.read_text(encoding="utf-8"))
        flow = baseline["components"]["securitySchemes"]["warehouse"]["flows"]["clientCredentials"]
        flow["tokenUrl"] = "token"
        baseline["servers"] = [{"url": "https://auth.example.test/oauth/"}]
        baseline["paths"]["/stock"]["get"]["security"][0]["warehouse"].append("stock:write")
        baseline["paths"]["/override"] = copy.deepcopy(baseline["paths"]["/stock"])
        baseline["paths"]["/override"]["get"]["servers"] = [{"url": "https://override.example.test/auth/"}]
        old.write_text(json.dumps(baseline), encoding="utf-8")
        candidate = copy.deepcopy(baseline)
        candidate["servers"] = [{"url": "https://changed.example.test/oauth/"}]
        candidate["paths"]["/override"]["get"]["security"] = [{"warehouse": ["stock:read"]}]
        new.write_text(json.dumps(candidate), encoding="utf-8")
        partial = invoke(["compare", old, new], 2, format="json")
        assert any(change["path"] == "/stock" and change["kind"] == "incomparable" for change in partial["changes"])
        assert any(change["path"] == "/override" and change["kind"] == "weakened" and change["witness"] for change in partial["changes"])
        invoke(["compare", old, new], 2, format="sarif")

        del baseline["paths"]["/override"]
        baseline["servers"] = [{"url": "https://{region}.example.test/auth/", "variables": {
            "region": {"default": "us", "enum": ["us", "eu"]}
        }}]
        old.write_text(json.dumps(baseline), encoding="utf-8")
        candidate = copy.deepcopy(baseline)
        candidate["paths"]["/stock"]["get"]["security"] = [{"warehouse": ["stock:read"]}]
        new.write_text(json.dumps(candidate), encoding="utf-8")
        invoke(["compare", old, new], 1, format="json")
        candidate["servers"][0]["variables"]["region"]["enum"].reverse()
        new.write_text(json.dumps(candidate), encoding="utf-8")
        invoke(["compare", old, new], 1, format="json")
        candidate["servers"][0]["variables"]["region"]["enum"].append("ap")
        new.write_text(json.dumps(candidate), encoding="utf-8")
        changed_domain = invoke(["compare", old, new], 2, format="json")
        assert any(item["code"] == "scheme-incomparable" for item in changed_domain["diagnostics"])
        del candidate["servers"][0]["variables"]["region"]["enum"]
        new.write_text(json.dumps(candidate), encoding="utf-8")
        unrestricted = invoke(["compare", old, new], 2, format="json")
        assert any(item["code"] == "auth.variable" for item in unrestricted["diagnostics"])

    with tempfile.TemporaryDirectory(prefix="oas-auth-diff-document-urls-") as directory:
        directory = Path(directory)
        old_api = directory / "before.json"
        new_api = directory / "after.json"
        deployed_url = "https://deploy.example/specs/v1/openapi.json"
        configured_url = "HTTPS://DEPLOY.EXAMPLE:443/specs/v1/openapi.json"
        both_urls = ["--before-document-url", configured_url, "--after-document-url", configured_url]
        baseline = json.loads(relative_after.read_text(encoding="utf-8"))
        baseline["servers"] = [{"url": "../oauth/"}]
        baseline["components"]["securitySchemes"]["warehouse"]["flows"]["clientCredentials"]["tokenUrl"] = "token"
        baseline["paths"]["/stock"]["get"]["security"] = [{"warehouse": ["stock:read", "stock:write"]}]
        candidate = copy.deepcopy(baseline)
        candidate["paths"]["/stock"]["get"]["security"] = [{"warehouse": ["stock:read"]}]
        old_api.write_text(json.dumps(baseline), encoding="utf-8")
        new_api.write_text(json.dumps(candidate), encoding="utf-8")

        without_urls = invoke(["compare", old_api, new_api], 2, format="json")
        assert any(item["code"] == "auth.base" for item in without_urls["diagnostics"])
        deployed = invoke(["compare", old_api, new_api, *both_urls], 1, format="json")
        assert deployed["document_urls"] == {"before": deployed_url, "after": deployed_url}
        assert deployed["changes"][0]["location"]["uri"] == new_api.resolve().as_uri()
        assert deployed["changes"][0]["witness"]
        text = invoke(["compare", old_api, new_api, *both_urls], 1)
        assert "Baseline document URL: " + deployed_url in text
        assert "Candidate document URL: " + deployed_url in text
        deployed_sarif = invoke(["compare", old_api, new_api, *both_urls], 1, format="sarif")
        assert deployed_sarif["runs"][0]["properties"]["document_urls"] == deployed["document_urls"]
        physical = deployed_sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == new_api.resolve().as_uri()
        wrong_base = invoke(["compare", old_api, new_api,
                             "--before-document-url", deployed_url,
                             "--after-document-url", "https://deploy.example/api/"], 2, format="json")
        assert wrong_base["changes"][0]["kind"] == "incomparable"

        # Each side's configuration is independent, including a missing base.
        invoke(["compare", old_api, new_api, "--before-document-url", deployed_url], 2, format="json")
        invoke(["compare", old_api, new_api, "--after-document-url", deployed_url], 2, format="json")
        absolute_after = copy.deepcopy(candidate)
        absolute_after["components"]["securitySchemes"]["warehouse"]["flows"]["clientCredentials"]["tokenUrl"] = "https://deploy.example/specs/oauth/token"
        new_api.write_text(json.dumps(absolute_after), encoding="utf-8")
        one_side = invoke(["compare", old_api, new_api, "--before-document-url", deployed_url], 1, format="json")
        assert one_side["document_urls"] == {"before": deployed_url, "after": None}
        absolute_before = copy.deepcopy(baseline)
        absolute_before["components"]["securitySchemes"]["warehouse"]["flows"]["clientCredentials"]["tokenUrl"] = "https://deploy.example/specs/oauth/token"
        old_api.write_text(json.dumps(absolute_before), encoding="utf-8")
        new_api.write_text(json.dumps(candidate), encoding="utf-8")
        other_side = invoke(["compare", old_api, new_api, "--after-document-url", deployed_url], 1, format="json")
        assert other_side["document_urls"] == {"before": None, "after": deployed_url}

        # Deployment changes invalidate only operations that depend on that base.
        baseline["paths"]["/fixed"] = copy.deepcopy(baseline["paths"]["/stock"])
        candidate["paths"]["/fixed"] = copy.deepcopy(candidate["paths"]["/stock"])
        for spec in (baseline, candidate):
            spec["paths"]["/fixed"]["get"]["servers"] = [{"url": "https://fixed.example/oauth/"}]
        old_api.write_text(json.dumps(baseline), encoding="utf-8")
        new_api.write_text(json.dumps(candidate), encoding="utf-8")
        changed_urls = ["--before-document-url", deployed_url, "--after-document-url", "https://changed.example/specs/v1/openapi.json"]
        changed = invoke(["compare", old_api, new_api, *changed_urls], 2, format="json")
        assert any(change["path"] == "/stock" and change["kind"] == "incomparable" for change in changed["changes"])
        assert any(change["path"] == "/fixed" and change["kind"] == "weakened" and change["witness"] for change in changed["changes"])
        changed_sarif = invoke(["compare", old_api, new_api, *changed_urls], 2, format="sarif")
        assert any(result["ruleId"] == "auth-regression" for result in changed_sarif["runs"][0]["results"])

        # Explicit URLs are validated even when authentication is already absolute.
        for flag in ("--before-document-url", "--after-document-url"):
            for url in ("relative/spec.json", "file:///spec.json", "https://deploy.example/spec.json#fragment", "https://bad host/spec.json"):
                invalid_url = invoke(["compare", before, before, flag, url], 2, format="json")
                assert invalid_url["complete"] is False
                assert invalid_url["document_urls"] == {"before": None, "after": None}
            for extra in ([flag], [flag, ""], [flag, deployed_url, flag, deployed_url]):
                invoke(["compare", before, before, *extra], 2, format="json")
        absolute = invoke(["compare", before, before, *changed_urls], 0, format="json")
        assert absolute["complete"] is True
        invalid_sarif = invoke(["compare", before, before, "--after-document-url", "ftp://deploy.example/spec.json"], 2, format="sarif")
        assert invalid_sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False
        assert invalid_sarif["runs"][0]["properties"]["document_urls"] == {"before": None, "after": None}

    with tempfile.TemporaryDirectory(prefix="oas-auth-diff-child-document-urls-") as directory:
        directory = Path(directory)
        old_api = directory / "before.json"
        new_dir = directory / "after"
        child_dir = new_dir / "fragments" / "deep"
        child_dir.mkdir(parents=True)
        new_api = new_dir / "api.json"
        middle = new_dir / "fragments" / "mid part%#.json"
        child = child_dir / "next part%#.json"
        middle.write_text(json.dumps({"item": {"$ref": "deep/next%20part%25%23.json#/item"}}), encoding="utf-8")
        baseline = json.loads(relative_after.read_text(encoding="utf-8"))
        baseline["components"]["securitySchemes"]["warehouse"]["flows"]["clientCredentials"]["tokenUrl"] = "https://deploy.example/specs/oauth/token"
        baseline["paths"]["/stock"]["get"]["security"] = [{"warehouse": ["stock:read", "stock:write"]}]
        candidate = copy.deepcopy(baseline)
        candidate["components"]["securitySchemes"]["warehouse"]["flows"]["clientCredentials"]["tokenUrl"] = "token"
        candidate["paths"]["/stock"] = {"$ref": "fragments/mid%20part%25%23.json#/item"}
        item = {"servers": [{"url": "../../oauth/"}], "get": {"security": [{"warehouse": ["stock:read"]}]}}
        child.write_text(json.dumps({"item": item}), encoding="utf-8")
        old_api.write_text(json.dumps(baseline), encoding="utf-8")
        new_api.write_text(json.dumps(candidate), encoding="utf-8")
        urls = ["--before-document-url", "https://deploy.example/specs/entry.json", "--after-document-url", "https://deploy.example/specs/entry.json"]
        disabled = invoke(["compare", old_api, new_api, *urls], 2, format="json")
        assert any(item["code"] == "ref.external" for item in disabled["diagnostics"])
        nested = invoke(["compare", old_api, new_api, "--local-refs", *urls], 1, format="json")
        assert nested["changes"][0]["location"]["uri"] == child.resolve().as_uri()

        # Query-relative server and endpoint references retain the child filename.
        # This exposes incorrect decoding/double-encoding of %20, %25, and %23.
        expected_endpoint = "https://deploy.example/specs/fragments/deep/next%20part%25%23.json?grant=client"
        baseline["components"]["securitySchemes"]["warehouse"]["flows"]["clientCredentials"]["tokenUrl"] = expected_endpoint
        candidate["components"]["securitySchemes"]["warehouse"]["flows"]["clientCredentials"]["tokenUrl"] = "?grant=client"
        item["servers"] = [{"url": "?deployment=v1"}]
        child.write_text(json.dumps({"item": item}), encoding="utf-8")
        old_api.write_text(json.dumps(baseline), encoding="utf-8")
        new_api.write_text(json.dumps(candidate), encoding="utf-8")
        escaped = invoke(["compare", old_api, new_api, "--local-refs", *urls], 1, format="json")
        assert escaped["changes"][0]["location"]["uri"].endswith("/next%20part%25%23.json")
        escaped_sarif = invoke(["compare", old_api, new_api, "--local-refs", *urls], 1, format="sarif")
        artifact = escaped_sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        assert artifact["uri"] == child.resolve().as_uri()

        # A deployment URL grants no additional access to the local filesystem.
        outside = directory / "outside.json"
        outside.write_text(json.dumps({"item": item}), encoding="utf-8")
        candidate["paths"]["/stock"] = {"$ref": "../outside.json#/item"}
        new_api.write_text(json.dumps(candidate), encoding="utf-8")
        denied = invoke(["compare", old_api, new_api, "--local-refs", *urls], 2, format="json")
        assert any(item["code"] == "ref.load" for item in denied["diagnostics"])

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
        assert any(item["code"] == "auth.base" for item in relative_report["diagnostics"])

    with tempfile.TemporaryDirectory(prefix="oas-auth-diff-refs-") as directory:
        directory = Path(directory)
        entries = []
        for label, roles in (("before", ["admin"]), ("after", [])):
            base = directory / label
            (base / "defs").mkdir(parents=True)
            (base / "paths").mkdir()
            (base / "defs/key.yaml").write_text(
                "Key:\n  type: http\n  scheme: bearer\n", encoding="utf-8"
            )
            (base / "paths/entry.yaml").write_text(
                "item:\n  $ref: nested.json#/actual\n", encoding="utf-8"
            )
            nested = {
                "actual": {"get": {"security": [{"Key": roles}], "responses": {
                    "200": {"$ref": "https://example.invalid/never-load.yaml"}
                }}},
                "components": {"securitySchemes": {"Key": {"type": "http", "scheme": "basic"}}},
            }
            (base / "paths/nested.json").write_text(json.dumps(nested), encoding="utf-8")
            entry = {
                "openapi": "3.1.1",
                "components": {"securitySchemes": {"Key": {"$ref": "defs/key.yaml#/Key"}}},
                "paths": {"/data": {"$ref": "paths/entry.yaml#/item"}},
            }
            entry_file = base / "api.json"
            entry_file.write_text(json.dumps(entry), encoding="utf-8")
            entries.append(entry_file)
        old, new = entries
        invoke(["compare", old, new], 2, format="json")
        multi = invoke(["compare", old, new, "--local-refs"], 1, format="json")
        change = multi["changes"][0]
        assert change["location"]["uri"].endswith("/after/paths/nested.json")
        assert change["location"]["pointer"] == "/actual/get/security"
        assert change["witness"] == [{"kind": "credential", "scheme": "Key"}]
        invoke(["compare", new, new, "--local-refs"], 0, format="json")
        external_sarif = invoke(["compare", old, new, "--local-refs"], 1, format="sarif")
        result_location = external_sarif["runs"][0]["results"][0]["locations"][0]
        assert result_location["physicalLocation"]["artifactLocation"]["uri"].endswith("/after/paths/nested.json")

        entry = json.loads(new.read_text(encoding="utf-8"))
        entry["paths"]["/missing"] = {"$ref": "missing.yaml#/item"}
        new.write_text(json.dumps(entry), encoding="utf-8")
        partial = invoke(["compare", old, new, "--local-refs"], 2, format="json")
        assert any(change["kind"] == "weakened" for change in partial["changes"])
        del entry["paths"]["/missing"]

        outside = directory / "outside.json"
        outside.write_text('{"get":{"security":[{"Key":[]}]}}', encoding="utf-8")
        for reference in ("../outside.json", "%2e%2e/outside.json", "https://example.invalid/item.json", "file:///etc/passwd", "/outside.json", "//host/item.json", "C:/outside.json", "..\\outside.json", "defs/key.yaml?query=yes"):
            entry["paths"]["/data"] = {"$ref": reference}
            new.write_text(json.dumps(entry), encoding="utf-8")
            denied = invoke(["compare", old, new, "--local-refs"], 2, format="json")
            assert denied["complete"] is False
        entry["paths"]["/data"] = {"$ref": "../outside.json"}
        new.write_text(json.dumps(entry), encoding="utf-8")
        invoke(["compare", old, new, "--ref-root", directory], 1, format="json")

        name = "接口 résumé 🦉 100%.json"
        unicode_target = new.parent / "paths" / name
        unicode_target.write_text('{"get":{"security":[{"Key":[]}]}}', encoding="utf-8")
        entry["paths"]["/data"] = {"$ref": "paths/%E6%8E%A5%E5%8F%A3%20r%C3%A9sum%C3%A9%20%F0%9F%A6%89%20100%25.json"}
        new.write_text(json.dumps(entry), encoding="utf-8")
        unicode_ref = invoke(["compare", old, new, "--local-refs"], 1, format="json")
        assert unicode_ref["changes"][0]["location"]["uri"].endswith("%20100%25.json")

        link = new.parent / "escape.json"
        try:
            os.symlink(outside, link)
        except OSError:
            if os.name != "nt":
                raise
        else:
            entry["paths"]["/data"] = {"$ref": "escape.json"}
            new.write_text(json.dumps(entry), encoding="utf-8")
            invoke(["compare", old, new, "--local-refs"], 2, format="json")
        if hasattr(os, "mkfifo"):
            pipe = new.parent / "reference-pipe.json"
            os.mkfifo(pipe)
            entry["paths"]["/data"] = {"$ref": "reference-pipe.json"}
            new.write_text(json.dumps(entry), encoding="utf-8")
            invoke(["compare", old, new, "--local-refs"], 2, format="json")

        for extra in (["--local-refs", "--local-refs"], ["--ref-root"], ["--ref-root", directory, "--ref-root", directory], ["--format", "xml"]):
            invoke(["compare", old, new, *extra], 2, format="json")

    print(f"CLI smoke: {checks} subprocess checks passed")


if __name__ == "__main__":
    main()
