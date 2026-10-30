"""Exercise the built CLI as a subprocess; no compiler or registry orchestration."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import quote


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

    assert "0.8.0" in invoke(["--version"], 0)
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
        # Without local references, source identity preserves the input path alias.
        expected_input_uri = new_api.absolute().as_uri()
        actual_input_uri = deployed["changes"][0]["location"]["uri"]
        assert actual_input_uri == expected_input_uri, (actual_input_uri, expected_input_uri)
        assert deployed["changes"][0]["witness"]
        text = invoke(["compare", old_api, new_api, *both_urls], 1)
        assert "Baseline document URL: " + deployed_url in text
        assert "Candidate document URL: " + deployed_url in text
        deployed_sarif = invoke(["compare", old_api, new_api, *both_urls], 1, format="sarif")
        assert deployed_sarif["runs"][0]["properties"]["document_urls"] == deployed["document_urls"]
        physical = deployed_sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        actual_sarif_uri = physical["artifactLocation"]["uri"]
        assert actual_sarif_uri == expected_input_uri, (actual_sarif_uri, expected_input_uri)
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
        expected_child_uri = child.resolve().as_uri()
        actual_child_uri = nested["changes"][0]["location"]["uri"]
        assert actual_child_uri == expected_child_uri, (actual_child_uri, expected_child_uri)

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
        assert artifact["uri"] == expected_child_uri, (artifact["uri"], expected_child_uri)

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

    with tempfile.TemporaryDirectory(prefix="oas-auth-diff-paired-schemes-") as directory:
        directory = Path(directory)
        entries = []
        for label in ("before", "after"):
            base = directory / label
            (base / "defs").mkdir(parents=True)
            (base / "defs/key.yaml").write_text(
                "B:\n  type: apiKey\n  in: header\n  name: X-Pair\n", encoding="utf-8"
            )
            entries.append(base / "api.json")
        old, new = entries
        baseline = {
            "openapi": "3.1.1",
            "components": {"securitySchemes": {
                "A": {"type": "http", "scheme": "bearer"},
                "B": {"$ref": "defs/key.yaml#/B"},
                "Stable": {"type": "http", "scheme": "basic"},
                "Unrelated": {"$ref": "never-read.json#/Unrelated"},
            }},
            "paths": {"/paired": {"get": {"security": [{"A": [], "B": []}]}}},
        }
        candidate = copy.deepcopy(baseline)
        candidate["paths"]["/paired"]["get"]["security"] = [{"A": []}]
        old.write_text(json.dumps(baseline), encoding="utf-8")
        new.write_text(json.dumps(candidate), encoding="utf-8")

        # B must be resolved on both sides even though the candidate drops it.
        paired = invoke(["compare", old, new, "--local-refs"], 1, format="json")
        change = paired["changes"][0]
        assert change["kind"] == "weakened"
        assert change["witness"] == [{"kind": "credential", "scheme": "A"}]
        expected_uri = new.resolve().as_uri()
        assert change["location"]["uri"] == expected_uri, (change["location"]["uri"], expected_uri)
        assert "weakened" in invoke(["compare", old, new, "--local-refs"], 1)
        paired_sarif = invoke(["compare", old, new, "--local-refs"], 1, format="sarif")
        result = paired_sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "auth-regression"
        assert result["locations"][0]["properties"]["jsonPointer"] == "/paths/~1paired/get/security"
        invoke(["compare", new, old, "--local-refs"], 0, format="json")

        candidate["paths"]["/paired"]["get"]["security"] = []
        new.write_text(json.dumps(candidate), encoding="utf-8")
        anonymous = invoke(["compare", old, new, "--local-refs"], 1, format="json")
        assert anonymous["changes"][0]["witness"] == []
        candidate["paths"]["/paired"]["get"]["security"] = [{"A": []}]

        # Missing or changed evidence is incomplete, retaining independent findings.
        baseline["paths"]["/stable"] = {"get": {"security": [{"Stable": ["operator"]}]}}
        candidate["paths"]["/stable"] = {"get": {"security": [{"Stable": []}]}}
        old.write_text(json.dumps(baseline), encoding="utf-8")
        new.write_text(json.dumps(candidate), encoding="utf-8")

        def incomplete_pair(extra=(), *, format="json"):
            report = invoke(["compare", old, new, *extra], 2, format=format)
            if format == "json":
                assert report["complete"] is False
                assert any(item["path"] == "/paired" and item["kind"] == "incomparable" for item in report["changes"])
                assert any(item["path"] == "/stable" and item["kind"] == "weakened" and item["witness"] for item in report["changes"])
            return report

        incomplete_pair()
        key_file = new.parent / "defs/key.yaml"
        key_file.write_text("B:\n  type: apiKey\n  in: header\n  name: X-Changed\n", encoding="utf-8")
        incomplete_pair(["--local-refs"])
        incomplete_pair(["--local-refs"], format="sarif")
        key_file.write_text("B: []\n", encoding="utf-8")
        malformed = incomplete_pair(["--local-refs"])
        expected_definition_uri = key_file.resolve().as_uri()
        assert any(item["location"]["uri"] == expected_definition_uri for item in malformed["diagnostics"]), malformed["diagnostics"]
        key_file.unlink()
        incomplete_pair(["--local-refs"])
        del candidate["components"]["securitySchemes"]["B"]
        new.write_text(json.dumps(candidate), encoding="utf-8")
        incomplete_pair(["--local-refs"])

        outside = directory / "outside.json"
        outside.write_text(json.dumps({"B": {"type": "apiKey", "in": "header", "name": "X-Pair"}}), encoding="utf-8")
        candidate["components"]["securitySchemes"]["B"] = {"$ref": "../outside.json#/B"}
        new.write_text(json.dumps(candidate), encoding="utf-8")
        urls = ["--before-document-url", "https://deploy.example/before/api.json",
                "--after-document-url", "https://deploy.example/after/api.json"]
        confined = incomplete_pair(["--local-refs", *urls])
        assert any(item["code"] == "ref.load" for item in confined["diagnostics"])
        assert confined["document_urls"] == {
            "before": "https://deploy.example/before/api.json",
            "after": "https://deploy.example/after/api.json",
        }
        shared_root = invoke(["compare", old, new, "--ref-root", directory, *urls], 1, format="json")
        assert shared_root["document_urls"] == confined["document_urls"]

        # Added and removed operations do not demand their names on the other side.
        simple = {"openapi": "3.1.1", "components": {"securitySchemes": {
            "A": {"type": "http", "scheme": "bearer"},
            "Unrelated": {"$ref": "never-read.json#/Unrelated"},
        }}, "paths": {"/common": {"get": {"security": [{"A": []}]}}}}
        baseline = copy.deepcopy(simple)
        candidate = copy.deepcopy(simple)
        baseline["components"]["securitySchemes"].update({
            "OnlyOld": {"type": "http", "scheme": "basic"},
            "OnlyNew": {"$ref": "never-read-new.json#/OnlyNew"},
        })
        candidate["components"]["securitySchemes"].update({
            "OnlyOld": {"$ref": "never-read-old.json#/OnlyOld"},
            "OnlyNew": {"type": "http", "scheme": "basic"},
        })
        baseline["paths"]["/removed"] = {"get": {"security": [{"OnlyOld": []}]}}
        candidate["paths"]["/added"] = {"get": {"security": [{"OnlyNew": []}]}}
        old.write_text(json.dumps(baseline), encoding="utf-8")
        new.write_text(json.dumps(candidate), encoding="utf-8")
        untouched = invoke(["compare", old, new, "--local-refs"], 0, format="json")
        assert {item["kind"] for item in untouched["changes"]} == {"equivalent", "added", "removed"}
        assert untouched["diagnostics"] == []
        invoke(["compare", old, new], 0, format="json")

        # Pair parsing identifies the failed entry without changing source identity.
        invalid = directory / "invalid.json"
        invalid.write_text('{"openapi": "3.1.1", "paths": ', encoding="utf-8")
        for left, right, bad_source in ((invalid, new, invalid), (old, invalid, invalid)):
            failure = invoke(["compare", left, right], 2, format="json")
            actual_uri = failure["diagnostics"][0]["location"]["uri"]
            expected_uri = bad_source.absolute().as_uri()
            assert actual_uri == expected_uri, (actual_uri, expected_uri)

    with tempfile.TemporaryDirectory(prefix="oas-auth-diff-path-parameters-") as directory:
        directory = Path(directory)
        old = directory / "before.json"
        new = directory / "after.json"
        old_path = "/orders/{id}"
        new_path = "/orders/{order_id}"
        baseline = json.loads(after.read_text(encoding="utf-8"))
        baseline["paths"] = {old_path: {"get": {
            "operationId": "getOrder",
            "security": [{"account": ["orders:read", "orders:write"]}],
        }}}
        candidate = copy.deepcopy(baseline)
        candidate["paths"] = {new_path: {"get": {"operationId": "getOrder", "security": []}}}
        old.write_text(json.dumps(baseline), encoding="utf-8")
        new.write_text(json.dumps(candidate), encoding="utf-8")

        # Renaming a template parameter must not hide removal of authentication.
        renamed = invoke(["compare", old, new], 1, format="json")
        assert len(renamed["changes"]) == 1
        change = renamed["changes"][0]
        assert change["kind"] == "weakened" and change["witness"] == []
        assert (change["before_path"], change["after_path"], change["path"]) == (old_path, new_path, new_path)
        expected_pointer = "/paths/~1orders~1{order_id}/get/security"
        expected_uri = new.absolute().as_uri()
        assert change["location"] == {"uri": expected_uri, "pointer": expected_pointer}, (change["location"], expected_uri)
        text = invoke(["compare", old, new], 1)
        assert old_path + " -> " + new_path in text
        renamed_sarif = invoke(["compare", old, new], 1, format="sarif")
        result = renamed_sarif["runs"][0]["results"][0]
        assert old_path + " -> " + new_path in result["message"]["text"]
        assert (result["properties"]["before_path"], result["properties"]["after_path"]) == (old_path, new_path)
        assert result["locations"][0]["properties"]["jsonPointer"] == expected_pointer
        invoke(["compare", new, old], 0, format="json")

        candidate["paths"][new_path]["get"]["security"] = [{"account": ["orders:read"]}]
        new.write_text(json.dumps(candidate), encoding="utf-8")
        scope_change = invoke(["compare", old, new], 1, format="json")
        assert {item.get("name") for item in scope_change["changes"][0]["witness"]} == {None, "orders:read"}
        candidate["paths"][new_path]["get"]["security"] = copy.deepcopy(baseline["paths"][old_path]["get"]["security"])
        candidate["paths"][new_path]["get"]["operationId"] = "renamedLabel"
        new.write_text(json.dumps(candidate), encoding="utf-8")
        equivalent = invoke(["compare", old, new], 0, format="json")
        assert equivalent["changes"][0]["kind"] == "equivalent"

        # HTTP methods and literal parts of paths still identify different operations.
        for different, verb in ((new_path, "post"), ("/orders/me", "get"),
                                ("/purchases/{order_id}", "get"), ("/Orders/{order_id}", "get"),
                                ("/orders/{order_id}/", "get"), ("/orders/%7Border_id%7D", "get")):
            candidate["paths"] = {different: {verb: {"operationId": "getOrder", "security": []}}}
            new.write_text(json.dumps(candidate), encoding="utf-8")
            distinct = invoke(["compare", old, new], 0, format="json")
            assert {item["kind"] for item in distinct["changes"]} == {"added", "removed"}
            added = next(item for item in distinct["changes"] if item["kind"] == "added")
            removed = next(item for item in distinct["changes"] if item["kind"] == "removed")
            assert added["before_path"] is None and added["after_path"] == different
            assert removed["before_path"] == old_path and removed["after_path"] is None

        baseline["paths"]["/stable"] = copy.deepcopy(baseline["paths"][old_path])
        old.write_text(json.dumps(baseline), encoding="utf-8")
        stable = {"get": {"security": [{"account": ["orders:read"]}]}}
        candidate["paths"] = {
            "/orders/{first}": {"get": {"security": []}},
            "/orders/{second}": {"$ref": "never-read-duplicate.json#/item", "post": {"security": []}},
            "/stable": stable,
        }
        new.write_text(json.dumps(candidate), encoding="utf-8")
        duplicate = invoke(["compare", old, new, "--local-refs"], 2, format="json")
        assert any(item["code"] == "path-duplicate" for item in duplicate["diagnostics"])
        assert not any(item["code"] == "ref.load" for item in duplicate["diagnostics"])
        assert any(item["path"] == "/stable" and item["kind"] == "weakened" for item in duplicate["changes"])
        assert not any(item["after_path"] in ("/orders/{first}", "/orders/{second}") for item in duplicate["changes"])

        for invalid in ("orders/{id}", "/orders/{}", "/orders/{id", "/orders/id}",
                        "/orders/{{id}}", "/orders/{one/two}"):
            candidate["paths"] = {invalid: {"$ref": "never-read-invalid.json#/item"}, "/stable": stable}
            new.write_text(json.dumps(candidate), encoding="utf-8")
            malformed = invoke(["compare", old, new, "--local-refs"], 2, format="json")
            assert any(item["code"] == "auth.path" for item in malformed["diagnostics"])
            assert not any(item["code"] == "ref.load" for item in malformed["diagnostics"])
            assert any(item["path"] == "/stable" and item["kind"] == "weakened" for item in malformed["changes"])

        # Paired loading follows the renamed operation and keeps the candidate pointer.
        (directory / "key.yaml").write_text("B:\n  type: http\n  scheme: basic\n", encoding="utf-8")
        baseline = {"openapi": "3.1.1", "components": {"securitySchemes": {
            "A": {"type": "http", "scheme": "bearer"},
            "B": {"$ref": "key.yaml#/B"},
        }}, "paths": {old_path: {"get": {"security": [{"A": [], "B": []}]}}}}
        candidate = copy.deepcopy(baseline)
        candidate["paths"] = {new_path: {"get": {"security": [{"A": []}]}}}
        old.write_text(json.dumps(baseline), encoding="utf-8")
        new.write_text(json.dumps(candidate), encoding="utf-8")
        paired = invoke(["compare", old, new, "--local-refs"], 1, format="json")
        change = paired["changes"][0]
        assert change["witness"] == [{"kind": "credential", "scheme": "A"}]
        expected_uri = new.resolve().as_uri()
        assert change["location"] == {"uri": expected_uri, "pointer": expected_pointer}, (change["location"], expected_uri)
        assert (change["before_path"], change["after_path"]) == (old_path, new_path)
        invoke(["compare", old, new], 2, format="json")

    with tempfile.TemporaryDirectory(prefix="oas-auth-diff-sarif-roots-") as directory:
        directory = Path(directory)
        baseline = json.loads(after.read_text(encoding="utf-8"))
        baseline["security"] = [{"account": ["orders:read", "orders:write"]}]
        baseline["paths"] = {
            "/orders": {"get": {"operationId": "listOrders"}, "post": {"operationId": "createOrder"}},
            "/orders/{id}": {"get": {"operationId": "getOrder"}},
        }
        candidate = copy.deepcopy(baseline)
        candidate["security"] = [{"account": ["orders:read"]}]
        checkouts = []
        root_reports = []
        for label in ("checkout-one", "checkout-two"):
            checkout = directory / label
            specs = checkout / "specs"
            specs.mkdir(parents=True)
            old = specs / "before.json"
            new = specs / "after.json"
            old.write_text(json.dumps(baseline), encoding="utf-8")
            new.write_text(json.dumps(candidate), encoding="utf-8")
            checkouts.append((checkout, old, new))
            rendered = invoke(["compare", old, new, "--source-root", checkout], 1, format="sarif")
            root_reports.append(rendered)
            run = rendered["runs"][0]
            expected_root = checkout.absolute().as_uri().rstrip("/") + "/"
            assert run["originalUriBaseIds"] == {"%SRCROOT%": {"uri": expected_root}}
            assert run["invocations"][0]["workingDirectory"]["uri"] == expected_root
            expected_sources = {"before": old.absolute().as_uri(), "after": new.absolute().as_uri()}
            assert run["properties"]["document_sources"] == expected_sources
            assert len(run["results"]) == 3
            for result in run["results"]:
                location = result["locations"][0]
                assert location["physicalLocation"]["artifactLocation"] == {"uri": "specs/after.json", "uriBaseId": "%SRCROOT%"}
                assert "region" not in location["physicalLocation"]
                assert location["properties"] == {"source": expected_sources["after"], "jsonPointer": "/security"}
                identity_path = "/orders/{}" if result["properties"]["path"] == "/orders/{id}" else "/orders"
                identity = ["oas-auth-diff/route/v1", result["ruleId"], "relative:specs/after.json",
                            result["properties"]["method"], identity_path]
                digest = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode("utf-8")).hexdigest()
                assert result["partialFingerprints"] == {"oasAuthDiff/route/v1": digest, "primaryLocationLineHash": digest}

        def fingerprints(rendered):
            return {(item["properties"]["method"], "/orders/{}" if item["properties"]["path"] in
                     ("/orders/{id}", "/orders/{order_id}") else item["properties"]["path"]):
                    item["partialFingerprints"]["primaryLocationLineHash"]
                    for item in rendered["runs"][0]["results"]}

        stable_fingerprints = fingerprints(root_reports[0])
        assert fingerprints(root_reports[1]) == stable_fingerprints
        assert len(set(stable_fingerprints.values())) == 3
        checkout, old, new = checkouts[0]
        plain = invoke(["compare", old, new], 1, format="json")
        assert plain["document_sources"] == {"before": old.absolute().as_uri(), "after": new.absolute().as_uri()}
        assert "weakened" in invoke(["compare", old, new], 1)
        no_root = invoke(["compare", old, new], 1, format="sarif")
        artifact = no_root["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        assert artifact == {"uri": new.absolute().as_uri()}
        invoke(["compare", old, old, "--source-root", checkout], 0, format="sarif")

        renamed = copy.deepcopy(candidate)
        renamed["paths"]["/orders/{order_id}"] = renamed["paths"].pop("/orders/{id}")
        variants = [renamed, copy.deepcopy(candidate), copy.deepcopy(candidate)]
        variants[1]["info"]["title"] = "Edited description"
        variants[1]["paths"]["/orders"]["get"]["operationId"] = "changedLabel"
        variants[2]["security"] = []
        for variant in variants:
            new.write_text(json.dumps(variant), encoding="utf-8")
            unchanged_identity = invoke(["compare", old, new, "--source-root", checkout], 1, format="sarif")
            assert fingerprints(unchanged_identity) == stable_fingerprints
        assert all(item["properties"]["witness"] == [] for item in unchanged_identity["runs"][0]["results"])
        new.write_text(json.dumps(candidate), encoding="utf-8")
        deployed = invoke(["compare", old, new, "--source-root", checkout,
                           "--after-document-url", "https://docs.example/specs/after.json"], 1, format="sarif")
        assert fingerprints(deployed) == stable_fingerprints

        other_entry = new.parent / "other-api.json"
        other_entry.write_text(json.dumps(candidate), encoding="utf-8")
        distinct_entry = invoke(["compare", old, other_entry, "--source-root", checkout], 1, format="sarif")
        assert not set(fingerprints(distinct_entry).values()) & set(stable_fingerprints.values())
        names = ["api space%#接口.json"]
        if os.name != "nt":
            names.extend(["api?query.json", "api:colon.json"])
        for name in names:
            special = checkout / name
            special.write_text(json.dumps(candidate), encoding="utf-8")
            special_report = invoke(["compare", old, special, "--source-root", checkout], 1, format="sarif")
            artifact = special_report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
            expected_relative = "./" + name if ":" in name else quote(name, safe="")
            assert artifact == {"uri": expected_relative, "uriBaseId": "%SRCROOT%"}, artifact

        sibling = directory / "checkout-one-extra"
        sibling.mkdir()
        sibling_entry = sibling / "after.json"
        sibling_entry.write_text(json.dumps(candidate), encoding="utf-8")
        outside = invoke(["compare", old, sibling_entry, "--source-root", checkout], 1, format="sarif")
        artifact = outside["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        assert artifact == {"uri": sibling_entry.absolute().as_uri()}, artifact

        # Source roots change reporting, never the loader's permission boundary.
        shared = directory / "shared"
        shared.mkdir()
        child = shared / "item.json"
        child.write_text(json.dumps({"item": {"get": {"security": [{"account": ["orders:read"]}]}}}), encoding="utf-8")
        external = copy.deepcopy(candidate)
        external["paths"] = {"/orders": {"$ref": "../../shared/item.json#/item"}}
        new.write_text(json.dumps(external), encoding="utf-8")
        disabled = invoke(["compare", old, new, "--source-root", checkout], 2, format="sarif")
        notifications = disabled["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        assert any(item["descriptor"]["id"] == "ref.external" for item in notifications)
        confined = invoke(["compare", old, new, "--source-root", directory, "--local-refs"], 2, format="sarif")
        notifications = confined["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        assert any(item["descriptor"]["id"] == "ref.load" for item in notifications)
        loaded = invoke(["compare", old, new, "--ref-root", directory, "--source-root", checkout], 1, format="sarif")
        run = loaded["runs"][0]
        expected_root = checkout.resolve().as_uri().rstrip("/") + "/"
        assert run["originalUriBaseIds"] == {"%SRCROOT%": {"uri": expected_root}}
        result = run["results"][0]
        artifact = result["locations"][0]["physicalLocation"]["artifactLocation"]
        assert artifact == {"uri": child.resolve().as_uri()}, artifact
        assert result["locations"][0]["properties"] == {"source": child.resolve().as_uri(), "jsonPointer": "/item/get/security"}
        assert result["partialFingerprints"]["primaryLocationLineHash"] == stable_fingerprints[("GET", "/orders")]

        for extra in (["--source-root"], ["--source-root", ""],
                      ["--source-root", checkout, "--source-root", checkout],
                      ["--source-root", directory / "missing"], ["--source-root", old]):
            invalid = invoke(["compare", old, new, *extra], 2, format="sarif")
            run = invalid["runs"][0]
            assert not run.get("originalUriBaseIds")
            notification = run["invocations"][0]["toolExecutionNotifications"][0]
            assert notification["locations"][0]["properties"]["source"] == "oas-auth-diff:arguments"
        for format in (None, "text", "json"):
            invalid = invoke(["compare", old, new, "--source-root", checkout], 2, format=format)
            if format == "json":
                assert invalid["diagnostics"][0]["location"]["uri"] == "oas-auth-diff:arguments"
        fatal = invoke(["compare", old, directory / "missing.json", "--source-root", checkout], 2, format="sarif")
        assert not fatal["runs"][0].get("originalUriBaseIds")
        assert fatal["runs"][0]["properties"]["document_sources"] == {"before": None, "after": None}

    check_ids = invoke(["checks", "--format", "json"], 0)
    assert json.loads(check_ids) == ["endpoint-removed", "request-parameter-added-required", "request-parameter-became-required"]
    assert "endpoint-removed" in invoke(["checks"], 0)
    parameter_before = cases / "parameters.before.yaml"
    parameter_after = cases / "parameters.after.json"
    invoke(["compare", parameter_before, parameter_after], 0, format="json")
    for output_format in ("text", "json", "sarif"):
        invoke(["breaking", parameter_before, parameter_before], 0, format=output_format)
        result = invoke(["breaking", parameter_before, parameter_after], 1, format=output_format)
        if output_format == "json":
            assert result["report_kind"] == "compatibility" and result["complete"]
            assert result["findings"][0]["parameter"] == "tenant"
        elif output_format == "sarif":
            assert result["runs"][0]["results"][0]["ruleId"] == "request-parameter-added-required"

    with tempfile.TemporaryDirectory(prefix="oas-contract-") as directory:
        directory = Path(directory)
        old, new = directory / "before.json", directory / "after.json"
        base = json.loads(parameter_after.read_text(encoding="utf-8"))
        changed = copy.deepcopy(base)
        base["paths"]["/orders"]["get"]["parameters"] = []
        old.write_text(json.dumps(base), encoding="utf-8")
        for position in ("query", "header", "cookie"):
            changed["paths"]["/orders"]["get"]["parameters"][0]["in"] = position
            new.write_text(json.dumps(changed), encoding="utf-8")
            report = invoke(["breaking", old, new], 1, format="json")
            assert report["findings"][0]["position"] == position
        changed["paths"]["/orders"]["get"]["responses"] = {"201": {"description": "Created"}}
        new.write_text(json.dumps(changed), encoding="utf-8")
        for output_format in ("text", "json", "sarif"):
            report = invoke(["breaking", old, new], 2, format=output_format)
            if output_format == "json":
                assert not report["complete"] and len(report["findings"]) == 1
            elif output_format == "sarif":
                assert not report["runs"][0]["invocations"][0]["executionSuccessful"]
                assert len(report["runs"][0]["results"]) == 1
        changed = copy.deepcopy(base)
        changed["paths"]["/orders"]["get"]["parameters"] = [{"$ref": "parameter.yaml"}]
        new.write_text(json.dumps(changed), encoding="utf-8")
        parameter_file = directory / "parameter.yaml"
        parameter_file.write_text("name: tenant\nin: query\nrequired: true\nschema: {type: string}\n", encoding="utf-8")
        invoke(["breaking", old, new], 2, format="json")
        report = invoke(["breaking", old, new, "--local-refs", "--source-root", directory], 1, format="sarif")
        finding = report["runs"][0]["results"][0]
        assert finding["locations"][0]["physicalLocation"]["artifactLocation"] == {"uri": "parameter.yaml", "uriBaseId": "%SRCROOT%"}
        fingerprint_key = ["oas-auth-diff/compatibility/v1", "after.json", "request-parameter-added-required", "GET", "/orders", "query", "tenant"]
        expected_fingerprint = hashlib.sha256(json.dumps(fingerprint_key, separators=(",", ":")).encode()).hexdigest()
        assert finding["partialFingerprints"]["compatibility/v1"] == expected_fingerprint
        parameter_file.write_text("name: tenant\nin: query\nrequired: not-a-boolean\n", encoding="utf-8")
        invoke(["breaking", old, new, "--local-refs"], 2, format="json")
        invoke(["breaking", old, directory / "missing.json"], 2, format="json")
        invoke(["breaking", old, new, "--before-document-url", "https://example.test/spec"], 2, format="json")

    print(f"CLI smoke: {checks} subprocess checks passed")


if __name__ == "__main__":
    main()
