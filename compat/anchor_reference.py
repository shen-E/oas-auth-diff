"""Check external static-anchor consumption and witnesses with jsonschema."""

import argparse
from importlib.metadata import version
from itertools import product
import json
from pathlib import Path
import subprocess
import tempfile

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from reference import yaml_text
from schema_reference import document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ours", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build = Path(__file__).resolve().parents[1] / "_build/native/debug/build/cmd/oas-auth-diff"
    ours = args.ours.resolve() if args.ours else next(
        (p for p in (build / "oas-auth-diff.exe", build / "oas-auth-diff") if p.is_file()), None)
    if ours is None:
        raise SystemExit("build the native CLI or pass --ours")
    wide, narrow = "^[一-龥]+$", "^猫+$"
    scenarios = [
        ("request-narrow", "request", wide, narrow, 1, False),
        ("request-widen", "request", narrow, wide, 0, False),
        ("response-widen", "response", narrow, wide, 1, False),
        ("response-narrow", "response", wide, narrow, 0, False),
        ("stable-anchor", "request", wide, wide, 0, False),
        ("anchor-to-pointer", "request", wide, wide, 0, True),
    ]
    results = []
    with tempfile.TemporaryDirectory(prefix="oas-anchor-reference-") as directory:
        directory = Path(directory)
        for formats, (name, direction, old_pattern, new_pattern, expected, pointer) in product(
                product(("json", "yaml"), repeat=2), scenarios):
            paths, validators = [], []
            for label, kind, pattern in zip(("before", "after"), formats, (old_pattern, new_pattern)):
                folder = directory / label
                folder.mkdir(exist_ok=True)
                target = {"$defs": {"Identifier": {"$anchor": "Id", "type": "string", "pattern": pattern}}}
                model = folder / ("model." + kind)
                model.write_text(yaml_text(target) if kind == "yaml" else json.dumps(target), encoding="utf-8")
                fragment = "#/$defs/Identifier" if pointer and label == "after" else "#Id"
                entry = document({"$ref": model.name + fragment}, direction, "3.1.1")
                path = folder / ("api." + kind)
                path.write_text(yaml_text(entry) if kind == "yaml" else json.dumps(entry), encoding="utf-8")
                paths.append(path)
                registry = Registry().with_resource(model.as_uri(), Resource(target, DRAFT202012))
                validator = Draft202012Validator({"$ref": model.as_uri() + fragment}, registry=registry)
                assert validator.is_valid("猫") and not validator.is_valid("a")
                validators.append(validator)
            completed = subprocess.run([str(ours), "breaking", *map(str, paths), "--local-refs", "--format", "json"],
                                       capture_output=True, encoding="utf-8", timeout=30)
            report = json.loads(completed.stdout)
            source, target = validators if direction == "request" else validators[::-1]
            witnesses = [f["witness"] for f in report["findings"] if f["witness_verified"]]
            results.append({
                "case": name, "input_formats": formats, "expected_exit": expected, "actual_exit": completed.returncode,
                "witnesses": len(witnesses),
                "passed": completed.returncode == expected and report["complete"]
                and (expected != 1 or bool(witnesses))
                and all(source.is_valid(w) and not target.is_valid(w) for w in witnesses)
                and all(f["location"]["pointer"] == "/$defs/Identifier"
                        and f["location"]["uri"].startswith(paths[1].parent.as_uri() + "/model.")
                        for f in report["findings"]),
            })
    result = {"validator": "jsonschema " + version("jsonschema"), "total": len(results),
              "passed": sum(r["passed"] for r in results), "witnesses": sum(r["witnesses"] for r in results),
              "cases": results}
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Independent static-anchor checks: {passed}/{total}, {witnesses} witnesses".format(**result))
    if result["passed"] != result["total"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
