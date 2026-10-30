"""Regenerate the embedded official metaschemas, verifying each pinned SHA-256."""

import hashlib
import json
from pathlib import Path
import urllib.request


def main():
    directory = Path(__file__).resolve().parent
    entries = json.loads((directory / "resources.json").read_text(encoding="utf-8"))
    resources = []
    for entry in entries:
        request = urllib.request.Request(entry["url"], headers={"User-Agent": "oas-auth-diff/schema-import"})
        data = urllib.request.urlopen(request, timeout=30).read()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise SystemExit("Metaschema checksum differs: " + entry["url"])
        resources.append((entry["url"], json.loads(data)))
    source = "// Bundled official OpenAPI / JSON Schema resources. Sources and licenses:\n// docs/validation.md and validation/JSON_SCHEMA_LICENSE.\n"
    for index, (url, value) in enumerate(resources):
        source += "\n///|\n// " + url + "\nlet resource_" + str(index) + " : String =\n"
        source += "".join("  #|" + line + "\n" for line in json.dumps(value, indent=2, ensure_ascii=True).splitlines())
    source += "\n///|\nlet bundled_schemas : Map[String, String] = Map([\n"
    for index, (url, _) in enumerate(resources):
        source += "  (" + json.dumps(url) + ", resource_" + str(index) + "),\n"
    source += "])\n"
    (directory / "resources.mbt").write_text(source, encoding="utf-8")
    print("Embedded {} checksum-verified metaschemas; run moon fmt".format(len(resources)))


if __name__ == "__main__":
    main()
